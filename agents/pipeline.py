"""
PDF-to-audit pipeline orchestration — LangChain Agentic Edition.

Uses LangChain RunnableLambda + RunnableSequence to orchestrate the
post-ingestion workflow:
  1. Ingestion Context Loader
  2. Analysis Agent        (extractive summary + classification)
  3. MAP Generation Agent  (LLM-queued or offline fallback)
  4. Deadline Agent        (deadline parsing + reminder setup)
  5. Conflict Agent        (circular conflict detection)
  6. Routing Agent         (MAP assignment to departments)
  7. Risk Scoring Agent    (bank-wide compliance score)
  8. Notification Agent    (CCO notification + blockchain entry)

Each stage receives and returns a ``state`` dict so the chain is
transparent and easily extensible with new agent steps.
"""

import json
import logging
import os
import re
from datetime import date, datetime

from p_crypto.blockchain import Blockchain
from p_crypto.encryptor import encrypt
from utils.database import get_circular_body, get_connection, store_map, _get_master_key
from utils.db_extensions import create_notification, enqueue_llm_task
from utils.dept_mapping import map_department
from utils.llm_queue import check_llm_health

logger = logging.getLogger("phantom_compliance.pipeline")

# ─── LangChain import (optional — degrade gracefully) ────────────────────────

try:
    from langchain_core.runnables import RunnableLambda, RunnableSequence
    _LANGCHAIN_AVAILABLE = True
    logger.info("LangChain available — using agentic pipeline")
except ImportError:
    _LANGCHAIN_AVAILABLE = False
    logger.warning("langchain_core not found — using sequential fallback pipeline")


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _record(agent_name: str, status: str = "COMPLETED", tasks: int = 1, error: str = ""):
    try:
        from core.agent_viz import record_agent_run
        record_agent_run(agent_name, status, tasks_processed=tasks, error=error)
    except Exception:
        pass


def _extractive_summary(text: str) -> str:
    clean = re.sub(r"\s+", " ", text or "").strip()
    if not clean:
        return "No readable text was extracted from this circular."
    sentences = re.split(r"(?<=[.!?])\s+", clean)
    picked = [s for s in sentences if len(s) > 40][:3]
    if not picked:
        picked = [clean[:500]]
    return " ".join(picked)[:1000]


def _classify(text: str) -> dict:
    lower = (text or "").lower()
    urgency = (
        "URGENT" if any(w in lower for w in ("immediate", "urgent", "forthwith"))
        else "HIGH" if "within 7 days" in lower
        else "NORMAL"
    )
    if any(w in lower for w in ("kyc", "aml", "customer due diligence")):
        circular_type = "KYC/AML"
    elif any(w in lower for w in ("payment", "upi", "settlement", "rtgs", "neft")):
        circular_type = "Payments"
    elif any(w in lower for w in ("cyber", "information security", "technology", "it ")):
        circular_type = "IT Security"
    elif any(w in lower for w in ("capital", "liquidity", "treasury")):
        circular_type = "Treasury"
    elif any(w in lower for w in ("credit", "stressed asset", "loan")):
        circular_type = "Credit Risk"
    elif any(w in lower for w in ("foreign exchange", "forex", "export", "import")):
        circular_type = "Forex"
    else:
        circular_type = "General Compliance"
    return {"urgency": urgency, "circular_type": circular_type}


def _department_from_text(text: str, fallback_code: str = "") -> str:
    lower = (text or "").lower()
    if any(w in lower for w in ("payment", "upi", "settlement", "rtgs", "neft")):
        return "Payments"
    if any(w in lower for w in ("cyber", "information security", "technology", "incident")):
        return "IT_Security"
    if any(w in lower for w in ("capital", "liquidity", "treasury")):
        return "Treasury"
    if any(w in lower for w in ("credit", "stressed asset", "loan")):
        return "Credit_Risk"
    if any(w in lower for w in ("foreign exchange", "forex", "export", "import")):
        return "Forex"
    if any(w in lower for w in ("kyc", "aml", "customer due diligence")):
        return "KYC"
    return map_department(fallback_code or "")


# ─── Individual stage functions ───────────────────────────────────────────────

def analyze_circular(circular_id: int) -> dict:
    """Stage 1 — Analyse circular text and persist the result."""
    body = get_circular_body(circular_id)
    summary = _extractive_summary(body)
    classification = _classify(body)
    from agents.deadline_parser import parse_deadline
    deadline = parse_deadline(body[:4000] if body else "")
    analysis = {
        "summary": summary,
        "urgency": deadline.get("urgency") or classification["urgency"],
        "circular_type": classification["circular_type"],
        "compliance_deadline": deadline.get("deadline_date"),
        "deadline_type": deadline.get("deadline_type"),
        "analyzed_at": datetime.now().isoformat(),
    }
    conn = get_connection()
    conn.execute(
        "UPDATE circulars SET analysis=? WHERE id=?",
        (json.dumps(analysis, ensure_ascii=False), circular_id),
    )
    conn.commit()
    conn.close()
    _record("LLM Agent", tasks=1)
    return analysis


def _fallback_maps_for_circular(circular_id: int) -> list[dict]:
    """Generate a single offline MAP when LLM is unavailable."""
    conn = get_connection()
    row = conn.execute(
        "SELECT circular_number, department_code, subject_line FROM circulars WHERE id=?",
        (circular_id,),
    ).fetchone()
    existing = conn.execute(
        "SELECT count(*) FROM maps WHERE circular_id=?", (circular_id,)
    ).fetchone()[0]
    conn.close()
    if not row or existing:
        return []

    body = get_circular_body(circular_id)
    analysis = _classify((row["subject_line"] or "") + " " + body[:2000])
    dept_hint = _department_from_text(
        (row["subject_line"] or "") + " " + body[:2000],
        row["department_code"] or analysis["circular_type"],
    )
    from agents.deadline_parser import parse_deadline
    deadline = parse_deadline(body[:4000] if body else row["subject_line"] or "")
    days = 30
    if deadline.get("deadline_date"):
        try:
            days = max(
                1,
                (datetime.strptime(deadline["deadline_date"], "%Y-%m-%d").date() - date.today()).days,
            )
        except ValueError:
            pass

    action = (row["subject_line"] or f"Comply with circular {row['circular_number'] or circular_id}")[:120]
    detail = {
        "map_id": f"RBI-MAP-{circular_id}-1",
        "obligation": action,
        "department_hint": dept_hint,
        "deadline_days_from_date": days,
        "evidence_required": f"Approved implementation note and evidence pack for: {action}",
        "frequency": "One-time",
        "source": "offline-fallback",
    }
    ciphertext, nonce, auth_tag = encrypt(json.dumps(detail, ensure_ascii=False), _get_master_key())
    mid = store_map(
        circular_id,
        detail["obligation"],
        ciphertext,
        nonce,
        auth_tag,
        dept_hint,
        days,
        frequency=detail["frequency"],
        evidence_required=detail["evidence_required"],
        map_id_label=detail["map_id"],
    )
    return [{"id": mid, **detail}]


def apply_deadlines(circular_id: int, analysis: dict, blockchain: Blockchain) -> dict:
    """Stage 3 — Persist deadlines and trigger reminders."""
    deadline_date = analysis.get("compliance_deadline")
    updated = 0
    if deadline_date:
        conn = get_connection()
        cur = conn.execute(
            "UPDATE maps SET deadline_date=? WHERE circular_id=? AND status='PENDING'",
            (deadline_date, circular_id),
        )
        updated = cur.rowcount
        conn.commit()
        conn.close()
    try:
        from agents.deadline_parser import ensure_reminders_table, check_reminders
        ensure_reminders_table()
        reminders = check_reminders()
    except Exception as e:
        logger.warning("Reminder setup failed: %s", e)
        reminders = {}
    blockchain.add_entry(
        "DEADLINES_PARSED",
        {
            "circular_id": circular_id,
            "deadline_date": deadline_date,
            "reminders": ["T-30", "T-7", "T-1"],
        },
    )
    _record("Deadline Parser Agent", tasks=max(updated, 1))
    return {"updated": updated, "reminders": reminders}


# ─── LangChain stage builders ─────────────────────────────────────────────────

def _build_pipeline_chain(circular_id: int, blockchain: Blockchain, source: str):
    """
    Compose the 8 pipeline stages into a LangChain RunnableSequence.
    Each stage is a RunnableLambda that receives and returns the shared
    ``state`` dict so outputs are accumulated and visible.
    """

    # Stage 1 — Ingestion context
    def stage_load(state: dict) -> dict:
        state["circular_id"] = circular_id
        state["source"] = source
        logger.info("[Pipeline] Stage 1 — Context loaded for circular %s", circular_id)
        return state

    # Stage 2 — Analysis
    def stage_analyse(state: dict) -> dict:
        analysis = analyze_circular(state["circular_id"])
        state["analysis"] = analysis
        logger.info("[Pipeline] Stage 2 — Analysis complete: %s", analysis.get("urgency"))
        return state

    # Stage 3 — MAP Generation (LLM queue or offline)
    def stage_map_gen(state: dict) -> dict:
        llm_enabled = os.environ.get("PHANTOM_NO_LLM") != "1" and check_llm_health()
        if llm_enabled:
            enqueue_llm_task(state["circular_id"], "GENERATE_MAPS", {"source": source})
            state["map_generation"] = "queued"
            state["maps_generated"] = 0
            logger.info("[Pipeline] Stage 3 — MAPs queued for LLM processing")
        else:
            maps = _fallback_maps_for_circular(state["circular_id"])
            state["map_generation"] = "offline-fallback"
            state["maps_generated"] = len(maps)
            _record("LLM Agent", tasks=len(maps))
            logger.info("[Pipeline] Stage 3 — Offline fallback: %d MAPs created", len(maps))
        return state

    # Stage 4 — Deadlines
    def stage_deadlines(state: dict) -> dict:
        state["deadlines"] = apply_deadlines(state["circular_id"], state["analysis"], blockchain)
        logger.info("[Pipeline] Stage 4 — Deadlines applied")
        return state

    # Stage 5 — Conflict detection
    def stage_conflicts(state: dict) -> dict:
        try:
            from agents.conflict_detector import ensure_conflicts_table, detect_conflicts
            ensure_conflicts_table()
            result = detect_conflicts(state["circular_id"], blockchain)
            state["conflicts"] = result
            _record("Conflict Detector Agent", tasks=result.get("count", 0))
            logger.info("[Pipeline] Stage 5 — Conflicts detected: %d", result.get("count", 0))
        except Exception as e:
            logger.warning("[Pipeline] Stage 5 — Conflict detection failed: %s", e)
            state["conflicts"] = {"error": str(e), "count": 0}
            _record("Conflict Detector Agent", "FAILED", error=str(e))
        return state

    # Stage 6 — Routing
    def stage_routing(state: dict) -> dict:
        try:
            from agents.routing_agent import route_all_pending
            state["routed"] = route_all_pending(blockchain)
            logger.info("[Pipeline] Stage 6 — Routed %d MAPs", state["routed"])
        except Exception as e:
            logger.warning("[Pipeline] Stage 6 — Routing failed: %s", e)
            state["routed"] = 0
        return state

    # Stage 7 — Risk scoring
    def stage_risk(state: dict) -> dict:
        try:
            from agents.risk_scorer import calculate_bank_score, ensure_score_history_table
            ensure_score_history_table()
            state["risk"] = calculate_bank_score()
            logger.info("[Pipeline] Stage 7 — Risk scored: %s", state["risk"].get("bank_score"))
        except Exception as e:
            logger.warning("[Pipeline] Stage 7 — Risk scoring failed: %s", e)
            state["risk"] = {"error": str(e)}
        return state

    # Stage 8 — Notification + blockchain commit
    def stage_notify(state: dict) -> dict:
        create_notification(
            "Circular Pipeline Completed",
            f"Circular #{state['circular_id']} processed: MAPs {state.get('map_generation')}, "
            f"routed {state.get('routed', 0)}.",
            "INFO",
            role="CCO",
            link=f"/cco?circular={state['circular_id']}",
        )
        blockchain.add_entry(
            "CIRCULAR_PIPELINE_COMPLETED",
            {
                "circular_id": state["circular_id"],
                "source": state.get("source"),
                "map_generation": state.get("map_generation"),
                "routed": state.get("routed", 0),
            },
        )
        logger.info("[Pipeline] Stage 8 — Notifications sent, blockchain updated")
        return state

    stages = [
        RunnableLambda(stage_load),
        RunnableLambda(stage_analyse),
        RunnableLambda(stage_map_gen),
        RunnableLambda(stage_deadlines),
        RunnableLambda(stage_conflicts),
        RunnableLambda(stage_routing),
        RunnableLambda(stage_risk),
        RunnableLambda(stage_notify),
    ]
    return stages[0] | stages[1] | stages[2] | stages[3] | stages[4] | stages[5] | stages[6] | stages[7]


# ─── Public entry point ───────────────────────────────────────────────────────

def run_post_ingestion_pipeline(
    circular_id: int,
    blockchain: Blockchain,
    source: str = "drop",
) -> dict:
    """
    Run the full post-ingestion agentic pipeline for a circular.

    Uses a LangChain RunnableSequence when langchain_core is installed,
    otherwise falls back to plain sequential execution.

    Returns a state dict with all stage outputs.
    """
    initial_state: dict = {}

    if _LANGCHAIN_AVAILABLE:
        try:
            chain = _build_pipeline_chain(circular_id, blockchain, source)
            result = chain.invoke(initial_state)
            logger.info(
                "[Pipeline] LangChain pipeline finished for circular %s — source=%s",
                circular_id, source,
            )
            return result
        except Exception as exc:
            logger.error(
                "[Pipeline] LangChain execution failed (%s) — falling back to sequential", exc
            )

    # ── Fallback: sequential execution (identical logic, no framework) ────────
    logger.info("[Pipeline] Sequential pipeline started for circular %s", circular_id)
    result: dict = {"circular_id": circular_id, "source": source}

    result["analysis"] = analyze_circular(circular_id)

    llm_enabled = os.environ.get("PHANTOM_NO_LLM") != "1" and check_llm_health()
    if llm_enabled:
        enqueue_llm_task(circular_id, "GENERATE_MAPS", {"source": source})
        result["map_generation"] = "queued"
    else:
        maps = _fallback_maps_for_circular(circular_id)
        result["map_generation"] = "offline-fallback"
        result["maps_generated"] = len(maps)
        _record("LLM Agent", tasks=len(maps))

    result["deadlines"] = apply_deadlines(circular_id, result["analysis"], blockchain)

    try:
        from agents.conflict_detector import ensure_conflicts_table, detect_conflicts
        ensure_conflicts_table()
        result["conflicts"] = detect_conflicts(circular_id, blockchain)
        _record("Conflict Detector Agent", tasks=result["conflicts"].get("count", 0))
    except Exception as e:
        logger.warning("Conflict detection failed: %s", e)
        result["conflicts"] = {"error": str(e), "count": 0}
        _record("Conflict Detector Agent", "FAILED", error=str(e))

    try:
        from agents.routing_agent import route_all_pending
        result["routed"] = route_all_pending(blockchain)
    except Exception as e:
        logger.warning("Routing failed: %s", e)
        result["routed"] = 0

    try:
        from agents.risk_scorer import calculate_bank_score, ensure_score_history_table
        ensure_score_history_table()
        result["risk"] = calculate_bank_score()
    except Exception as e:
        logger.warning("Risk scoring failed: %s", e)
        result["risk"] = {"error": str(e)}

    create_notification(
        "Circular Pipeline Completed",
        f"Circular #{circular_id} processed: MAPs {result.get('map_generation')}, routed {result.get('routed', 0)}.",
        "INFO",
        role="CCO",
        link=f"/cco?circular={circular_id}",
    )
    blockchain.add_entry(
        "CIRCULAR_PIPELINE_COMPLETED",
        {
            "circular_id": circular_id,
            "source": source,
            "map_generation": result.get("map_generation"),
            "routed": result.get("routed", 0),
        },
    )
    return result
