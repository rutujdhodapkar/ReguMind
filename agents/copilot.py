"""
PHANTOM COMPLIANCE — Compliance Copilot
Natural language query engine for compliance data.
Supports both rule-based and LLM-powered answers.
Quick-action registry for frontend button shortcuts.
"""

import json
import logging
import urllib.request
import urllib.error
from datetime import datetime, timedelta

from utils.database import get_connection, get_all_circulars, get_all_maps, get_maps_for_department
from utils.db_extensions import audit_log
from utils.llm_queue import check_llm_health
from agents.risk_scorer import calculate_bank_score
from agents.acknowledgement_agent import get_unacknowledged_count

LLM_URL = "http://localhost:8080/completion"

logger = logging.getLogger("phantom_compliance.copilot")

_INTENT_TRIGGERS = {
    "circulars_about": ["which circulars", "circulars about", "circulars mentioning", "circulars on", "circulars related to", "show circulars", "find circulars", "circulars for"],
    "dept_deadlines": ["deadlines for", "deadlines in", "show deadlines", "department deadlines", "due dates", "pending deadlines"],
    "overdue": ["who is behind", "which teams are behind", "who is delayed", "overdue", "breached", "behind schedule", "missed deadline"],
    "pending_dept": ["show me pending", "pending items for", "pending tasks", "my pending", "pending maps", "what is pending"],
    "recent_changes": ["what changed", "recent changes", "this month", "latest circulars", "new this month", "recent circulars"],
    "summary": ["summary", "overview", "show status", "dashboard", "status report", "what is the status"],
    "risk_score": ["risk score", "compliance score", "risk", "how risky", "score", "bank score", "risk assessment"],
    "conflicts": ["conflicts", "overrides", "contradictions", "conflicting", "which circulars conflict"],
    "acknowledgement": ["acknowledge", "unacknowledged", "not acknowledged", "pending acknowledgement", "who hasn't acknowledged"],
    "how_many": ["how many", "count of", "total", "number of"],
}


def _normalise(text: str) -> str:
    return text.lower().strip()


def _match_intent(query: str) -> tuple[str, str]:
    """Match query to an intent and extract the topic/subject."""
    q = _normalise(query)
    for intent, triggers in _INTENT_TRIGGERS.items():
        for trigger in triggers:
            idx = q.find(trigger)
            if idx != -1:
                topic = q[idx + len(trigger):].strip().lstrip(",").strip()
                return intent, topic
    return "unknown", ""


def _build_suggestions() -> list[str]:
    return [
        "Which circulars affect KYC?",
        "Show payment deadlines",
        "Which teams are behind?",
        "What changed this month?",
        "Compliance score",
        "Conflicts",
        "Summary",
        "Show me pending IT_Security",
        "How many circulars this month?",
        "Unacknowledged items",
    ]


def _llm_answer(nl_query: str, data: dict, rule_answer: str) -> str | None:
    """Send query + data to LLM for a natural-language answer. Returns None on failure."""
    try:
        payload = json.dumps({
            "prompt": (
                "[INST]Answer briefly (1-2 sentences) using the data. "
                f"Question: {nl_query}\n\nData:\n{json.dumps(data, indent=2, default=str)}\n\n"
                "Answer:[/INST]"
            ),
            "temperature": 0.1,
            "max_tokens": 128,
            "stop": ["</s>", "\n\n\n"],
        }).encode("utf-8")
        req = urllib.request.Request(
            LLM_URL, data=payload,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            text = json.loads(resp.read().decode("utf-8")).get("content", "")
            if text.strip():
                return text.strip()
    except Exception:
        logger.exception("LLM copilot call failed")
    return None


def query_compliance(nl_query: str, user_role: str = "CCO", user_dept: str = "", use_llm: bool = False) -> dict:
    """
    Parse a natural language query using keyword matching.
    Optionally enhance the answer with LLM if use_llm=True and LLM server is healthy.
    Returns {'answer': str, 'data': ..., 'suggestions': [...]}.
    """
    def _rule_query():
        intent, topic = _match_intent(nl_query)
        logger.info("Copilot query: '%s' -> intent=%s topic='%s' role=%s", nl_query, intent, topic, user_role)

        if intent == "circulars_about":
            if not topic:
                topic = user_dept
            conn = get_connection()
            rows = conn.execute(
                "SELECT id, circular_number, subject_line, department_code, issue_date "
                "FROM circulars WHERE subject_line LIKE ? ORDER BY issue_date DESC LIMIT 20",
                (f"%{topic}%",),
            ).fetchall()
            conn.close()
            result = [dict(r) for r in rows]
            if result:
                items = "\n".join(f"  • {r['circular_number']}: {r['subject_line']} ({r['issue_date']})" for r in result)
                return {
                    "answer": f"Found {len(result)} circular{'s' if len(result) != 1 else ''} related to '{topic}':\n{items}",
                    "data": result,
                    "suggestions": _build_suggestions(),
                }
            return {
                "answer": f"No circulars found mentioning '{topic}'.",
                "data": [],
                "suggestions": _build_suggestions(),
            }

        if intent == "dept_deadlines":
            dept = topic if topic else user_dept
            if not dept:
                return {
                    "answer": "Please specify a department (e.g. 'Show Payment deadlines').",
                    "data": [],
                    "suggestions": _build_suggestions(),
                }
            maps = get_maps_for_department(dept)
            if not maps:
                return {
                    "answer": f"No deadlines found for department '{dept}'.",
                    "data": [],
                    "suggestions": _build_suggestions(),
                }
            items = "\n".join(
                f"  • MAP #{m['id']} | {m.get('circular_number','?')} | Due: {m.get('deadline_date','N/A')} | Status: {m.get('status','?')}"
                for m in maps
            )
            return {
                "answer": f"{len(maps)} deadline{'s' if len(maps) != 1 else ''} for {dept}:\n{items}",
                "data": maps,
                "suggestions": _build_suggestions(),
            }

        if intent == "overdue":
            today_str = datetime.now().strftime("%Y-%m-%d")
            conn = get_connection()
            rows = conn.execute(
                """SELECT m.*, c.circular_number, c.subject_line
                   FROM maps m JOIN circulars c ON m.circular_id = c.id
                   WHERE m.deadline_date < ? AND m.status NOT IN ('VALIDATED','SUPERSEDED')
                   ORDER BY m.deadline_date ASC""",
                (today_str,),
            ).fetchall()
            conn.close()
            result = [dict(r) for r in rows]
            if not result:
                return {
                    "answer": "No overdue items found. Everything is on track.",
                    "data": [],
                    "suggestions": _build_suggestions(),
                }
            grouped = {}
            for r in result:
                assigned = r.get("assigned_to", "Unassigned")
                grouped.setdefault(assigned, []).append(r)
            lines = []
            for dept, items in sorted(grouped.items()):
                lines.append(f"  {dept}: {len(items)} overdue")
            summary = "\n".join(lines)
            return {
                "answer": f"Found {len(result)} overdue item{'s' if len(result) != 1 else ''}:\n{summary}",
                "data": result,
                "suggestions": _build_suggestions(),
            }

        if intent == "pending_dept":
            dept = topic if topic else user_dept
            if not dept:
                return {
                    "answer": "Please specify a department (e.g. 'Show me pending IT_Security').",
                    "data": [],
                    "suggestions": _build_suggestions(),
                }
            conn = get_connection()
            rows = conn.execute(
                """SELECT m.*, c.circular_number, c.subject_line
                   FROM maps m JOIN circulars c ON m.circular_id = c.id
                   WHERE m.assigned_to = ? AND m.status NOT IN ('VALIDATED','SUPERSEDED')
                   ORDER BY m.deadline_date ASC""",
                (dept,),
            ).fetchall()
            conn.close()
            result = [dict(r) for r in rows]
            if not result:
                return {
                    "answer": f"No pending items for '{dept}'.",
                    "data": [],
                    "suggestions": _build_suggestions(),
                }
            items = "\n".join(
                f"  • MAP #{m['id']} | {m.get('circular_number','?')} | Due: {m.get('deadline_date','N/A')} | Status: {m.get('status','?')}"
                for m in result
            )
            return {
                "answer": f"{len(result)} pending item{'s' if len(result) != 1 else ''} for {dept}:\n{items}",
                "data": result,
                "suggestions": _build_suggestions(),
            }

        if intent == "recent_changes":
            thirty_days_ago = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
            conn = get_connection()
            rows = conn.execute(
                "SELECT id, circular_number, subject_line, department_code, issue_date, ingested_at "
                "FROM circulars WHERE ingested_at >= ? ORDER BY ingested_at DESC LIMIT 20",
                (thirty_days_ago,),
            ).fetchall()
            conn.close()
            result = [dict(r) for r in rows]
            if not result:
                return {
                    "answer": "No circulars ingested in the last 30 days.",
                    "data": [],
                    "suggestions": _build_suggestions(),
                }
            items = "\n".join(
                f"  • {r['circular_number']}: {r['subject_line']} ({r['department_code']}, {r['issue_date']})"
                for r in result
            )
            return {
                "answer": f"{len(result)} circular{'s' if len(result) != 1 else ''} in the last 30 days:\n{items}",
                "data": result,
                "suggestions": _build_suggestions(),
            }

        if intent == "summary":
            circulars = get_all_circulars()
            maps = get_all_maps()
            total_circ = len(circulars)
            total_maps = len(maps)
            validated = sum(1 for m in maps if m.get("status") == "VALIDATED")
            pending = sum(1 for m in maps if m.get("status") in ("PENDING", "ASSIGNED", "ASSIGNED_UNACKNOWLEDGED", "ASSIGNED_ACKNOWLEDGED"))
            overdue = sum(1 for m in maps if m.get("status") in ("BREACHED", "ESCALATED"))
            superseded = sum(1 for m in maps if m.get("status") == "SUPERSEDED")
            summary_text = (
                f"Compliance Overview:\n"
                f"  • Circulars ingested: {total_circ}\n"
                f"  • Total MAPs: {total_maps}\n"
                f"  • Validated: {validated}\n"
                f"  • Pending: {pending}\n"
                f"  • Overdue / Breached: {overdue}\n"
                f"  • Superseded: {superseded}"
            )
            return {
                "answer": summary_text,
                "data": {"circulars": len(circulars), "maps": len(maps), "validated": validated, "pending": pending, "overdue": overdue, "superseded": superseded},
                "suggestions": _build_suggestions(),
            }

        if intent == "risk_score":
            try:
                score_data = calculate_bank_score()
                dept_lines = "\n".join(
                    f"  • {d.get('display_name', d['department'])}: {d['score']}/100"
                    for d in score_data.get("departments", [])
                )
                answer = (
                    f"Bank Compliance Score: {score_data['bank_score']}/100 ({score_data['threshold_label']})\n"
                    f"Change from yesterday: {score_data['delta']:+.1f}\n"
                    f"Departments:\n{dept_lines}"
                )
                if score_data.get("insight"):
                    answer += f"\nInsight: {score_data['insight']}"
                return {
                    "answer": answer,
                    "data": score_data,
                    "suggestions": _build_suggestions(),
                }
            except Exception as e:
                logger.exception("Risk score calculation failed")
                return {
                    "answer": f"Could not calculate risk score: {e}",
                    "data": {},
                    "suggestions": _build_suggestions(),
                }

        if intent == "conflicts":
            from agents.conflict_detector import get_all_conflicts
            try:
                conflicts = get_all_conflicts(resolved=False)
                if not conflicts:
                    return {
                        "answer": "No unresolved conflicts detected.",
                        "data": [],
                        "suggestions": _build_suggestions(),
                    }
                items = "\n".join(
                    f"  • {c.get('relationship','?')}: Circular #{c.get('circular_a_id','?')} vs #{c.get('circular_b_id','?')} "
                    f"(confidence: {c.get('confidence',0)})"
                    for c in conflicts
                )
                return {
                    "answer": f"{len(conflicts)} unresolved conflict{'s' if len(conflicts) != 1 else ''}:\n{items}",
                    "data": conflicts,
                    "suggestions": _build_suggestions(),
                }
            except Exception as e:
                logger.exception("Conflict fetch failed")
                return {
                    "answer": f"Could not fetch conflicts: {e}",
                    "data": [],
                    "suggestions": _build_suggestions(),
                }

        if intent == "acknowledgement":
            try:
                ack_data = get_unacknowledged_count()
                count = ack_data.get("unacknowledged", 0)
                total = ack_data.get("total_unacknowledged", 0)
                return {
                    "answer": f"{count} unacknowledged MAP{'s' if count != 1 else ''} "
                             f"({total} total across all departments). "
                             f"Use the acknowledgement dashboard to review.",
                    "data": ack_data,
                    "suggestions": _build_suggestions(),
                }
            except Exception as e:
                logger.exception("Acknowledgement count failed")
                return {
                    "answer": f"Could not fetch acknowledgement status: {e}",
                    "data": {},
                    "suggestions": _build_suggestions(),
                }

        if intent == "how_many":
            counts = []
            if "circular" in nl_query.lower():
                c = get_all_circulars()
                counts.append(f"circulars: {len(c)}")
            if "map" in nl_query.lower() or "deadline" in nl_query.lower():
                m = get_all_maps()
                counts.append(f"MAPs: {len(m)}")
            if "conflict" in nl_query.lower():
                from agents.conflict_detector import get_all_conflicts
                try:
                    cfl = get_all_conflicts()
                    unresolved = sum(1 for x in cfl if not x.get("resolved"))
                    counts.append(f"conflicts: {len(cfl)} ({unresolved} unresolved)")
                except Exception:
                    counts.append("conflicts: (error)")
            if not counts:
                counts.append(f"circulars: {len(get_all_circulars())}")
                counts.append(f"MAPs: {len(get_all_maps())}")
            return {
                "answer": "Counts — " + ", ".join(counts),
                "data": {k.split(":")[0].strip(): int(v.strip()) for item in counts for k, v in [item.split(":")]},
                "suggestions": _build_suggestions(),
            }

        return {
            "answer": (
                "I can help you with:\n"
                "  • 'Which circulars affect KYC?'\n"
                "  • 'Show Payment deadlines'\n"
                "  • 'Which teams are behind?'\n"
                "  • 'What changed this month?'\n"
                "  • 'Compliance score'\n"
                "  • 'Conflicts'\n"
                "  • 'Summary'\n"
                "  • 'How many circulars?'\n"
                "  • 'Unacknowledged'"
            ),
            "suggestions": _build_suggestions(),
        }

    try:
        result = _rule_query()
        if use_llm and result.get("answer") and result.get("data"):
            llm_text = _llm_answer(nl_query, result["data"], result["answer"])
            if llm_text:
                result["answer"] = llm_text
                result["llm_enhanced"] = True
        return result
    except Exception as e:
        logger.exception("Copilot query failed")
        return {
            "answer": f"An error occurred while processing your query: {e}",
            "data": {},
            "suggestions": _build_suggestions(),
        }


def get_suggestions(query_so_far: str = "") -> list[str]:
    """Return autocomplete suggestions based on current partial query."""
    try:
        if not query_so_far:
            return _build_suggestions()
        q = _normalise(query_so_far)
        suggestions = _build_suggestions()
        return [s for s in suggestions if q in _normalise(s)]
    except Exception as e:
        logger.error("get_suggestions failed: %s", e)
        return _build_suggestions()


def ensure_copilot_tables():
    """CREATE TABLE IF NOT EXISTS copilot_actions."""
    conn = get_connection()
    conn.execute("""CREATE TABLE IF NOT EXISTS copilot_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        api_endpoint TEXT NOT NULL,
        description TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now'))
    )""")
    conn.commit()
    conn.close()
    logger.info("copilot_actions table ensured")


def register_quick_action(name: str, api_endpoint: str, description: str = "") -> bool:
    """Register a custom quick action button."""
    try:
        ensure_copilot_tables()
        conn = get_connection()
        conn.execute(
            "INSERT INTO copilot_actions (name, api_endpoint, description) VALUES (?, ?, ?)",
            (name, api_endpoint, description),
        )
        conn.commit()
        conn.close()
        logger.info("Quick action registered: %s -> %s", name, api_endpoint)
        audit_log(0, "SYSTEM", "QUICK_ACTION_REGISTERED", "copilot", 0,
                  f"Action '{name}' -> {api_endpoint}")
        return True
    except Exception as e:
        logger.exception("Failed to register quick action '%s'", name)
        return False


def execute_quick_action(action_id: int) -> dict:
    """Validate a registered quick action exists and return it for frontend execution."""
    try:
        ensure_copilot_tables()
        conn = get_connection()
        row = conn.execute(
            "SELECT * FROM copilot_actions WHERE id = ?", (action_id,)
        ).fetchone()
        conn.close()
        if not row:
            return {"success": False, "error": f"Action #{action_id} not found"}
        action = dict(row)
        return {
            "success": True,
            "action": action,
            "message": "Execute from frontend",
            "endpoint": action["api_endpoint"],
        }
    except Exception as e:
        logger.exception("execute_quick_action failed for id %s", action_id)
        return {"success": False, "error": str(e)}


def get_all_actions() -> list[dict]:
    """Return all registered quick actions."""
    try:
        ensure_copilot_tables()
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM copilot_actions ORDER BY created_at DESC"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.exception("get_all_actions failed")
        return []
