"""
IMPLEMENTATION PLAN GENERATOR
- Generates step-by-step action plans for MAPs
- Tracks progress per step
- Recalculates completion percentage
- Optionally appends blockchain blocks
"""

import json
import logging
from datetime import datetime, timedelta

from utils.database import get_connection

logger = logging.getLogger("phantom_compliance.planner")

DEFAULT_TEMPLATE = [
    {"step_number": 1, "action": "Review circular requirements", "responsible_role": "CCO/Compliance", "estimated_hours": 2, "depends_on": [], "evidence_required": "Circular review notes"},
    {"step_number": 2, "action": "Update Standard Operating Procedure (SOP)", "responsible_role": "Department Head", "estimated_hours": 8, "depends_on": [1], "evidence_required": "Updated SOP document"},
    {"step_number": 3, "action": "Modify backend/system configuration", "responsible_role": "IT/Department", "estimated_hours": 16, "depends_on": [1], "evidence_required": "Configuration change log"},
    {"step_number": 4, "action": "Train relevant employees", "responsible_role": "HR/Training", "estimated_hours": 4, "depends_on": [2, 3], "evidence_required": "Training attendance record"},
    {"step_number": 5, "action": "Implement control measures", "responsible_role": "Department Team", "estimated_hours": 8, "depends_on": [2], "evidence_required": "Control implementation report"},
    {"step_number": 6, "action": "Upload compliance evidence", "responsible_role": "Compliance Officer", "estimated_hours": 2, "depends_on": [5], "evidence_required": "Evidence documents"},
    {"step_number": 7, "action": "Internal audit review", "responsible_role": "Internal Audit", "estimated_hours": 4, "depends_on": [6], "evidence_required": "Audit sign-off"},
    {"step_number": 8, "action": "Mark as complete in system", "responsible_role": "CCO/Compliance", "estimated_hours": 1, "depends_on": [7], "evidence_required": "Final approval"},
]


def ensure_plans_table():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS implementation_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            map_id INTEGER NOT NULL,
            steps_json TEXT NOT NULL,
            total_hours REAL NOT NULL,
            estimated_completion TEXT NOT NULL,
            progress_pct REAL DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(map_id) REFERENCES maps(id)
        )
    """)
    conn.commit()
    conn.close()


def generate_plan(map_id: int, blockchain=None) -> dict:
    ensure_plans_table()
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM maps WHERE id = ?", (map_id,)).fetchone()
        if not row:
            raise ValueError(f"MAP #{map_id} not found")

        deadline_str = row["deadline_date"]
        buffer_days = row["deadline_days"] if row["deadline_days"] else 0
        buffer_days = max(buffer_days, 7)

        steps = []
        for tmpl in DEFAULT_TEMPLATE:
            step = dict(tmpl)
            step["status"] = "pending"
            step["completed_at"] = None
            steps.append(step)

        total_hours = sum(s["estimated_hours"] for s in steps)
        deadline_date = datetime.strptime(deadline_str, "%Y-%m-%d")
        estimated_completion = (deadline_date - timedelta(days=buffer_days)).strftime("%Y-%m-%d")

        steps_json = json.dumps(steps, ensure_ascii=False)
        plan_data = {
            "map_id": map_id,
            "steps_json": steps_json,
            "total_hours": total_hours,
            "estimated_completion": estimated_completion,
            "progress_pct": 0.0,
        }

        cur = conn.execute(
            """INSERT INTO implementation_plans
               (map_id, steps_json, total_hours, estimated_completion, progress_pct)
               VALUES (?, ?, ?, ?, ?)""",
            (map_id, steps_json, total_hours, estimated_completion, 0.0),
        )
        plan_id = cur.lastrowid
        conn.commit()

        plan = {
            "id": plan_id,
            "map_id": map_id,
            "steps": steps,
            "total_hours": total_hours,
            "estimated_completion": estimated_completion,
            "progress_pct": 0.0,
        }

        if blockchain is not None:
            payload = {
                "plan_id": plan_id,
                "map_id": map_id,
                "steps_count": len(steps),
                "total_hours": total_hours,
                "estimated_completion": estimated_completion,
            }
            blockchain.add_entry("IMPLEMENTATION_PLAN_CREATED", payload)

        logger.info(f"Generated implementation plan #{plan_id} for MAP #{map_id}")
        return plan

    except Exception:
        logger.exception(f"Failed to generate plan for MAP #{map_id}")
        raise
    finally:
        conn.close()


def get_plan(map_id: int) -> dict:
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM implementation_plans WHERE map_id = ? ORDER BY id DESC LIMIT 1",
            (map_id,),
        ).fetchone()
        if not row:
            raise ValueError(f"No implementation plan found for MAP #{map_id}")

        steps = json.loads(row["steps_json"])
        return {
            "id": row["id"],
            "map_id": row["map_id"],
            "steps": steps,
            "total_hours": row["total_hours"],
            "estimated_completion": row["estimated_completion"],
            "progress_pct": row["progress_pct"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
    except Exception:
        logger.exception(f"Failed to get plan for MAP #{map_id}")
        raise
    finally:
        conn.close()


def update_plan_progress(plan_id: int, step_number: int, status: str) -> dict:
    if status not in ("pending", "in_progress", "completed"):
        raise ValueError(f"Invalid status: {status}")

    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM implementation_plans WHERE id = ?", (plan_id,)
        ).fetchone()
        if not row:
            raise ValueError(f"Implementation plan #{plan_id} not found")

        steps = json.loads(row["steps_json"])
        matched = [s for s in steps if s["step_number"] == step_number]
        if not matched:
            raise ValueError(f"Step #{step_number} not found in plan #{plan_id}")

        step = matched[0]
        step["status"] = status
        if status == "completed":
            step["completed_at"] = datetime.now().isoformat()
        else:
            step["completed_at"] = None

        completed_steps = sum(1 for s in steps if s.get("status") == "completed")
        total_steps = len(steps)
        progress_pct = round((completed_steps / total_steps) * 100, 2) if total_steps > 0 else 0.0

        updated_json = json.dumps(steps, ensure_ascii=False)
        conn.execute(
            """UPDATE implementation_plans
               SET steps_json = ?, progress_pct = ?, updated_at = datetime('now')
               WHERE id = ?""",
            (updated_json, progress_pct, plan_id),
        )
        conn.commit()

        return {
            "id": plan_id,
            "map_id": row["map_id"],
            "steps": steps,
            "total_hours": row["total_hours"],
            "estimated_completion": row["estimated_completion"],
            "progress_pct": progress_pct,
        }
    except Exception:
        logger.exception(f"Failed to update progress for plan #{plan_id}")
        raise
    finally:
        conn.close()
