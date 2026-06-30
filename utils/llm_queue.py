"""
LLM Queue Manager - resilient, retry-capable LLM task queue.

When the LLM server is unreachable, tasks are queued in the llm_queue table
and retried automatically with exponential backoff. This ensures zero data
loss even when the LLM is temporarily down.

Background process:
  1. Polls llm_queue for PENDING tasks
  2. Checks if LLM server is reachable (HEAD request to localhost:8080)
  3. If reachable: process task
  4. If not: leave in queue, retry later
  5. After max_retries: mark FAILED, create notification
"""

import json
import logging
import os
import urllib.request
import urllib.error
from datetime import datetime

from utils.db_extensions import (
    get_pending_llm_tasks, update_llm_task, create_notification
)
from agents.llm_agent import generate_maps
from utils.database import get_connection, _get_master_key

logger = logging.getLogger("phantom_compliance.llm_queue")

LLM_HEALTH_URL = "http://localhost:8080/health"
LLM_COMPLETION_URL = "http://localhost:8080/completion"


_health_cache = {"result": False, "time": 0}


def check_llm_health() -> bool:
    """Check if the LLM server is reachable. Returns True if healthy. Cached for 30s."""
    import time
    now = time.time()
    if now - _health_cache["time"] < 30:
        return _health_cache["result"]
    for url in (LLM_HEALTH_URL, "http://localhost:8080/", "http://localhost:8080/health"):
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status == 200:
                    _health_cache["result"] = True
                    _health_cache["time"] = now
                    return True
        except Exception:
            continue
    _health_cache["result"] = False
    _health_cache["time"] = now
    return False


def process_queue():
    """
    Process one batch of queued LLM tasks.
    Returns dict: {processed, failed, skipped}
    """
    if os.environ.get("PHANTOM_NO_LLM") == "1":
        return {"processed": 0, "failed": 0, "skipped": 0}
    if not check_llm_health():
        logger.warning("LLM server not reachable, skipping queue")
        return {"processed": 0, "failed": 0, "skipped": 0}

    tasks = get_pending_llm_tasks(limit=5)
    result = {"processed": 0, "failed": 0, "skipped": 0}

    for task in tasks:
        try:
            update_llm_task(task["id"], "PROCESSING")
            mk = _get_master_key()

            if task["action"] == "GENERATE_MAPS":
                maps = generate_maps(task["circular_id"], mk)
                if maps is None:
                    raise ValueError("MAP generation failed (error)")
                try:
                    from config.settings import get_app_paths
                    from p_crypto.blockchain import Blockchain
                    from agents.pipeline import apply_deadlines
                    from agents.routing_agent import route_all_pending
                    from agents.risk_scorer import calculate_bank_score, ensure_score_history_table
                    blockchain = Blockchain(get_app_paths()["CHAIN_PATH"])
                    conn = get_connection()
                    row = conn.execute("SELECT analysis FROM circulars WHERE id=?", (task["circular_id"],)).fetchone()
                    conn.close()
                    analysis = {}
                    if row and row["analysis"]:
                        try:
                            analysis = json.loads(row["analysis"])
                        except Exception:
                            analysis = {}
                    apply_deadlines(task["circular_id"], analysis, blockchain)
                    route_all_pending(blockchain)
                    ensure_score_history_table()
                    calculate_bank_score()
                    blockchain.add_entry("MAP_GENERATION_PIPELINE_COMPLETED", {
                        "circular_id": task["circular_id"],
                        "maps_generated": len(maps),
                    })
                except Exception as downstream_error:
                    logger.warning("Post-MAP pipeline continuation failed: %s", downstream_error)
                update_llm_task(task["id"], "DONE")
                result["processed"] += 1
            else:
                update_llm_task(task["id"], "DONE")
                result["processed"] += 1

        except Exception as e:
            error_msg = str(e)[:500]
            logger.error(f"Queue task {task['id']} failed: {error_msg}")
            update_llm_task(task["id"], "FAILED", error_msg)
            result["failed"] += 1

            if task["retry_count"] >= task["max_retries"] - 1:
                create_notification(
                    title="LLM Task Failed",
                    message=f"Task #{task['id']} for circular #{task['circular_id']} "
                            f"failed after {task['max_retries']} retries: {error_msg[:200]}",
                    ntype="ERROR",
                    role="CCO",
                )

    return result
