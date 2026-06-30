"""
Data Retention & Auto-Purge module.
Configurable retention periods for circulars, notifications, and audit logs.
Background task runs periodically to purge expired data.
"""

import logging
from datetime import datetime, timedelta
from pathlib import Path

from utils.database import get_connection
from utils.db_extensions import get_config, set_config, create_notification

logger = logging.getLogger("phantom_compliance.retention")


def get_retention_days(key: str, default: int = 365) -> int:
    try:
        return int(get_config(key, str(default)))
    except (ValueError, TypeError):
        return default


def purge_old_circulars(days: Optional[int] = None) -> int:
    """
    Delete circulars older than `days`.
    Also deletes associated MAPs.
    Returns count of circulars deleted.
    """
    if days is None:
        days = get_retention_days("retention_days_circulars", 365)
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    old = conn.execute(
        "SELECT id FROM circulars WHERE created_at < ?", (cutoff,)
    ).fetchall()
    ids = [r["id"] for r in old]
    if ids:
        placeholders = ",".join("?" * len(ids))
        conn.execute(f"DELETE FROM maps WHERE circular_id IN ({placeholders})", ids)
        conn.execute(f"DELETE FROM circulars WHERE id IN ({placeholders})", ids)
    conn.commit()
    conn.close()
    if ids:
        logger.info(f"Purged {len(ids)} old circulars (> {days} days)")
    return len(ids)


def purge_old_notifications(days: Optional[int] = None) -> int:
    """Delete read notifications older than `days`."""
    if days is None:
        days = get_retention_days("retention_days_notifications", 90)
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    deleted = conn.execute(
        "DELETE FROM notifications WHERE is_read = 1 AND created_at < ?", (cutoff,)
    ).rowcount
    conn.commit()
    conn.close()
    if deleted:
        logger.info(f"Purged {deleted} old notifications (> {days} days)")
    return deleted


def purge_old_audit_logs(days: int = 365) -> int:
    """Delete audit logs older than `days`."""
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    deleted = conn.execute(
        "DELETE FROM audit_log WHERE created_at < ?", (cutoff,)
    ).rowcount
    conn.commit()
    conn.close()
    return deleted


def run_auto_purge():
    """
    Run all configured purge jobs.
    Called by background scheduler.
    """
    enabled = get_config("auto_purge_enabled", "true")
    if enabled.lower() != "true":
        logger.info("Auto-purge is disabled")
        return {"circulars": 0, "notifications": 0, "audit_logs": 0}

    result = {
        "circulars": purge_old_circulars(),
        "notifications": purge_old_notifications(),
        "audit_logs": purge_old_audit_logs(),
    }
    total = sum(result.values())
    if total > 0:
        create_notification(
            title="Auto-Purge Completed",
            message=f"Purged {total} old records: {result}",
            ntype="SYSTEM",
            role="CCO",
        )
    return result
