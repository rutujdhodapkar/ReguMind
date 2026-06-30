"""
PHANTOM COMPLIANCE - Air-Gapped Agentic Regulatory Compliance System
Main entry point. Initializes database, background services, and dashboard.

Usage:
  python main.py                   # Launch Flask web UI (default)
  python main.py --no-llm          # Run without LLM (demo/offline)
  python main.py --generate-demo   # Generate demo PDFs and exit
  python main.py --seed-demo-users # Seed demo department users
  python main.py --backend-only    # Run background services only (no web UI)
"""

import sys
import os
import threading
import time
import argparse
import logging

from config.settings import get_app_paths, load_config, save_config
from utils.logging_setup import setup_logging
from utils.database import init_database, seed_admin_user, user_exists
from utils.db_extensions import apply_v2_schema, migrate_users_to_v2, create_user
from utils.llm_queue import process_queue, check_llm_health
from utils.retention import run_auto_purge
from p_crypto.blockchain import Blockchain
from agents.ingestion_agent import start_watching

logger = None


def first_run_setup():
    from auth.credential_manager import store_admin_password, get_admin_password
    from config.settings import load_config, save_config

    paths = get_app_paths()
    init_database()
    apply_v2_schema()

    if not user_exists("admin"):
        import secrets
        cfg = load_config()
        admin_password = cfg.get("admin_password")
        if not admin_password:
            admin_password = secrets.token_urlsafe(12)
            cfg["admin_password"] = admin_password
        seed_admin_user(admin_password)
        migrate_users_to_v2()
        store_admin_password(admin_password)
        cfg["first_run_complete"] = True
        cfg["llm_url"] = "http://localhost:8080/completion"
        save_config(cfg)
        print(f"[FIRST RUN] Admin password: {admin_password}")
        print("[FIRST RUN] Saved to Windows Credential Manager. Login with username: admin")
    else:
        migrate_users_to_v2()
        cfg = load_config()
        if "first_run_complete" not in cfg:
            cfg["first_run_complete"] = True
            cfg["llm_url"] = "http://localhost:8080/completion"
            save_config(cfg)
        if not get_admin_password():
            stored = cfg.get("admin_password", "")
            if stored:
                store_admin_password(stored)


def seed_demo_users():
    """Seed department users for demo purposes."""
    apply_v2_schema()
    migrate_users_to_v2()
    demo_users = [
        ("kyc_officer", "KYC12345", "KYC", "KYC Officer", "DOR.AML"),
        ("payments_officer", "Pay12345", "Payments", "Payments Officer", "CO.DPSS"),
        ("it_security_officer", "IT12345", "IT_Security", "IT Security Officer", "DoS.CO"),
        ("treasury_officer", "Tre12345", "Treasury", "Treasury Officer", "DBR.BP"),
        ("forex_officer", "For12345", "Forex", "Forex Officer", "A.P.DIR"),
        ("credit_officer", "Cre12345", "Credit_Risk", "Credit Risk Officer", "DOR.STR"),
    ]
    from utils.db_extensions import get_all_users_v2
    existing = {u["username"] for u in get_all_users_v2()}
    for uname, pwd, role, display, dept in demo_users:
        if uname not in existing:
            create_user(uname, pwd, role, display, dept, created_by=1)
            print(f"Created demo user: {uname} ({role})")
    print("Demo users seeded. Passwords: see passwords above")


def start_inbox_watcher():
    paths = get_app_paths()
    bc = Blockchain(paths["CHAIN_PATH"])
    observer = start_watching(paths["INBOX_DIR"], bc)
    return observer


def background_worker(stop_event):
    """Background thread: process LLM queue, auto-route, auto-validate, auto-escalate, auto-purge."""
    from p_crypto.blockchain import Blockchain
    paths = get_app_paths()
    blockchain = Blockchain(paths["CHAIN_PATH"])
    
    # Initialize agent viz tables
    try:
        from core.agent_viz import ensure_agent_viz_tables
        ensure_agent_viz_tables()
    except Exception:
        pass

    last_queue_run = 0
    last_route_run = 0
    last_validate_run = 0
    last_escalate_run = 0
    last_ack_check_run = 0
    last_reminder_run = 0
    last_risk_recalc_run = 0
    last_purge_run = 0
    last_backup_run = 0

    while not stop_event.is_set():
        now = time.time()

        def _record_run(agent_name, func, *args, **kwargs):
            from core.agent_viz import record_agent_run
            start_t = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_t
                if isinstance(result, dict):
                    tasks = sum(v for v in result.values() if isinstance(v, (int, float)))
                elif isinstance(result, (list, tuple)):
                    tasks = len(result)
                else:
                    tasks = int(result) if result else 0
                record_agent_run(agent_name, "COMPLETED", tasks_processed=tasks)
                return result
            except Exception as e:
                record_agent_run(agent_name, "FAILED", error=str(e))
                raise

        # Daily compliance snapshot (at ~9 AM = 32400 seconds from midnight)
        try:
            current_hour = time.localtime().tm_hour
            if current_hour == 9 and not hasattr(background_worker, '_snapshot_today'):
                from agents.compliance_checker import run_full_compliance_check
                snapshot = run_full_compliance_check()
                logger.info(f"Daily compliance snapshot: score={snapshot['compliance_score']}, status={snapshot['status']}")
                try:
                    conn = __import__("utils.database", fromlist=["get_connection"]).get_connection()
                    conn.execute("INSERT INTO daily_snapshots (snapshot_data) VALUES (?)",
                                 (json.dumps(snapshot, default=str),))
                    conn.commit()
                    conn.close()
                except Exception:
                    pass
                background_worker._snapshot_today = True
        except Exception:
            pass
        if current_hour != 9:
            background_worker._snapshot_today = False

        if now - last_queue_run >= 30:
            try:
                result = process_queue()
                if result["processed"] > 0 or result["failed"] > 0:
                    logger.info(f"LLM queue: {result}")
                _record_run("LLM Agent", lambda: result)
            except Exception as e:
                logger.error(f"Queue processing error: {e}", exc_info=True)
            last_queue_run = now

        if now - last_route_run >= 120:
            try:
                from agents.routing_agent import route_all_pending
                result = _record_run("Routing Agent", route_all_pending, blockchain)
                if isinstance(result, dict):
                    routed = result.get("routed", 0)
                elif isinstance(result, (list, tuple)):
                    routed = len(result)
                else:
                    routed = int(result) if result else 0
                if routed > 0:
                    logger.info(f"Auto-routed {routed} MAPs")
            except Exception as e:
                logger.error(f"Auto-route error: {e}", exc_info=True)
            last_route_run = now

        if now - last_validate_run >= 180:
            try:
                from agents.validation_agent import run_validation_cycle
                result = _record_run("Validation Agent", run_validation_cycle, blockchain)
                if isinstance(result, dict):
                    validated = result.get("validated", 0)
                    breached = result.get("breached", 0)
                elif isinstance(result, (list, tuple)):
                    validated = len(result)
                    breached = 0
                else:
                    validated = int(result) if result else 0
                    breached = 0
                if validated > 0 or breached > 0:
                    logger.info(f"Auto-validation: {validated} valid, {breached} breached")
            except Exception as e:
                logger.error(f"Auto-validate error: {e}", exc_info=True)
            last_validate_run = now

        if now - last_escalate_run >= 300:
            try:
                from agents.escalation_agent import escalate_overdue_maps
                result = _record_run("Escalation Agent", escalate_overdue_maps, blockchain)
                if isinstance(result, (list, tuple)):
                    escalated = len(result)
                elif isinstance(result, dict):
                    escalated = result.get("escalated", 0)
                else:
                    escalated = int(result) if result else 0
                if escalated > 0:
                    logger.info(f"Auto-escalated {escalated} overdue MAPs")
            except Exception as e:
                logger.error(f"Auto-escalate error: {e}", exc_info=True)
            last_escalate_run = now

        if now - last_reminder_run >= 300:
            try:
                from agents.deadline_parser import check_reminders
                result = _record_run("Deadline Parser", check_reminders)
                if isinstance(result, dict):
                    reminded = sum(result.values())
                elif isinstance(result, (list, tuple)):
                    reminded = len(result)
                else:
                    reminded = int(result) if result else 0
                if reminded > 0:
                    logger.info(f"Deadline reminders triggered: {result}")
            except Exception as e:
                logger.error(f"Reminder check error: {e}", exc_info=True)
            last_reminder_run = now

        if now - last_ack_check_run >= 600:
            try:
                from agents.acknowledgement_agent import check_unacknowledged_maps
                result = _record_run("Acknowledgement Agent", check_unacknowledged_maps, blockchain)
                if isinstance(result, (list, tuple)):
                    escalated = len(result)
                elif isinstance(result, dict):
                    escalated = result.get("escalated", 0)
                else:
                    escalated = int(result) if result else 0
                if escalated > 0:
                    logger.info(f"Unacknowledged MAPs escalated: {escalated}")
            except Exception as e:
                logger.error(f"Acknowledgement check error: {e}", exc_info=True)
            last_ack_check_run = now

        if now - last_risk_recalc_run >= 900:
            try:
                from agents.risk_scorer import calculate_bank_score, ensure_score_history_table
                ensure_score_history_table()
                score = _record_run("Risk Scorer", calculate_bank_score)
                logger.info(f"Risk score recalculated: {score['bank_score']}/100 ({score['threshold']})")
            except Exception as e:
                logger.error(f"Risk score error: {e}", exc_info=True)
            last_risk_recalc_run = now

        if now - last_purge_run >= 3600:
            try:
                result = run_auto_purge()
                if sum(result.values()) > 0:
                    logger.info(f"Auto-purge: {result}")
            except Exception as e:
                logger.error(f"Auto-purge error: {e}", exc_info=True)
            last_purge_run = now

        if now - last_backup_run >= 14400:
            try:
                from utils.backup import create_backup
                backup_path = create_backup()
                logger.info(f"Auto-backup created: {backup_path.name}")
            except Exception as e:
                logger.error(f"Auto-backup error: {e}", exc_info=True)
            try:
                from core.data_protector import protect_database, protect_config
                protect_database()
                protect_config()
                logger.info("Data protector backup completed")
            except Exception as e:
                logger.error(f"Data protector backup error: {e}", exc_info=True)
            last_backup_run = now

        stop_event.wait(5)


def main():
    global logger

    parser = argparse.ArgumentParser(description="Phantom Compliance")
    parser.add_argument("--no-llm", action="store_true", help="Run without LLM (offline demo)")
    parser.add_argument("--generate-demo", action="store_true", help="Generate demo PDFs and exit")
    parser.add_argument("--first-run", action="store_true", help="Force first-run setup")
    parser.add_argument("--seed-demo-users", action="store_true", help="Seed demo department users")
    parser.add_argument("--backend-only", action="store_true", help="Run background services only (no web UI)")
    parser.add_argument("--port", type=int, default=5000, help="Web UI port (default: 5000)")
    parser.add_argument("--host", default="127.0.0.1", help="Web UI host (default: 127.0.0.1)")
    parser.add_argument("--skip-integrity-check", action="store_true", help="Bypass integrity hash check")

    args = parser.parse_args()

    if args.generate_demo:
        from demo_data.generate_demo import generate_pdfs
        generate_pdfs()
        print("Demo PDFs generated in /demo_data and copied to /inbox")
        sys.exit(0)

    if args.seed_demo_users:
        seed_demo_users()
        sys.exit(0)

    logger = setup_logging()

    # ─── Tamper Detection ───────────────────────────────────────
    from core.tamper_detection import block_if_tampered
    if not block_if_tampered():
        print("\n  System blocked due to integrity violation.")
        print("  Run with --skip-integrity-check to bypass (NOT RECOMMENDED).")
        if not args.skip_integrity_check:
            sys.exit(1)
        else:
            print("  Bypassing integrity check (--skip-integrity-check flag detected)")
    # ─────────────────────────────────────────────────────────────

    logger.info("Phantom Compliance starting...")

    paths = get_app_paths()
    cfg = load_config()
    is_first_run = args.first_run or not cfg.get("first_run_complete", False) or not user_exists("admin")

    if is_first_run:
        first_run_setup()
    else:
        init_database()
        apply_v2_schema()
        migrate_users_to_v2()

    if args.no_llm:
        logger.info("Running in OFFLINE mode (no LLM)")
        os.environ["PHANTOM_NO_LLM"] = "1"
    else:
        logger.info("LLM integration enabled (http://localhost:8080)")
        try:
            from core.setup import is_model_downloaded
            if is_model_downloaded():
                from core.server_manager import ensure_server_online
                if ensure_server_online():
                    logger.info("LLM server auto-started successfully")
                else:
                    logger.warning("Failed to auto-start LLM server")
        except Exception as e:
            logger.warning(f"Could not auto-start LLM server: {e}")

    observer = start_inbox_watcher()

    stop_event = threading.Event()
    bg_thread = threading.Thread(target=background_worker, args=(stop_event,), daemon=True)
    bg_thread.start()

    if args.backend_only:
        logger.info("Running in backend-only mode (no web UI)")
        print("\n" + "=" * 60)
        print("  Phantom Compliance backend running")
        print("  Inbox watching: active")
        print("  Background queue: active")
        print("  Press Ctrl+C to stop")
        print("=" * 60 + "\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            stop_event.set()
            observer.stop()
        observer.join()
        bg_thread.join(timeout=5)
        logger.info("Shutdown complete.")
        return

    logger.info("Starting Flask web UI...")
    print("\n" + "=" * 60)
    print("  PHANTOM COMPLIANCE")
    print("  Web UI: http://{}:{}".format(args.host, args.port))
    print("  Inbox watching: active")
    print("  Background workers: active")
    print("  Press Ctrl+C to stop")
    print("=" * 60 + "\n")

    try:
        from web.server import start_server
        start_server(host=args.host, port=args.port, debug=False)
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("Shutting down...")
        stop_event.set()
        observer.stop()
        observer.join()
        bg_thread.join(timeout=5)
        logger.info("Shutdown complete.")


if __name__ == "__main__":
    main()
