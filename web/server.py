"""
Phantom Compliance - Flask Web Server
Custom UI (no Streamlit). Minimalist white background, black buttons.
Handles auth, all dashboard views, and JSON API endpoints.
"""

import os
import sys
import json
import uuid
import time
import logging
import functools
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import (
    Flask, render_template, request, redirect, url_for,
    session as flask_session, jsonify, send_file
)

from config.settings import get_app_paths, load_jwt_secret, load_config, save_config
from auth.session import create_token, verify_token
from auth.security import (
    check_rate_limit, record_failed_login, reset_login_attempts,
    is_account_locked, get_lockout_remaining_seconds, get_session_timeout_seconds,
)
from auth.credential_manager import store_admin_password, get_admin_password
from p_crypto.blockchain import Blockchain
from utils.database import (
    get_all_circulars, get_all_maps, get_filtered_circulars, get_filtered_maps,
    search_circulars, search_maps, store_circular,
    store_map, assign_map, update_map_evidence,
    validate_map, breach_map, escalate_map,
    get_maps_for_department, get_escalated_maps, get_pending_maps,
)
from utils.db_extensions import (
    apply_v2_schema, migrate_users_to_v2, authenticate_user_v2,
    get_all_users_v2, create_user, get_user_v2, update_user, reset_password,
    get_notifications, get_unread_count, mark_notification_read, mark_all_read,
    create_notification, get_llm_queue_stats, get_audit_logs, audit_log,
    get_config, set_config, get_all_config, enqueue_llm_task,
    get_security_question, verify_security_answer,
    create_reset_token, reset_password_with_token,
    change_own_password, update_security_question, apply_security_columns,
)
from utils.database import get_connection
from utils.dept_mapping import map_department, get_display_name
from utils.pdf_parser import extract_text_from_pdf, extract_circular_metadata
from agents.routing_agent import route_all_pending
from agents.validation_agent import run_validation_cycle
from agents.escalation_agent import escalate_overdue_maps
from agents.ingestion_agent import ingest_single
from utils.backup import create_backup, list_backups, restore_backup
from utils.llm_queue import process_queue, check_llm_health
from utils.retention import run_auto_purge
from core.llm_power_check import check_system_capability, require_llm_warning, get_llm_disclaimer
from auth.rbac import has_permission, is_read_only, check_access, get_effective_role, get_role_label, migrate_old_roles, ensure_new_roles
from auth.signed_logs import log_signed_event, get_signed_logs, verify_signed_logs, ensure_signed_logs_table
from core.time_saved import get_time_saved_metrics, get_weekly_savings, get_benchmark_comparison
from core.agent_viz import get_agent_statuses, record_agent_run, get_agent_flow, ensure_agent_viz_tables
from core.knowledge_graph import build_graph_for_circular, get_graph_for_department, answer_graph_query
from core.cross_regulator import get_supported_regulators, get_regulator_circulars, cross_regulator_impact, ensure_regulator_column
from core.panic_button import generate_inspection_package, get_inspection_package, list_inspection_packages, ensure_panic_table
from core.red_team import find_policy_bypass_vectors, audit_access_controls, simulate_insider_threat
from core.benchmarking import get_benchmarking_data, get_department_benchmarking
from core.predict_next import predict_next_circulars, get_topic_trends
from core.explanations import explain_action, get_map_explanation, get_confidence_level

if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    frontend_dist = Path(sys._MEIPASS) / "frontend" / "dist"
else:
    frontend_dist = Path(__file__).parent.parent / "frontend" / "dist"
static_folder = str(frontend_dist) if frontend_dist.exists() else None

app = Flask(__name__, static_folder=static_folder, static_url_path="")
paths = get_app_paths()
logger = logging.getLogger("phantom_compliance")
# persist secret key so sessions survive restarts
_secret_key_path = paths["CONFIG_DIR"] / "flask_secret.key"
if _secret_key_path.exists():
    app.secret_key = _secret_key_path.read_text().strip()
else:
    app.secret_key = os.urandom(32).hex()
    _secret_key_path.write_text(app.secret_key)
blockchain = Blockchain(paths["CHAIN_PATH"])

# ─── Helpers ────────────────────────────────────────────────

ROLES = ['CCO', 'KYC', 'Payments', 'IT_Security', 'Treasury', 'Credit_Risk', 'Forex']


def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in flask_session:
            if request.path.startswith("/api/"):
                return json_response({"error": "Authentication required", "redirect": "/"}, 401)
            return redirect(url_for("login_page"))
        login_time = flask_session.get("login_time", 0)
        if time.time() - login_time > get_session_timeout_seconds():
            flask_session.clear()
            if request.path.startswith("/api/"):
                return json_response({"error": "Session expired", "redirect": "/"}, 401)
            return redirect(url_for("login_page"))
        flask_session["login_time"] = time.time()
        return f(*args, **kwargs)
    return decorated


def cco_only(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if flask_session.get("role") != "CCO":
            return jsonify({"error": "CCO access required"}), 403
        return f(*args, **kwargs)
    return decorated


def json_response(data, status=200):
    return app.response_class(
        response=json.dumps(data, default=str, indent=2),
        status=status,
        mimetype="application/json",
    )


# ─── First Run ────────────────────────────────────────────────

@app.route("/api/first-run")
def api_first_run():
    from config.settings import load_config
    cfg = load_config()
    is_first = not cfg.get("first_run_complete", False)
    admin_pw = get_admin_password() or cfg.get("admin_password", "")
    return json_response({
        "is_first_run": is_first,
        "admin_password": admin_pw or "",
    })


# ─── Auth Routes ─────────────────────────────────────────────

def _serve_react():
    """Serve the React SPA for all non-API routes."""
    if frontend_dist.exists():
        index_path = frontend_dist / "index.html"
        if index_path.exists():
            return app.response_class(index_path.read_text(encoding="utf-8"), mimetype="text/html")
    return render_template("login.html")

@app.route("/")
def login_page():
    if "user_id" in flask_session:
        return redirect("/dashboard")
    return _serve_react()


@app.route("/login", methods=["POST"])
def login_action():
    data = request.get_json()
    if not data:
        return json_response({"error": "No data"}, 400)

    client_ip = request.remote_addr or "unknown"
    if not check_rate_limit(client_ip):
        return json_response({"error": "Too many requests. Try again later."}, 429)

    username = data.get("username", "").strip()
    if is_account_locked(username):
        remaining = get_lockout_remaining_seconds(username)
        return json_response({"error": f"Account locked. Try again in {remaining} seconds."}, 423)

    user = authenticate_user_v2(username, data.get("password", ""))
    if not user:
        record_failed_login(username)
        attempts_left = max(0, 5 - getattr(record_failed_login, "attempts", 0))
        return json_response({"error": "Invalid credentials"}, 401)

    reset_login_attempts(username)
    flask_session["user_id"] = user["id"]
    flask_session["username"] = user["username"]
    flask_session["role"] = user["role"]
    flask_session["login_time"] = time.time()
    audit_log(user["id"], username, "LOGIN_SUCCESS", "user", user["id"], f"IP: {client_ip}")

    from utils.db_extensions import get_connection as gconn
    conn = gconn()
    conn.execute("UPDATE users_v2 SET last_login = datetime('now') WHERE id = ?", (user["id"],))
    conn.commit(); conn.close()

    return json_response({"ok": True, "role": user["role"]})


@app.route("/logout")
def logout():
    flask_session.clear()
    return redirect(url_for("login_page"))


@app.route("/api/session")
@login_required
def api_session():
    return json_response({
        "username": flask_session["username"],
        "role": flask_session["role"],
        "user_id": flask_session["user_id"],
    })


# ─── SPA: All page routes → React ──────────────────────────

@app.route("/register")
def register_page():
    return _serve_react()

@app.route("/forgot-password")
def forgot_password_page():
    return _serve_react()

@app.route("/account")
@login_required
def account_page():
    return _serve_react()

@app.route("/dashboard")
@login_required
def dashboard():
    return _serve_react()

@app.route("/cco")
@login_required
@cco_only
def cco_page():
    return _serve_react()

@app.route("/department")
@login_required
def dept_page():
    return _serve_react()

@app.route("/audit")
@login_required
def audit_page():
    return _serve_react()

@app.route("/users")
@login_required
def users_page():
    return _serve_react()

@app.route("/health")
@login_required
def health_page():
    return _serve_react()

@app.route("/reports")
@login_required
def reports_page():
    return _serve_react()

@app.route("/compliance-intel")
@login_required
def compliance_intel_page():
    return _serve_react()

@app.route("/impact-simulator")
@login_required
def impact_simulator_page():
    return _serve_react()

@app.route("/copilot")
@login_required
def copilot_page():
    return _serve_react()

@app.route("/heatmap")
@login_required
def heatmap_page():
    return _serve_react()

@app.route("/plans")
@login_required
def plans_page():
    return _serve_react()

@app.route("/security")
@login_required
def security_page():
    return _serve_react()

@app.route("/auditor")
@login_required
def auditor_page():
    return _serve_react()

@app.route("/signed-logs")
@login_required
def signed_logs_page():
    return _serve_react()

@app.route("/knowledge")
@login_required
def knowledge_page():
    return _serve_react()


@app.route("/logs")
@login_required
def logs_page():
    return _serve_react()


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json()
    if not data:
        return json_response({"error": "No data"}, 400)
    username = data.get("username", "").strip()
    password = data.get("password", "")
    confirm = data.get("confirm_password", "")
    display = data.get("display_name", username)
    question = data.get("security_question", "").strip()
    answer = data.get("security_answer", "").strip()
    role = data.get("role", "KYC")

    if not username or len(username) < 3:
        return json_response({"error": "Username must be at least 3 characters"}, 400)
    if not password or len(password) < 6:
        return json_response({"error": "Password must be at least 6 characters"}, 400)
    if password != confirm:
        return json_response({"error": "Passwords do not match"}, 400)
    if question and not answer:
        return json_response({"error": "Please provide a security answer"}, 400)

    conn_check = get_connection()
    existing_row = conn_check.execute("SELECT id FROM users_v2 WHERE username = ?", (username,)).fetchone()
    conn_check.close()
    if existing_row:
        return json_response({"error": "Username already exists"}, 400)

    uid = create_user(
        username=username,
        password=password,
        role=role,
        display_name=display,
        created_by=0,
        security_question=question,
        security_answer=answer,
    )
    create_notification("New User Registered", f"User {username} ({role}) registered",
                        "INFO", role="CCO")
    audit_log(0, username, "USER_REGISTERED", "user", uid, f"Self-registered as {role}")
    return json_response({"ok": True, "user_id": uid})


# ─── Forgot Password ────────────────────────────────────────

@app.route("/api/forgot-password/question", methods=["POST"])
def api_forgot_question():
    data = request.get_json()
    username = data.get("username", "").strip()
    question, user_id = get_security_question(username)
    if not question:
        return json_response({"error": "No security question set for this user, contact admin"}, 404)
    return json_response({"question": question, "username": username, "user_id": user_id})


@app.route("/api/forgot-password/verify", methods=["POST"])
def api_forgot_verify():
    data = request.get_json()
    user_id = data.get("user_id")
    answer = data.get("answer", "")
    if not verify_security_answer(user_id, answer):
        return json_response({"error": "Incorrect answer"}, 401)
    token = create_reset_token(user_id)
    return json_response({"ok": True, "token": token})


@app.route("/api/forgot-password/reset", methods=["POST"])
def api_forgot_reset():
    data = request.get_json()
    token = data.get("token", "")
    new_password = data.get("new_password", "")
    confirm = data.get("confirm_password", "")
    if not new_password or len(new_password) < 6:
        return json_response({"error": "Password must be at least 6 characters"}, 400)
    if new_password != confirm:
        return json_response({"error": "Passwords do not match"}, 400)
    if reset_password_with_token(token, new_password):
        return json_response({"ok": True})
    return json_response({"error": "Invalid or expired reset token"}, 400)


# ─── Account Settings ───────────────────────────────────────

@app.route("/api/account")
@login_required
def api_account():
    user = get_user_v2(flask_session["user_id"])
    if not user:
        return json_response({"error": "User not found"}, 404)
    return json_response({
        "id": user["id"],
        "username": user["username"],
        "display_name": user.get("display_name", ""),
        "role": user["role"],
        "department_code": user.get("department_code", ""),
        "email": user.get("email", ""),
        "security_question": user.get("security_question", ""),
        "created_at": user.get("created_at", ""),
    })


@app.route("/api/account/update", methods=["POST"])
@login_required
def api_account_update():
    data = request.get_json()
    user_id = flask_session["user_id"]
    conn = get_connection()
    fields = []
    vals = []
    for f in ["display_name", "email"]:
        if f in data:
            fields.append(f"{f}=?")
            vals.append(data[f])
    if "security_question" in data and "security_answer" in data:
        fields.append("security_question=?")
        vals.append(data["security_question"])
        if data["security_answer"]:
            from auth.password import hash_password as hp
            fields.append("security_answer_hash=?")
            vals.append(hp(data["security_answer"]).decode("utf-8"))
    if fields:
        vals.append(user_id)
        conn.execute(f"UPDATE users_v2 SET {', '.join(fields)}, updated_at=datetime('now') WHERE id=?", vals)
        conn.commit()
    conn.close()
    return json_response({"ok": True})


@app.route("/api/account/change-password", methods=["POST"])
@login_required
def api_change_password():
    data = request.get_json()
    user_id = flask_session["user_id"]
    old_pw = data.get("old_password", "")
    new_pw = data.get("new_password", "")
    confirm = data.get("confirm_password", "")
    if not old_pw or not new_pw:
        return json_response({"error": "All fields required"}, 400)
    if new_pw != confirm:
        return json_response({"error": "Passwords do not match"}, 400)
    if len(new_pw) < 6:
        return json_response({"error": "Password must be at least 6 characters"}, 400)
    if change_own_password(user_id, old_pw, new_pw):
        create_notification("Password Changed", f"User {flask_session['username']} changed their password",
                            "INFO", user_id=user_id)
        return json_response({"ok": True})
    return json_response({"error": "Current password is incorrect"}, 401)


# ─── API: Dashboard Stats ────────────────────────────────────

@app.route("/api/stats")
@login_required
def api_stats():
    all_circs = get_all_circulars()
    all_maps = get_all_maps()
    chain_valid, chain_errors = blockchain.verify_chain()
    llm_ok = check_llm_health()
    unread = get_unread_count(
        user_id=flask_session["user_id"],
        role=flask_session["role"] if flask_session["role"] == "CCO" else None,
    )
    return json_response({
        "circulars": len(all_circs),
        "maps": len(all_maps),
        "validated": sum(1 for m in all_maps if m["status"] == "VALIDATED"),
        "breached": sum(1 for m in all_maps if m["status"] in ("BREACHED", "ESCALATED")),
        "pending": sum(1 for m in all_maps if m["status"] in ("PENDING", "ASSIGNED")),
        "chain_valid": chain_valid,
        "llm_ok": llm_ok,
        "unread": unread,
        "blocks": len(blockchain.get_chain()),
    })


# ─── API: Circulars ──────────────────────────────────────────

@app.route("/api/circulars")
@login_required
def api_circulars():
    return json_response(get_all_circulars())


@app.route("/api/circulars/<int:cid>", methods=["DELETE"])
@login_required
@cco_only
def api_delete_circular(cid):
    from utils.database import get_connection
    conn = get_connection()
    conn.execute("DELETE FROM maps WHERE circular_id=?", (cid,))
    conn.execute("DELETE FROM circulars WHERE id=?", (cid,))
    conn.commit()
    conn.close()
    blockchain.add_entry("CIRCULAR_DELETED", {"circular_id": cid, "by": flask_session["username"]})
    audit_log(flask_session["user_id"], flask_session["username"], "CIRCULAR_DELETED", "circular", cid, "")
    return json_response({"ok": True})


@app.route("/api/circulars/<int:cid>/body")
@login_required
def api_circular_body(cid):
    from utils.database import get_circular_body
    body = get_circular_body(cid)
    return json_response({"body": body if body else "No text extracted from PDF"})


@app.route("/api/circulars/<int:cid>/analyze", methods=["POST"])
@login_required
@cco_only
def api_circular_analyze(cid):
    from utils.database import get_circular_body, get_connection
    body = get_circular_body(cid)
    if not body:
        return json_response({"error": "No text content to analyze"}, 400)
    import json, re as _re
    clean = _re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', body)
    markers = ['In exercise of the powers', 'These Directions shall be called',
               'Chapter – I  Preliminary', '1. Short title', '2. Applicability']
    body_start = 1000
    for m in markers:
        idx = clean.find(m, 500)
        if 500 < idx < min(len(clean) - 2000, 30000):
            body_start = idx
            break
    truncated = clean[body_start:body_start + 2500] if clean else ""
    raw_text = ""
    try:
        from agents.llm_agent import query_llm
        prompt = f"""Extract key information from this RBI circular text.
Return ONLY valid JSON with these fields:
- circular_number: string
- issue_date: string
- departments: array of strings (affected departments)
- key_regulations: array of {{code: string, description: string}} (regulation codes and what they require)
- compliance_deadline: string or null
- summary: 2-3 sentence summary
- risk_level: "HIGH"/"MEDIUM"/"LOW"

Example:
{{"circular_number": "RBI/2023-24/102", "issue_date": "April 10, 2023", "departments": ["IT_Security"], "key_regulations": [{{"code": "Section 35A", "description": "Banking Regulation Act"}}], "compliance_deadline": "October 1, 2023", "summary": "This circular mandates...", "risk_level": "MEDIUM"}}

CIRCULAR TEXT:
{truncated}"""
        resp = query_llm(prompt, max_tokens=1024)
        raw_full = str(resp)
        if not raw_full:
            return json_response({"ok": False, "error": "LLM returned empty response", "raw_response": ""}, 500)
        # Strip markdown code fences
        cleaned = raw_full.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("\n", 1)[-1]
            cleaned = cleaned.rsplit("```", 1)[0]
            cleaned = cleaned.strip()
        if not cleaned:
            return json_response({"ok": False, "error": "LLM returned empty after stripping fences", "raw_response": raw_full[:2000]}, 500)
        analysis = json.loads(cleaned)
        analysis["_raw_response"] = raw_full[:2000]
        conn = get_connection()
        conn.execute("UPDATE circulars SET analysis=? WHERE id=?", (json.dumps(analysis, ensure_ascii=False), cid))
        conn.commit()
        conn.close()
        return json_response({"ok": True, "analysis": analysis, "raw_response": raw_full[:2000]})
    except json.JSONDecodeError:
        return json_response({"ok": False, "error": "LLM returned invalid JSON", "raw_response": raw_full[:2000]}, 500)
    except Exception as e:
        return json_response({"error": str(e), "raw_response": raw_full[:2000]}, 500)


@app.route("/api/circulars/ingest", methods=["POST"])
@login_required
def api_ingest():
    if "file" not in request.files:
        return json_response({"error": "No file uploaded"}, 400)
    f = request.files["file"]
    if not f.filename.lower().endswith(".pdf"):
        return json_response({"error": "PDF only"}, 400)
    temp_path = paths["TEMP_DIR"] / f.filename
    f.save(str(temp_path))
    cid = ingest_single(str(temp_path), blockchain)
    audit_log(flask_session["user_id"], flask_session["username"],
              "CIRCULAR_UPLOADED", "circular", cid, f"Uploaded {f.filename}")
    create_notification("Circular Ingested", f"Circular #{cid}: {f.filename}",
                        "INFO", role="CCO")
    llm_active = check_llm_health()
    # Enqueue LLM task but don't wait for it — background worker will process it
    try:
        from agents.pipeline import run_post_ingestion_pipeline
        pipeline_result = run_post_ingestion_pipeline(cid, blockchain, source="upload")
    except Exception as e:
        logger.error(f"Circular pipeline failed: {e}", exc_info=True)
        pipeline_result = {"error": str(e)}
    return json_response({
        "ok": True,
        "circular_id": cid,
        "llm_active": llm_active,
        "pipeline": pipeline_result,
    })


@app.route("/api/circulars/<int:cid>/maps-status")
@login_required
def api_circular_maps_status(cid):
    from utils.database import get_connection
    import json
    conn = get_connection()
    llm_row = conn.execute("SELECT status, retry_count, max_retries, error FROM llm_queue WHERE circular_id=? ORDER BY id DESC LIMIT 1", (cid,)).fetchone()
    pending = conn.execute("SELECT COUNT(*) as cnt FROM llm_queue WHERE circular_id=? AND status IN ('PENDING','PROCESSING')", (cid,)).fetchone()["cnt"]
    maps = [dict(r) for r in conn.execute("SELECT id, map_text, map_id_label, assigned_to as department, status, frequency, evidence_required, deadline_date FROM maps WHERE circular_id=?", (cid,)).fetchall()]
    # Get stored analysis with raw LLM response
    analysis_row = conn.execute("SELECT analysis FROM circulars WHERE id=?", (cid,)).fetchone()
    conn.close()
    llm_status = dict(llm_row) if llm_row else {"status": "NOT_QUEUED", "retry_count": 0, "max_retries": 0, "error": None}
    is_busy = llm_status["status"] in ("PENDING", "PROCESSING")
    # Parse analysis if stored
    analysis_data = None
    raw_response = ""
    if analysis_row and analysis_row["analysis"]:
        try:
            analysis_data = json.loads(analysis_row["analysis"])
            raw_response = analysis_data.pop("_raw_response", "") if isinstance(analysis_data, dict) else ""
        except (json.JSONDecodeError, AttributeError):
            raw_response = str(analysis_row["analysis"])[:2000]
    return json_response({
        "llm_busy": is_busy,
        "llm_status": llm_status["status"],
        "llm_retry": llm_status["retry_count"],
        "llm_max_retries": llm_status["max_retries"],
        "llm_error": llm_status["error"] or "",
        "llm_raw_response": raw_response,
        "analysis": analysis_data,
        "maps_count": len(maps),
        "maps": maps,
    })


@app.route("/api/circulars/<int:cid>/summary")
@login_required
def api_circular_summary(cid):
    """Return full circular data with extracted MAPs, analysis summary."""
    from utils.database import get_connection
    conn = get_connection()
    circ = conn.execute("SELECT * FROM circulars WHERE id=?", (cid,)).fetchone()
    if not circ:
        conn.close()
        return json_response({"error": "Not found"}, 404)
    maps = [dict(r) for r in conn.execute("SELECT id, map_text, map_id_label, assigned_to, status, frequency, evidence_required, deadline_date FROM maps WHERE circular_id=?", (cid,)).fetchall()]
    conn.close()
    data = dict(circ)
    if data.get("encrypted_body"):
        try:
            from utils.crypto import decrypt_aes
            data["body"] = decrypt_aes(data["encrypted_body"], data.get("nonce"), data.get("auth_tag"))
        except Exception:
            data["body"] = "[encrypted]"
    data.pop("encrypted_body", None)
    data.pop("nonce", None)
    data.pop("auth_tag", None)
    for k in ("body", "subject_line", "circular_number", "department_code", "issue_date", "addressee"):
        data.setdefault(k, "")
    data["maps"] = maps
    data["maps_count"] = len(maps)
    return json_response(data)


# ─── API: MAPs ───────────────────────────────────────────────

@app.route("/api/circulars/<int:cid>/maps")
@login_required
def api_circular_maps(cid):
    from utils.database import get_connection
    conn = get_connection()
    rows = conn.execute("SELECT * FROM maps WHERE circular_id=?", (cid,)).fetchall()
    conn.close()
    return json_response([dict(r) for r in rows])


@app.route("/api/regulations")
@login_required
def api_regulations():
    from utils.database import get_connection
    conn = get_connection()
    rows = conn.execute("""
        SELECT m.id as map_id, m.circular_id, c.circular_number, c.issue_date,
               c.subject_line, m.map_text, m.assigned_to, m.deadline_date, m.status
        FROM maps m JOIN circulars c ON m.circular_id = c.id
        ORDER BY m.id DESC
    """).fetchall()
    conn.close()
    return json_response([dict(r) for r in rows])


@app.route("/api/maps")
@login_required
def api_maps():
    role = flask_session["role"]
    if role == "CCO":
        return json_response(get_all_maps())
    return json_response(get_maps_for_department(role))


@app.route("/api/maps/reassign", methods=["POST"])
@login_required
@cco_only
def api_maps_reassign():
    """Reassign a MAP to a different department. Admin password required."""
    data = request.get_json()
    map_id = data.get("map_id")
    new_dept = data.get("assigned_to")
    admin_pw = data.get("admin_password", "")
    if not map_id or not new_dept:
        return json_response({"ok": False, "error": "map_id and assigned_to required"}), 400
    # verify admin password
    from utils.database import get_connection
    conn = get_connection()
    pw_row = conn.execute("SELECT password_hash FROM users WHERE role='CCO' LIMIT 1").fetchone()
    if not pw_row:
        conn.close()
        return json_response({"ok": False, "error": "No admin user found"}), 403
    from werkzeug.security import check_password_hash
    if not check_password_hash(pw_row["password_hash"], admin_pw):
        conn.close()
        return json_response({"ok": False, "error": "Invalid admin password"}), 403
    # update the MAP
    conn.execute("UPDATE maps SET assigned_to=? WHERE id=?", (new_dept, map_id))
    conn.commit()
    audit_log(flask_session["username"], f"MAP #{map_id} reassigned to {new_dept}")
    conn.close()
    return json_response({"ok": True})


@app.route("/api/maps/assign", methods=["POST"])
@login_required
@cco_only
def api_maps_assign():
    """Assign a MAP to a department (no password required for CCO)."""
    data = request.get_json()
    map_id = data.get("map_id")
    dept = data.get("assigned_to")
    if not map_id or not dept:
        return json_response({"ok": False, "error": "map_id and assigned_to required"}), 400
    conn = get_connection()
    conn.execute("UPDATE maps SET assigned_to=?, status='ASSIGNED', assigned_by=?, assigned_at=datetime('now') WHERE id=?",
                 (dept, flask_session["username"], map_id))
    conn.commit()
    conn.close()
    blockchain.add_entry("MAP_ASSIGNED", {"map_id": map_id, "to": dept, "by": flask_session["username"]})
    audit_log(flask_session["user_id"], flask_session["username"],
              "MAP_ASSIGNED", "map", map_id, f"Assigned to {dept}")
    create_notification("MAP Assigned", f"MAP #{map_id} assigned to {dept}", "INFO", role=dept)
    return json_response({"ok": True})


@app.route("/api/maps/complete", methods=["POST"])
@login_required
def api_maps_complete():
    """Mark a MAP as completed."""
    data = request.get_json()
    map_id = data.get("map_id")
    if not map_id:
        return json_response({"ok": False, "error": "map_id required"}), 400
    conn = get_connection()
    conn.execute("UPDATE maps SET status='COMPLETED', completed_by=?, completed_at=datetime('now') WHERE id=?",
                 (flask_session["username"], map_id))
    conn.commit()
    conn.close()
    blockchain.add_entry("MAP_COMPLETED", {"map_id": map_id, "by": flask_session["username"]})
    audit_log(flask_session["user_id"], flask_session["username"],
              "MAP_COMPLETED", "map", map_id, "Marked as completed")
    create_notification("MAP Completed", f"MAP #{map_id} marked as completed", "INFO", role="CCO")
    return json_response({"ok": True})


@app.route("/api/maps/reject", methods=["POST"])
@login_required
def api_maps_reject():
    """Reject a MAP with a reason."""
    data = request.get_json()
    map_id = data.get("map_id")
    reason = data.get("reason", "Rejected")
    if not map_id:
        return json_response({"ok": False, "error": "map_id required"}), 400
    conn = get_connection()
    conn.execute("UPDATE maps SET status='REJECTED', rejected_by=?, rejected_reason=? WHERE id=?",
                 (flask_session["username"], reason, map_id))
    conn.commit()
    conn.close()
    blockchain.add_entry("MAP_REJECTED", {"map_id": map_id, "by": flask_session["username"], "reason": reason})
    audit_log(flask_session["user_id"], flask_session["username"],
              "MAP_REJECTED", "map", map_id, f"Rejected: {reason}")
    create_notification("MAP Rejected", f"MAP #{map_id} rejected: {reason}", "WARNING", role="CCO")
    return json_response({"ok": True})


@app.route("/api/maps/evidence", methods=["POST"])
@login_required
def api_submit_evidence():
    data = request.get_json()
    map_id = data.get("map_id")
    evidence = data.get("evidence_text", "")
    if not map_id or not evidence:
        return json_response({"error": "Missing map_id or evidence_text"}, 400)
    update_map_evidence(int(map_id), evidence)
    audit_log(flask_session["user_id"], flask_session["username"],
              "EVIDENCE_SUBMITTED", "map", int(map_id), evidence[:100])
    blockchain.add_entry("EVIDENCE_SUBMITTED", {
        "map_id": map_id, "by": flask_session["username"]
    })
    create_notification("Evidence Submitted", f"MAP #{map_id} evidence submitted",
                        "INFO", role="CCO")
    return json_response({"ok": True})


# ─── API: Agents ─────────────────────────────────────────────

@app.route("/api/agents/route", methods=["POST"])
@login_required
@cco_only
def api_route():
    from agents.sql_fallback_generator import generate_maps_sql_fallback
    from utils.database import _get_master_key
    try:
        mk = _get_master_key()
        gen = generate_maps_sql_fallback(mk)
    except Exception:
        gen = {"generated": 0}
    count = route_all_pending(blockchain)
    audit_log(flask_session["user_id"], flask_session["username"],
              "AGENT_ROUTE", None, 0, f"Routed {count} MAPs")
    return json_response({"routed": count})


@app.route("/api/maps/generate-fallback", methods=["POST"])
@login_required
@cco_only
def api_generate_maps_fallback():
    from utils.database import get_connection
    conn = get_connection()
    circs = [r["id"] for r in conn.execute("SELECT id FROM circulars ORDER BY id").fetchall()]
    conn.close()
    queued = 0
    for cid in circs:
        conn2 = get_connection()
        existing = conn2.execute("SELECT COUNT(*) as cnt FROM maps WHERE circular_id=?", (cid,)).fetchone()["cnt"]
        conn2.close()
        if existing == 0:
            enqueue_llm_task(cid, "GENERATE_MAPS", {"circular_id": cid, "source": "manual"})
            queued += 1
    if check_llm_health():
        process_queue()
    audit_log(flask_session["user_id"], flask_session["username"],
              "MAPS_QUEUED_LLM", None, 0, f"Queued {queued} circulars for LLM MAP generation")
    return json_response({"generated": 0, "queued": queued})


@app.route("/api/agents/validate", methods=["POST"])
@login_required
@cco_only
def api_validate():
    result = run_validation_cycle(blockchain)
    audit_log(flask_session["user_id"], flask_session["username"],
              "AGENT_VALIDATE", None, 0, str(result))
    return json_response(result)


@app.route("/api/agents/escalate", methods=["POST"])
@login_required
@cco_only
def api_escalate():
    esc = escalate_overdue_maps(blockchain)
    audit_log(flask_session["user_id"], flask_session["username"],
              "AGENT_ESCALATE", None, 0, f"Escalated {len(esc)} MAPs")
    return json_response({"escalated": len(esc), "ids": esc})


@app.route("/api/agents/generate-maps", methods=["POST"])
@login_required
@cco_only
def api_generate_maps():
    data = request.get_json()
    circular_id = data.get("circular_id")
    if not circular_id:
        return json_response({"error": "circular_id required"}, 400)
    from agents.llm_agent import generate_maps as gen_maps
    from utils.database import _get_master_key
    mk = _get_master_key()
    maps = gen_maps(int(circular_id), mk)
    if maps:
        blockchain.add_entry("MAPS_GENERATED", {"circular_id": circular_id, "count": len(maps)})
    audit_log(flask_session["user_id"], flask_session["username"],
              "MAPS_GENERATED", "circular", int(circular_id), f"Generated {len(maps)} MAPs")
    return json_response({"maps": maps})


# ─── API: Search / Filter / Historical Data ─────────────────

@app.route("/api/search/circulars")
@login_required
def api_search_circulars():
    q = request.args.get("q", "")
    page = int(request.args.get("page", 1))
    dept = request.args.get("dept", "")
    rows, total = get_filtered_circulars(search=q, dept=dept, page=page)
    return json_response({"rows": rows, "total": total, "page": page})


@app.route("/api/search/maps")
@login_required
def api_search_maps():
    q = request.args.get("q", "")
    status = request.args.get("status", "")
    page = int(request.args.get("page", 1))
    dept = request.args.get("dept", "")
    rows, total = get_filtered_maps(search=q, status=status, dept=dept, page=page)
    return json_response({"rows": rows, "total": total, "page": page})


@app.route("/api/audit-log/search")
@login_required
def api_audit_log_search():
    q = request.args.get("q", "").strip()
    limit = int(request.args.get("limit", 100))
    conn = get_connection()
    if q:
        rows = conn.execute(
            """SELECT * FROM audit_log
               WHERE username LIKE ? OR action LIKE ? OR details LIKE ?
               ORDER BY created_at DESC LIMIT ?""",
            [f"%{q}%", f"%{q}%", f"%{q}%", limit],
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return json_response([dict(r) for r in rows])


@app.route("/api/stats/history")
@login_required
def api_stats_history():
    conn = get_connection()
    circs = conn.execute("SELECT date(ingested_at) as d, count(*) as c FROM circulars GROUP BY d ORDER BY d DESC LIMIT 30").fetchall()
    maps = conn.execute("SELECT status, count(*) as c FROM maps GROUP BY status").fetchall()
    users = conn.execute("SELECT count(*) FROM users_v2").fetchone()[0]
    conn.close()
    return json_response({
        "circulars_by_day": [dict(r) for r in circs],
        "maps_by_status": [dict(r) for r in maps],
        "total_users": users,
    })


# ─── API: Blockchain ─────────────────────────────────────────

@app.route("/api/chain")
@login_required
def api_chain():
    return json_response(blockchain.get_chain())


@app.route("/api/chain/verify")
@login_required
def api_verify_chain():
    valid, errors = blockchain.verify_chain()
    return json_response({"valid": valid, "errors": errors, "count": len(blockchain.get_chain())})


@app.route("/api/chain/corrupt", methods=["POST"])
@login_required
@cco_only
def api_corrupt():
    data = request.get_json()
    index = data.get("index", 1)
    field = data.get("field", "action")
    value = data.get("value", "TAMPERED")
    blockchain.corrupt_block(int(index), field, value)
    valid, errors = blockchain.verify_chain()
    blockchain.corrupt_block(int(index), field, blockchain.get_chain()[int(index)][field])
    blockchain._chain = blockchain.get_chain()
    return json_response({"tamper_detected": not valid, "errors": errors})


# ─── API: Users ──────────────────────────────────────────────

@app.route("/api/users")
@login_required
@cco_only
def api_users():
    return json_response(get_all_users_v2())


@app.route("/api/users/create", methods=["POST"])
@login_required
@cco_only
def api_create_user():
    data = request.get_json()
    uid = create_user(
        username=data["username"],
        password=data["password"],
        role=data["role"],
        display_name=data.get("display_name", data["username"]),
        department_code=data.get("department_code", ""),
        created_by=flask_session["user_id"],
    )
    audit_log(flask_session["user_id"], flask_session["username"],
              "USER_CREATED", "user", uid, f"Created {data['username']}")
    create_notification("User Created", f"User {data['username']} ({data['role']}) created",
                        "INFO", role="CCO")
    return json_response({"ok": True, "user_id": uid})


@app.route("/api/users/update", methods=["POST"])
@login_required
@cco_only
def api_update_user():
    data = request.get_json()
    update_user(int(data["user_id"]),
                display_name=data.get("display_name"),
                role=data.get("role"),
                department_code=data.get("department_code"),
                is_active=data.get("is_active"))
    return json_response({"ok": True})


@app.route("/api/users/reset-password", methods=["POST"])
@login_required
@cco_only
def api_reset_password():
    data = request.get_json()
    reset_password(int(data["user_id"]), data["new_password"])
    return json_response({"ok": True})


# ─── API: Notifications ──────────────────────────────────────

@app.route("/api/notifications")
@login_required
def api_notifications():
    role = flask_session["role"]
    uid = flask_session["user_id"]
    return json_response(get_notifications(
        user_id=uid,
        role=role if role == "CCO" else None,
    ))


@app.route("/api/notifications/unread")
@login_required
def api_unread():
    role = flask_session["role"]
    uid = flask_session["user_id"]
    return json_response({
        "count": get_unread_count(user_id=uid, role=role if role == "CCO" else None)
    })


@app.route("/api/notifications/read/<int:nid>", methods=["POST"])
@login_required
def api_read_notification(nid):
    mark_notification_read(nid)
    return json_response({"ok": True})


@app.route("/api/notifications/read-all", methods=["POST"])
@login_required
def api_read_all():
    role = flask_session["role"]
    uid = flask_session["user_id"]
    mark_all_read(user_id=uid, role=role if role == "CCO" else None)
    return json_response({"ok": True})


# ─── API: Health ─────────────────────────────────────────────

@app.route("/api/health")
@login_required
def api_health():
    llm_ok = check_llm_health()
    chain_valid, chain_errs = blockchain.verify_chain()
    db_path = paths["DB_PATH"]
    db_size = db_path.stat().st_size if db_path.exists() else 0
    queue_stats = get_llm_queue_stats()
    backups = list_backups()
    return json_response({
        "llm_status": "ONLINE" if llm_ok else "OFFLINE",
        "llm": llm_ok,
        "chain_valid": chain_valid,
        "chain_errors": chain_errs,
        "db_size": db_size,
        "queue": queue_stats,
        "queue_pending": queue_stats.get("pending", 0),
        "queue_processing": queue_stats.get("processing", 0),
        "backups": len(backups),
        "unread": get_unread_count(user_id=flask_session["user_id"],
                                    role=flask_session["role"] if flask_session["role"] == "CCO" else None),
    })


@app.route("/api/backup/create", methods=["POST"])
@login_required
@cco_only
def api_create_backup():
    bp = create_backup()
    return json_response({"ok": True, "name": bp.name})


@app.route("/api/backups")
@login_required
def api_backups():
    return json_response(list_backups())


@app.route("/api/backup/restore", methods=["POST"])
@login_required
@cco_only
def api_restore_backup():
    data = request.get_json()
    path = data.get("path", "")
    ok = restore_backup(Path(path))
    return json_response({"ok": ok})


# ─── API: Reports ────────────────────────────────────────────

@app.route("/api/reports/data")
@login_required
def api_report_data():
    maps = get_all_maps()
    dept_map = {}
    for m in maps:
        dept = m.get("assigned_to", "Unassigned") or "Unassigned"
        if dept not in dept_map:
            dept_map[dept] = {"total": 0, "validated": 0, "breached": 0, "pending": 0, "escalated": 0}
        dept_map[dept]["total"] += 1
        s = m.get("status", "PENDING")
        if s == "VALIDATED":
            dept_map[dept]["validated"] += 1
        elif s == "BREACHED":
            dept_map[dept]["breached"] += 1
        elif s == "ESCALATED":
            dept_map[dept]["escalated"] += 1
        else:
            dept_map[dept]["pending"] += 1
    rows = []
    for dept, stats in sorted(dept_map.items()):
        rate = f"{stats['validated'] / stats['total'] * 100:.0f}" if stats["total"] > 0 else "0"
        rows.append({
            "department": get_display_name(dept),
            "total": stats["total"],
            "validated": stats["validated"],
            "pending": stats["pending"],
            "breached": stats["breached"],
            "escalated": stats["escalated"],
            "compliance_rate": rate,
        })
    return json_response(rows)


# ─── API: Audit Log ──────────────────────────────────────────

@app.route("/api/audit-log")
@login_required
def api_audit_log():
    return json_response(get_audit_logs(limit=200))


@app.route("/api/logs")
@login_required
def api_logs():
    """Return last N lines from the system log file."""
    paths = get_app_paths()
    log_path = paths.get("LOG_PATH")
    if not log_path or not log_path.exists():
        return json_response({"lines": [], "error": None})
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
        lines = text.strip().splitlines()
        return json_response({"lines": lines[-200:]})
    except Exception as e:
        return json_response({"lines": [], "error": str(e)})


# ─── API: Config ─────────────────────────────────────────────

@app.route("/api/config")
@login_required
@cco_only
def api_config():
    return json_response(get_all_config())


@app.route("/api/config/update", methods=["POST"])
@login_required
@cco_only
def api_update_config():
    data = request.get_json()
    for k, v in data.items():
        set_config(k, str(v))
    return json_response({"ok": True})


# ═══════════════════════════════════════════════════════════════
# FEATURE: Risk Score Engine
# ═══════════════════════════════════════════════════════════════

@app.route("/api/risk/score")
@login_required
def api_risk_score():
    from agents.risk_scorer import calculate_bank_score, get_score_history, ensure_score_history_table
    ensure_score_history_table()
    score = calculate_bank_score()
    history = get_score_history(days=30)
    return json_response({"current": score, "history": history})


@app.route("/api/risk/department/<department>")
@login_required
def api_risk_department(department):
    from agents.risk_scorer import get_department_score
    return json_response(get_department_score(department))


# ═══════════════════════════════════════════════════════════════
# FEATURE: RBI Inspection Report
# ═══════════════════════════════════════════════════════════════

@app.route("/api/reports/generate", methods=["POST"])
@login_required
@cco_only
def api_generate_report():
    data = request.get_json()
    start_date = data.get("start_date", "")
    end_date = data.get("end_date", "")
    password = data.get("password", "inspection2024")
    if not start_date or not end_date:
        return json_response({"error": "start_date and end_date required"}, 400)
    from agents.report_generator import generate_report
    result = generate_report(start_date, end_date, password)
    return json_response(result)


@app.route("/api/reports/list")
@login_required
def api_reports_list():
    from pathlib import Path
    reports_dir = paths["DATABASE_DIR"] / "reports"
    files = []
    if reports_dir.exists():
        for f in sorted(reports_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
            if f.suffix == ".pbc":
                files.append({"name": f.name, "size": f.stat().st_size, "modified": f.stat().st_mtime})
    return json_response(files)


# ═══════════════════════════════════════════════════════════════
# FEATURE: Deadline Intelligence & Reminders
# ═══════════════════════════════════════════════════════════════

@app.route("/api/reminders")
@login_required
def api_reminders():
    from agents.deadline_parser import get_reminders_for_department
    role = flask_session["role"]
    reminders = get_reminders_for_department(role)
    return json_response(reminders)


@app.route("/api/reminders/check", methods=["POST"])
@login_required
@cco_only
def api_check_reminders():
    from agents.deadline_parser import check_reminders
    result = check_reminders()
    return json_response(result)


# ═══════════════════════════════════════════════════════════════
# FEATURE: Acknowledgement System
# ═══════════════════════════════════════════════════════════════

@app.route("/api/acknowledge/<int:map_id>", methods=["POST"])
@login_required
def api_acknowledge_map(map_id):
    from agents.acknowledgement_agent import acknowledge_map
    data = request.get_json()
    password = data.get("password", "")
    uid = flask_session["user_id"]
    username = flask_session["username"]
    result = acknowledge_map(map_id, uid, username, password, blockchain)
    return json_response(result)


@app.route("/api/acknowledge/status")
@login_required
def api_acknowledgement_status():
    from agents.acknowledgement_agent import get_unacknowledged_count, get_oldest_unacknowledged
    role = flask_session["role"]
    count = get_unacknowledged_count(role)
    oldest = get_oldest_unacknowledged(role)
    return json_response({"unacknowledged": count["unacknowledged"], "oldest": oldest})


# ═══════════════════════════════════════════════════════════════
# FEATURE: Circular Conflict Detector
# ═══════════════════════════════════════════════════════════════

@app.route("/api/conflicts")
@login_required
def api_conflicts():
    from agents.conflict_detector import get_all_conflicts
    resolved = request.args.get("resolved")
    if resolved is not None:
        resolved = resolved.lower() == "true"
    return json_response(get_all_conflicts(resolved))


@app.route("/api/conflicts/detect/<int:circular_id>", methods=["POST"])
@login_required
@cco_only
def api_detect_conflicts(circular_id):
    from agents.conflict_detector import detect_conflicts
    result = detect_conflicts(circular_id, blockchain)
    try:
        from core.agent_viz import record_agent_run
        record_agent_run("Conflict Detector", "COMPLETED", tasks_processed=len(result.get("conflicts", [])))
    except Exception:
        pass
    return json_response(result)


@app.route("/api/conflicts/resolve/<int:conflict_id>", methods=["POST"])
@login_required
@cco_only
def api_resolve_conflict(conflict_id):
    from agents.conflict_detector import resolve_conflict
    data = request.get_json()
    resolution = data.get("resolution", "Resolved by CCO")
    result = resolve_conflict(conflict_id, resolution, flask_session["user_id"],
                               flask_session["username"], blockchain)
    return json_response(result)


# ═══════════════════════════════════════════════════════════════
# FEATURE: Llama Server Management
# ═══════════════════════════════════════════════════════════════

@app.route("/api/server/status")
@login_required
def api_server_status():
    from core.server_manager import is_server_online, read_pid, is_pid_running
    pid = read_pid()
    return json_response({
        "online": is_server_online(),
        "pid": pid,
        "pid_running": is_pid_running(pid) if pid else False,
    })


@app.route("/api/server/stop", methods=["POST"])
@login_required
@cco_only
def api_stop_server():
    from core.server_manager import stop_server
    stop_server()
    return json_response({"ok": True, "online": False})


@app.route("/api/server/restart", methods=["POST"])
@login_required
@cco_only
def api_restart_server():
    try:
        from core.server_manager import start_server, stop_server, find_llama_server
        if not find_llama_server():
            return json_response({"ok": False, "online": False, "error": "llama-server.exe not found in install directory"})
        stop_server()
        import time; time.sleep(2)
        ok = start_server()
        if ok:
            try:
                process_queue()
            except Exception:
                pass
            return json_response({"ok": True, "online": True})
        return json_response({"ok": False, "online": False, "error": "Server process started but not responding within timeout"})
    except Exception as e:
        logger.exception("Failed to restart LLM server")
        return json_response({"ok": False, "online": False, "error": str(e)})


@app.route("/api/llm/flush-queue", methods=["POST"])
@login_required
@cco_only
def api_llm_flush_queue():
    """Process all pending LLM queue tasks now."""
    try:
        if not check_llm_health():
            return json_response({"ok": False, "error": "LLM server not online"})
        result = process_queue()
        return json_response({"ok": True, "processed": result.get("processed", 0), "failed": result.get("failed", 0)})
    except Exception as e:
        return json_response({"ok": False, "error": str(e)})


# ═══════════════════════════════════════════════════════════════
# FEATURE: Model Download (LLM)

_model_download = {"in_progress": False, "progress": 0, "total": 0, "error": None, "done": False, "phase": "idle"}
_model_download_lock = __import__('threading').Lock()

@app.route("/api/model/status")
@login_required
def api_model_status():
    from core.setup import get_model_path, is_model_downloaded, MODEL_FILENAME
    model_path = get_model_path()
    size = model_path.stat().st_size if model_path.exists() else 0
    size_mb = size / (1024 * 1024) if size else 0
    return json_response({
        "exists": model_path.exists(),
        "downloaded": is_model_downloaded(),
        "path": str(model_path),
        "filename": model_path.name,
        "size": size,
        "size_mb": round(size_mb, 1),
        "valid_size": size_mb >= 500,
        "download": {**_model_download},
    })


@app.route("/api/model/download", methods=["POST"])
@login_required
@cco_only
def api_model_download():
    global _model_download
    with _model_download_lock:
        if _model_download["in_progress"]:
            return json_response({"error": "Download already in progress"}, 400)
        _model_download = {"in_progress": True, "progress": 0, "total": 0, "error": None, "done": False, "phase": "downloading"}

    def _download_worker():
        global _model_download
        import urllib.request
        from core.setup import get_model_path, MODEL_FILENAME
        model_url = "https://huggingface.co/bartowski/Llama-3.2-3B-Instruct-GGUF/resolve/main/" + MODEL_FILENAME
        model_path = get_model_path()
        model_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            req = urllib.request.Request(model_url, headers={"User-Agent": "PhantomCompliance/1.0"})
            with urllib.request.urlopen(req, timeout=3600) as resp:
                total = int(resp.headers.get("content-length", 0))
                with _model_download_lock:
                    _model_download["total"] = total
                downloaded = 0
                chunk_size = 1024 * 1024  # 1MB
                with open(model_path, "wb") as f:
                    while True:
                        chunk = resp.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)
                        with _model_download_lock:
                            _model_download["progress"] = downloaded
            from core.setup import run_first_run_setup
            run_first_run_setup()
            # Turn on: start llama-server
            with _model_download_lock:
                _model_download["phase"] = "turning_on"
            from core.server_manager import start_server
            server_started = start_server()
            with _model_download_lock:
                _model_download["done"] = True
                _model_download["in_progress"] = False
                _model_download["phase"] = "online" if server_started else "error"
                if not server_started:
                    _model_download["error"] = "Model downloaded but LLM server failed to start"
        except Exception as e:
            with _model_download_lock:
                _model_download["error"] = str(e)
                _model_download["in_progress"] = False
                _model_download["phase"] = "error"
            if model_path.exists():
                model_path.unlink()

    import threading
    t = threading.Thread(target=_download_worker, daemon=True)
    t.start()
    return json_response({"ok": True, "message": "Download started"})


# ═══════════════════════════════════════════════════════════════
# FEATURE: Enhanced RBAC & Auditor Mode
# ═══════════════════════════════════════════════════════════════

@app.route("/api/rbac/roles")
@login_required
@cco_only
def api_rbac_roles():
    from auth.rbac import ROLES
    return json_response({k: {"label": v["label"], "rank": v["rank"], "permissions": v["permissions"],
                               "read_only": v.get("read_only", False)} for k, v in ROLES.items()})


@app.route("/api/rbac/my-permissions")
@login_required
def api_rbac_my_permissions():
    role = flask_session.get("role", "")
    from auth.rbac import ROLES
    role_config = ROLES.get(role, ROLES["DEPARTMENT_USER"])
    return json_response({
        "role": role,
        "label": get_role_label(role),
        "permissions": role_config.get("permissions", []),
        "read_only": role_config.get("read_only", False),
    })


@app.route("/api/rbac/upgrade-roles", methods=["POST"])
@login_required
@cco_only
def api_rbac_upgrade():
    migrate_old_roles()
    ensure_new_roles()
    return json_response({"ok": True, "message": "Roles migrated to new RBAC system"})


# ═══════════════════════════════════════════════════════════════
# FEATURE: Signed Audit Logs (Tamper-Evidence)
# ═══════════════════════════════════════════════════════════════

@app.route("/api/signed-logs")
@login_required
def api_signed_logs():
    ensure_signed_logs_table()
    return json_response(get_signed_logs())


@app.route("/api/signed-logs/verify")
@login_required
def api_signed_logs_verify():
    ensure_signed_logs_table()
    return json_response(verify_signed_logs())


@app.route("/api/signed-logs/event", methods=["POST"])
@login_required
def api_signed_log_event():
    ensure_signed_logs_table()
    data = request.get_json()
    event = log_signed_event(
        event_type=data.get("event_type", "MANUAL"),
        user=flask_session["username"],
        details=data.get("details", {}),
        entity_type=data.get("entity_type", ""),
        entity_id=data.get("entity_id", 0),
    )
    return json_response(event)


# ═══════════════════════════════════════════════════════════════
# FEATURE: Tamper Detection
# ═══════════════════════════════════════════════════════════════

@app.route("/api/security/verify-integrity")
@login_required
@cco_only
def api_security_integrity():
    from core.tamper_detection import verify_integrity
    return json_response(verify_integrity())


@app.route("/api/security/rebaseline", methods=["POST"])
@login_required
@cco_only
def api_security_rebaseline():
    from core.tamper_detection import record_new_baseline
    count = record_new_baseline()
    return json_response({"ok": True, "files": count})


# ═══════════════════════════════════════════════════════════════
# FEATURE: File Sandbox & Folder Allowlisting
# ═══════════════════════════════════════════════════════════════

@app.route("/api/security/sandbox/check", methods=["POST"])
@login_required
@cco_only
def api_sandbox_check():
    from core.file_sandbox import sandbox_ingestion
    data = request.get_json()
    filepath = data.get("filepath", "")
    expected_hash = data.get("expected_hash", "")
    if not filepath:
        return json_response({"error": "filepath required"}, 400)
    result = sandbox_ingestion(filepath, expected_hash)
    return json_response(result)


@app.route("/api/security/allowed-folders")
@login_required
def api_allowed_folders():
    from core.file_sandbox import get_allowed_folder_paths, ALLOWED_FOLDERS
    folders = get_allowed_folder_paths()
    return json_response({
        "allowed_folders": ALLOWED_FOLDERS,
        "resolved_paths": [str(f) for f in folders],
    })


# ═══════════════════════════════════════════════════════════════
# FEATURE: Data Protector (Hidden Encrypted Backups)
# ═══════════════════════════════════════════════════════════════

@app.route("/api/security/protect-db", methods=["POST"])
@login_required
@cco_only
def api_protect_db():
    from core.data_protector import protect_database
    result = protect_database()
    return json_response(result)


@app.route("/api/security/protect-config", methods=["POST"])
@login_required
@cco_only
def api_protect_config():
    from core.data_protector import protect_config
    return json_response(protect_config())


@app.route("/api/security/backup-info")
@login_required
@cco_only
def api_backup_info():
    from core.data_protector import get_hidden_backup_info
    return json_response(get_hidden_backup_info())


# ═══════════════════════════════════════════════════════════════
# FEATURE: Disaster Recovery
# ═══════════════════════════════════════════════════════════════

@app.route("/api/disaster/create", methods=["POST"])
@login_required
@cco_only
def api_disaster_create():
    from core.disaster_recovery import create_disaster_recovery_package
    result = create_disaster_recovery_package()
    return json_response(result)


@app.route("/api/disaster/packages")
@login_required
@cco_only
def api_disaster_packages():
    from core.disaster_recovery import list_dr_packages
    return json_response(list_dr_packages())


@app.route("/api/disaster/verify", methods=["POST"])
@login_required
@cco_only
def api_disaster_verify():
    from core.disaster_recovery import verify_dr_package
    data = request.get_json()
    path = data.get("path", "")
    return json_response(verify_dr_package(path))


# ═══════════════════════════════════════════════════════════════
# FEATURE: Knowledge Assistant
# ═══════════════════════════════════════════════════════════════

@app.route("/api/knowledge/query", methods=["POST"])
@login_required
def api_knowledge_query():
    from agents.knowledge_assistant import query, store_knowledge_query, ensure_assistant_tables, seed_default_rules
    ensure_assistant_tables()
    seed_default_rules()
    data = request.get_json()
    q = data.get("query", "")
    result = query(q)
    store_knowledge_query(q, result.get("answer", ""), result.get("total_found", 0))
    return json_response(result)


@app.route("/api/knowledge/ask", methods=["POST"])
@login_required
def api_knowledge_ask():
    from agents.knowledge_assistant import get_answer, store_knowledge_query, ensure_assistant_tables
    from agents.llm_agent import query_llm
    ensure_assistant_tables()
    data = request.get_json()
    q = data.get("question", "")
    use_llm = data.get("use_llm", False)
    if use_llm:
        try:
            llm_prompt = f"Answer this compliance question concisely based on regulatory knowledge:\n\nQuestion: {q}\n\nAnswer:"
            llm_answer = query_llm(llm_prompt, max_tokens=256)
            if llm_answer:
                store_knowledge_query(q, llm_answer, 1)
                return json_response({"answer": llm_answer, "source": "llm"})
        except Exception:
            pass
    answer = get_answer(q)
    store_knowledge_query(q, answer, 1)
    return json_response({"answer": answer})


# ═══════════════════════════════════════════════════════════════
# FEATURE: AI Governance
# ═══════════════════════════════════════════════════════════════

@app.route("/api/governance/validate-output", methods=["POST"])
@login_required
@cco_only
def api_governance_validate():
    from agents.ai_governance import validate_llm_output, audit_llm_usage, ensure_governance_tables
    ensure_governance_tables()
    data = request.get_json()
    text = data.get("text", "")
    context = data.get("context", "")
    action = data.get("action", "manual_check")
    result = validate_llm_output(text, context)
    audit_llm_usage(action, flask_session["username"], context, text)
    return json_response(result)


@app.route("/api/governance/check-breach", methods=["POST"])
@login_required
def api_governance_breach():
    from agents.ai_governance import check_compliance_breach
    data = request.get_json()
    result = check_compliance_breach(
        data.get("entity_type", ""),
        data.get("entity_id", 0),
        data.get("details", {}),
    )
    return json_response(result)


# ═══════════════════════════════════════════════════════════════
# FEATURE: Evidence Validator (Rule-Based)
# ═══════════════════════════════════════════════════════════════

@app.route("/api/evidence/validate", methods=["POST"])
@login_required
def api_evidence_validate():
    from agents.evidence_validator import validate_evidence
    data = request.get_json()
    map_id = data.get("map_id")
    if not map_id:
        return json_response({"error": "map_id required"}, 400)
    result = validate_evidence(int(map_id), data.get("evidence_data", {}))
    return json_response(result)


@app.route("/api/evidence/templates")
@login_required
def api_evidence_templates():
    from agents.evidence_validator import get_evidence_templates
    return json_response(get_evidence_templates())


# ═══════════════════════════════════════════════════════════════
# FEATURE: Policy Drift Detector
# ═══════════════════════════════════════════════════════════════

@app.route("/api/policy/drift", methods=["POST"])
@login_required
@cco_only
def api_policy_drift():
    from agents.policy_drift import detect_policy_drift
    data = request.get_json()
    result = detect_policy_drift(
        data.get("policy_text", ""),
        data.get("circular_id", 0),
    )
    return json_response(result)


@app.route("/api/policy/supersession", methods=["POST"])
@login_required
@cco_only
def api_policy_supersession():
    from agents.policy_drift import track_supersession, ensure_policy_tables
    ensure_policy_tables()
    data = request.get_json()
    result = track_supersession(
        int(data["old_circular_id"]),
        int(data["new_circular_id"]),
        data.get("relationship", "supersedes"),
    )
    return json_response(result)


@app.route("/api/policy/supersession/<int:circular_id>")
@login_required
def api_policy_supersession_chain(circular_id):
    from agents.policy_drift import get_supersession_chain, ensure_policy_tables
    ensure_policy_tables()
    return json_response(get_supersession_chain(circular_id))


# ═══════════════════════════════════════════════════════════════
# FEATURE: Compliance Checker
# ═══════════════════════════════════════════════════════════════

@app.route("/api/compliance/check")
@login_required
def api_compliance_check():
    from agents.compliance_checker import run_full_compliance_check
    result = run_full_compliance_check()
    return json_response(result)


@app.route("/api/compliance/department/<dept_code>")
@login_required
def api_compliance_department(dept_code):
    from agents.compliance_checker import get_department_compliance
    return json_response(get_department_compliance(dept_code.upper()))


# ═══════════════════════════════════════════════════════════════
# FEATURE: Local Search
# ═══════════════════════════════════════════════════════════════

@app.route("/api/search/local", methods=["POST"])
@login_required
def api_search_local():
    from core.local_search import search_all, rebuild_search_index
    data = request.get_json()
    q = data.get("query", "")
    if not q.strip():
        return json_response({"error": "Query required"}, 400)
    rebuild_search_index()
    results = search_all(q)
    return json_response(results)


@app.route("/api/search/rebuild-index", methods=["POST"])
@login_required
@cco_only
def api_search_rebuild():
    from core.local_search import rebuild_search_index
    rebuild_search_index()
    return json_response({"ok": True})


# ═══════════════════════════════════════════════════════════════
# FEATURE: Daily Compliance Snapshot
# ═══════════════════════════════════════════════════════════════

@app.route("/api/snapshot/generate", methods=["POST"])
@login_required
@cco_only
def api_snapshot_generate():
    from agents.compliance_checker import run_full_compliance_check
    result = run_full_compliance_check()
    result["snapshot_time"] = __import__("datetime").datetime.now().isoformat()
    # Store snapshot
    conn = get_connection()
    conn.execute(
        "INSERT INTO daily_snapshots (snapshot_data) VALUES (?)",
        (json.dumps(result, default=str),),
    )
    conn.commit()
    conn.close()
    return json_response(result)


@app.route("/api/snapshot/history")
@login_required
def api_snapshot_history():
    ensure_snapshot_table()
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM daily_snapshots ORDER BY created_at DESC LIMIT 30"
    ).fetchall()
    conn.close()
    return json_response([dict(r) for r in rows])


def ensure_snapshot_table():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS daily_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_data TEXT DEFAULT '{}',
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    conn.close()


# ═══════════════════════════════════════════════════════════════
# FEATURE: LLM Power Warning & System Check
# ═══════════════════════════════════════════════════════════════

@app.route("/api/system/check")
@login_required
def api_system_check():
    return json_response(require_llm_warning())


@app.route("/api/system/disclaimer")
@login_required
def api_system_disclaimer():
    return json_response({"disclaimer": get_llm_disclaimer()})


# ═══════════════════════════════════════════════════════════════
# FEATURE: Regulatory Impact Simulator
# ═══════════════════════════════════════════════════════════════

@app.route("/api/impact/simulate/<int:circular_id>", methods=["POST"])
@login_required
@cco_only
def api_impact_simulate(circular_id):
    from agents.impact_simulator import simulate_impact, ensure_impact_table
    ensure_impact_table()
    data = request.get_json() or {}
    ignore_days = data.get("ignore_days", 90)
    result = simulate_impact(circular_id, ignore_days, blockchain)
    return json_response(result)


@app.route("/api/impact/history/<int:circular_id>")
@login_required
def api_impact_history(circular_id):
    from agents.impact_simulator import get_impact_history, ensure_impact_table
    ensure_impact_table()
    return json_response(get_impact_history(circular_id))


# ═══════════════════════════════════════════════════════════════
# FEATURE: Explainable AI
# ═══════════════════════════════════════════════════════════════

@app.route("/api/explain/<action_type>")
@login_required
def api_explain(action_type):
    data = request.args.to_dict()
    return json_response(explain_action(action_type, data))


@app.route("/api/explain/map/<int:map_id>/<int:circular_id>")
@login_required
def api_explain_map(map_id, circular_id):
    return json_response(get_map_explanation(map_id, circular_id))


@app.route("/api/explain/confidence")
@login_required
def api_explain_confidence():
    action = request.args.get("action", "")
    return json_response({"confidence": get_confidence_level(action, {})})


# ═══════════════════════════════════════════════════════════════
# FEATURE: Compliance Heatmap
# ═══════════════════════════════════════════════════════════════

@app.route("/api/heatmap")
@login_required
def api_heatmap():
    from agents.risk_scorer import calculate_bank_score
    score = calculate_bank_score()
    dept_list = score.get("departments", [])
    dept_by_code = {d["department"]: d for d in dept_list}
    heatmap = []
    dept_names = {
        "KYC": "KYC/AML", "Payments": "Payments/DPSS", "IT_Security": "Cybersecurity",
        "Treasury": "Treasury", "Forex": "Forex", "Credit_Risk": "Credit Risk",
    }
    from utils.database import get_connection
    for dept, name in dept_names.items():
        ds = dept_by_code.get(dept, {})
        s = ds.get("score", 50) if isinstance(ds, dict) else 50
        total = ds.get("total_maps", 0) if isinstance(ds, dict) else 0
        validated = ds.get("validated", 0)
        pending = ds.get("pending", 0)
        overdue = ds.get("overdue", 0)
        penalties = ds.get("penalties", [])
        typ = ds.get("display_name", name)
        # fetch detailed MAPs for this department
        conn = get_connection()
        rows = conn.execute(
            """SELECT m.id, m.circular_id, m.map_text, m.assigned_to, m.deadline_date, m.status, c.circular_number, c.subject_line
               FROM maps m JOIN circulars c ON m.circular_id = c.id
               WHERE m.assigned_to = ? ORDER BY m.deadline_date""",
            (dept,),
        ).fetchall()
        conn.close()
        maps = []
        for r in rows:
            maps.append({
                "id": r["id"],
                "circular_id": r["circular_id"],
                "map_text": r["map_text"],
                "circular_number": r["circular_number"],
                "subject_line": r["subject_line"],
                "deadline_date": r["deadline_date"],
                "status": r["status"],
            })
        if s >= 80:
            status = "COMPLIANT"
            color = "#4caf50"
        elif s >= 50:
            status = "AT_RISK"
            color = "#ff9800"
        else:
            status = "CRITICAL"
            color = "#f44336"
        heatmap.append({"department": typ, "code": dept, "score": round(s, 1), "status": status, "color": color, "maps_total": total, "validated": validated, "pending": pending, "overdue": overdue, "penalties": penalties, "maps": maps})
    bank_score = score.get("bank_score", 0)
    bank_status = "COMPLIANT" if bank_score >= 80 else "AT_RISK" if bank_score >= 50 else "CRITICAL"
    return json_response({"departments": heatmap, "bank_score": round(bank_score, 1), "bank_status": bank_status})


# ═══════════════════════════════════════════════════════════════
# FEATURE: What Changed? Engine
# ═══════════════════════════════════════════════════════════════

@app.route("/api/what-changed/detect", methods=["POST"])
@login_required
@cco_only
def api_what_changed():
    from agents.what_changed import detect_changes, ensure_changes_table
    ensure_changes_table()
    data = request.get_json()
    old_id = data.get("old_circular_id")
    new_id = data.get("new_circular_id")
    if not old_id or not new_id:
        return json_response({"error": "old_circular_id and new_circular_id required"}, 400)
    result = detect_changes(int(old_id), int(new_id), blockchain)
    return json_response(result)


@app.route("/api/what-changed/diff/<int:old_id>/<int:new_id>")
@login_required
def api_what_changed_diff(old_id, new_id):
    from agents.what_changed import generate_diff_html
    html = generate_diff_html(old_id, new_id)
    return json_response({"html": html})


@app.route("/api/what-changed/for/<int:circular_id>")
@login_required
def api_what_changed_for(circular_id):
    from agents.what_changed import get_changes_for_circular
    return json_response(get_changes_for_circular(circular_id))


# ═══════════════════════════════════════════════════════════════
# FEATURE: Implementation Plan Generator
# ═══════════════════════════════════════════════════════════════

@app.route("/api/plans/generate/<int:map_id>", methods=["POST"])
@login_required
@cco_only
def api_generate_plan(map_id):
    from agents.implementation_planner import generate_plan, ensure_plans_table
    ensure_plans_table()
    result = generate_plan(map_id, blockchain)
    return json_response(result)


@app.route("/api/plans/<int:map_id>")
@login_required
def api_get_plan(map_id):
    from agents.implementation_planner import get_plan, ensure_plans_table
    ensure_plans_table()
    plan = get_plan(map_id)
    if not plan:
        return json_response({"error": "No plan found"}, 404)
    return json_response(plan)


@app.route("/api/plans/update-progress/<int:plan_id>", methods=["POST"])
@login_required
def api_update_plan_progress(plan_id):
    from agents.implementation_planner import update_plan_progress
    data = request.get_json()
    step_num = data.get("step_number")
    status = data.get("status", "completed")
    if not step_num:
        return json_response({"error": "step_number required"}, 400)
    result = update_plan_progress(plan_id, int(step_num), status)
    return json_response(result)


# ═══════════════════════════════════════════════════════════════
# FEATURE: Compliance Copilot
# ═══════════════════════════════════════════════════════════════

@app.route("/api/copilot/query", methods=["POST"])
@login_required
def api_copilot_query():
    from agents.copilot import query_compliance, ensure_copilot_tables
    ensure_copilot_tables()
    data = request.get_json()
    q = data.get("query", "")
    role = flask_session.get("role", "CCO")
    dept = flask_session.get("department_code", "")
    use_llm = data.get("use_llm", False)
    result = query_compliance(q, role, dept, use_llm=use_llm)
    return json_response(result)


@app.route("/api/copilot/suggestions")
@login_required
def api_copilot_suggestions():
    from agents.copilot import get_suggestions
    q = request.args.get("q", "")
    return json_response({"suggestions": get_suggestions(q)})


@app.route("/api/copilot/actions")
@login_required
def api_copilot_actions():
    from agents.copilot import get_all_actions
    return json_response(get_all_actions())


# ═══════════════════════════════════════════════════════════════
# FEATURE: Predict Future Violations
# ═══════════════════════════════════════════════════════════════

@app.route("/api/predict/violations")
@login_required
def api_predict_violations():
    from agents.predictor import predict_violation_risk
    try:
        result = predict_violation_risk()
        return json_response(result)
    except Exception as e:
        logger.error(f"Predict violations error: {e}")
        return json_response({
            "risk_score": 50, "confidence": "LOW",
            "message": "Error computing predictions",
            "next_violation_probability": 0, "trend": "STABLE",
            "departments": [], "error": str(e),
        })


@app.route("/api/predict/impact/<int:circular_id>")
@login_required
def api_predict_impact(circular_id):
    from agents.predictor import predict_circular_impact
    return json_response(predict_circular_impact(circular_id))


@app.route("/api/predict/accuracy")
@login_required
def api_predict_accuracy():
    from agents.predictor import get_prediction_model_accuracy
    return json_response(get_prediction_model_accuracy())


# ═══════════════════════════════════════════════════════════════
# FEATURE: Executive Panic Button
# ═══════════════════════════════════════════════════════════════

@app.route("/api/panic/generate", methods=["POST"])
@login_required
@cco_only
def api_panic_generate():
    ensure_panic_table()
    uid = flask_session["user_id"]
    uname = flask_session["username"]
    result = generate_inspection_package(uid, uname, blockchain)
    return json_response(result)


@app.route("/api/panic/package/<int:package_id>")
@login_required
def api_panic_package(package_id):
    pkg = get_inspection_package(package_id)
    if not pkg:
        return json_response({"error": "Package not found"}, 404)
    return json_response(pkg)


@app.route("/api/panic/packages")
@login_required
def api_panic_packages():
    return json_response(list_inspection_packages())


# ═══════════════════════════════════════════════════════════════
# FEATURE: Time Saved Metrics
# ═══════════════════════════════════════════════════════════════

@app.route("/api/metrics/time-saved")
@login_required
def api_time_saved():
    return json_response(get_time_saved_metrics())


@app.route("/api/metrics/weekly-savings")
@login_required
def api_weekly_savings():
    return json_response(get_weekly_savings())


@app.route("/api/metrics/benchmark-comparison")
@login_required
def api_benchmark_comparison():
    return json_response(get_benchmark_comparison())


# ═══════════════════════════════════════════════════════════════
# FEATURE: Multi-Agent Collaboration Visualization
# ═══════════════════════════════════════════════════════════════

@app.route("/api/agents/status")
@login_required
def api_agent_status():
    ensure_agent_viz_tables()
    return json_response(get_agent_statuses())


@app.route("/api/agents/flow")
@login_required
def api_agent_flow():
    ensure_agent_viz_tables()
    return json_response(get_agent_flow())


# ═══════════════════════════════════════════════════════════════
# FEATURE: Compliance Knowledge Graph
# ═══════════════════════════════════════════════════════════════

@app.route("/api/graph/circular/<int:circular_id>")
@login_required
def api_graph_circular(circular_id):
    return json_response(build_graph_for_circular(circular_id))


@app.route("/api/graph/department/<dept_code>")
@login_required
def api_graph_department(dept_code):
    return json_response(get_graph_for_department(dept_code))


@app.route("/api/graph/query", methods=["POST"])
@login_required
def api_graph_query():
    data = request.get_json()
    q = data.get("query", "")
    return json_response(answer_graph_query(q))


# ═══════════════════════════════════════════════════════════════
# FEATURE: Cross-Regulator Support
# ═══════════════════════════════════════════════════════════════

@app.route("/api/regulators")
@login_required
def api_regulators():
    ensure_regulator_column()
    return json_response(get_supported_regulators())


@app.route("/api/regulators/<regulator_code>/circulars")
@login_required
def api_regulator_circulars(regulator_code):
    return json_response(get_regulator_circulars(regulator_code.upper()))


@app.route("/api/regulators/impact/<int:circular_id>")
@login_required
def api_regulator_impact(circular_id):
    return json_response(cross_regulator_impact(circular_id))


# ═══════════════════════════════════════════════════════════════
# FEATURE: Auto-Draft Compliance Evidence
# ═══════════════════════════════════════════════════════════════

@app.route("/api/draft/evidence/<int:map_id>", methods=["POST"])
@login_required
def api_draft_evidence(map_id):
    from agents.evidence_drafter import draft_evidence
    return json_response(draft_evidence(map_id))


# ═══════════════════════════════════════════════════════════════
# FEATURE: Internal AI Red Team
# ═══════════════════════════════════════════════════════════════

@app.route("/api/redteam/audit")
@login_required
@cco_only
def api_redteam_audit():
    return json_response(audit_access_controls())


@app.route("/api/redteam/bypass", methods=["POST"])
@login_required
@cco_only
def api_redteam_bypass():
    data = request.get_json()
    text = data.get("policy_text", "")
    return json_response(find_policy_bypass_vectors(text))


@app.route("/api/redteam/simulate", methods=["POST"])
@login_required
@cco_only
def api_redteam_simulate():
    data = request.get_json()
    scenario = data.get("scenario", "")
    return json_response(simulate_insider_threat(scenario))


# ═══════════════════════════════════════════════════════════════
# FEATURE: Industry Benchmarking
# ═══════════════════════════════════════════════════════════════

@app.route("/api/benchmarking")
@login_required
def api_benchmarking():
    return json_response(get_benchmarking_data())


@app.route("/api/benchmarking/department/<dept_code>")
@login_required
def api_benchmarking_dept(dept_code):
    return json_response(get_department_benchmarking(dept_code.upper()))


# ═══════════════════════════════════════════════════════════════
# FEATURE: Predict Next Circulars
# ═══════════════════════════════════════════════════════════════

@app.route("/api/predict/next-circulars")
@login_required
def api_predict_next():
    return json_response(predict_next_circulars())


@app.route("/api/predict/topics")
@login_required
def api_predict_topics():
    return json_response(get_topic_trends())


# ═══════════════════════════════════════════════════════════════
# FEATURE: Export / Import
# ═══════════════════════════════════════════════════════════════

@app.route("/api/export/data", methods=["POST"])
@login_required
def api_export_data():
    """Export all data (circulars, MAPs, users, blockchain) as JSON package. All roles can export."""
    from utils.database import get_connection
    conn = get_connection()
    circs = [dict(r) for r in conn.execute("SELECT * FROM circulars ORDER BY id").fetchall()]
    maps = [dict(r) for r in conn.execute("SELECT * FROM maps ORDER BY id").fetchall()]
    users = [dict(r) for r in conn.execute("SELECT id, username, display_name, role, department_code, is_active FROM users ORDER BY id").fetchall()]
    changes = [dict(r) for r in conn.execute("SELECT * FROM what_changed ORDER BY id").fetchall()]
    conflicts = [dict(r) for r in conn.execute("SELECT * FROM conflicts ORDER BY id").fetchall()]
    conn.close()
    # include blockchain
    bc_entries = []
    try:
        if blockchain and hasattr(blockchain, "chain"):
            bc_entries = blockchain.chain
    except Exception:
        pass
    package = {
        "exported_at": datetime.now().isoformat(),
        "version": "1.0",
        "circulars": [{k: (str(v) if isinstance(v, bytes) else v) for k, v in c.items()} for c in circs],
        "maps": [{k: (str(v) if isinstance(v, bytes) else v) for k, v in m.items()} for m in maps],
        "users": users,
        "what_changed": [{k: (str(v) if isinstance(v, bytes) else v) for k, v in c.items()} for c in changes],
        "conflicts": [{k: (str(v) if isinstance(v, bytes) else v) for k, v in c.items()} for c in conflicts],
        "blockchain": bc_entries,
    }
    return json_response(package)


@app.route("/api/import/data", methods=["POST"])
@login_required
def api_import_data():
    """Import data package from export. Merges into existing database. All roles can import."""
    from utils.database import get_connection
    pkg = request.get_json()
    if not pkg or not isinstance(pkg, dict):
        return json_response({"ok": False, "error": "Invalid package"}), 400
    conn = get_connection()
    imported = {"circulars": 0, "maps": 0, "users": 0}
    try:
        for c in pkg.get("circulars", []):
            conn.execute(
                """INSERT OR IGNORE INTO circulars
                   (id, circular_number, subject_line, department_code, issue_date, body, ingested_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (c.get("id"), c.get("circular_number"), c.get("subject_line"),
                 c.get("department_code"), c.get("issue_date"), c.get("body"), c.get("ingested_at"))
            )
            if conn.total_changes:
                imported["circulars"] += 1
        for m in pkg.get("maps", []):
            conn.execute(
                """INSERT OR IGNORE INTO maps
                   (id, circular_id, map_text, assigned_to, deadline_date, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (m.get("id"), m.get("circular_id"), m.get("map_text"),
                 m.get("assigned_to"), m.get("deadline_date"), m.get("status"), m.get("created_at"))
            )
            if conn.total_changes:
                imported["maps"] += 1
        for u in pkg.get("users", []):
            conn.execute(
                """INSERT OR IGNORE INTO users
                   (id, username, display_name, role, department_code, is_active)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (u.get("id"), u.get("username"), u.get("display_name"),
                 u.get("role"), u.get("department_code"), u.get("is_active", 1))
            )
            if conn.total_changes:
                imported["users"] += 1
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        logger.exception("Import failed")
        return json_response({"ok": False, "error": str(e)}), 500
    conn.close()
    # log import
    _log_import(flask_session["username"], imported)
    return json_response({"ok": True, "imported": imported})


def _log_import(username, imported):
    """Log an import event to the import_log table."""
    try:
        conn = get_connection()
        conn.execute("""CREATE TABLE IF NOT EXISTS import_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            imported_at TEXT DEFAULT (datetime('now')),
            circulars INTEGER DEFAULT 0,
            maps INTEGER DEFAULT 0,
            users INTEGER DEFAULT 0
        )""")
        conn.execute(
            "INSERT INTO import_log (username, circulars, maps, users) VALUES (?, ?, ?, ?)",
            (username, imported.get("circulars", 0), imported.get("maps", 0), imported.get("users", 0))
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("Failed to log import: %s", e)


@app.route("/api/import/log", methods=["GET"])
@login_required
def api_import_log():
    """Return import history."""
    from utils.database import get_connection
    conn = get_connection()
    conn.execute("""CREATE TABLE IF NOT EXISTS import_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        imported_at TEXT DEFAULT (datetime('now')),
        circulars INTEGER DEFAULT 0,
        maps INTEGER DEFAULT 0,
        users INTEGER DEFAULT 0
    )""")
    rows = conn.execute("SELECT * FROM import_log ORDER BY id DESC LIMIT 50").fetchall()
    conn.close()
    return json_response([dict(r) for r in rows])


@app.route("/api/export/users", methods=["POST"])
@login_required
def api_export_users():
    """Export users from users_v2 (has display_name, is_active, password_hash). All roles can export."""
    from utils.database import get_connection
    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT id, username, display_name, role, department_code,
                      is_active, password_hash, created_at
               FROM users_v2 ORDER BY id"""
        ).fetchall()
        users = [dict(r) for r in rows]
    except Exception as e:
        conn.close()
        logger.error(f"Export users failed querying users_v2: {e}")
        return json_response({"ok": False, "error": f"Export failed: {e}"}), 500
    conn.close()
    return json_response({"exported_at": datetime.now().isoformat(), "users": users})


@app.route("/api/import/users", methods=["POST"])
@login_required
def api_import_users():
    """Import users into users_v2 (and keep legacy users table in sync). All roles can import."""
    from utils.database import get_connection
    pkg = request.get_json()
    if not pkg or not isinstance(pkg, dict):
        return json_response({"ok": False, "error": "Invalid package"}), 400
    conn = get_connection()
    imported = 0
    try:
        for u in pkg.get("users", []):
            # Primary insert into users_v2
            conn.execute(
                """INSERT OR REPLACE INTO users_v2
                   (id, username, display_name, role, department_code,
                    is_active, password_hash, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    u.get("id"), u.get("username"),
                    u.get("display_name") or u.get("username"),
                    u.get("role"), u.get("department_code"),
                    u.get("is_active", 1),
                    u.get("password_hash", ""),
                    u.get("created_at"),
                )
            )
            # Keep legacy users table in sync (best-effort)
            try:
                conn.execute(
                    """INSERT OR REPLACE INTO users
                       (id, username, role, department_code, password_hash, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        u.get("id"), u.get("username"),
                        u.get("role"), u.get("department_code"),
                        u.get("password_hash", ""), u.get("created_at"),
                    )
                )
            except Exception:
                pass
            imported += 1
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        logger.exception("User import failed")
        return json_response({"ok": False, "error": str(e)}), 500
    conn.close()
    return json_response({"ok": True, "imported": imported})


# ─── Auto-Start LLM Server ────────────────────────────────────

_llm_auto_started = False

def _ensure_llm_server():
    """Auto-start the LLM server if model and binary exist and server is offline."""
    global _llm_auto_started
    if _llm_auto_started:
        return
    _llm_auto_started = True
    try:
        if check_llm_health():
            return
        from core.server_manager import start_server as start_llm, find_llama_server
        from core.setup import is_model_downloaded
        if find_llama_server() and is_model_downloaded():
            logger.info("Auto-starting LLM server...")
            started = start_llm()
            if started:
                logger.info("LLM server auto-started successfully")
            else:
                logger.warning("LLM server auto-start failed")
    except Exception as e:
        logger.warning(f"LLM auto-start error: {e}")


# ─── Background LLM Queue Processor ──────────────────────────

def _llm_queue_worker():
    """Background thread that processes pending LLM tasks every 30s."""
    import time as _time
    logger = logging.getLogger("phantom_compliance.llm_worker")
    _time.sleep(10)  # give server time to start
    while True:
        try:
            if check_llm_health():
                result = process_queue()
                if result["processed"] or result["failed"]:
                    logger.info(f"LLM queue processed: {result}")
        except Exception as exc:
            logger.warning(f"LLM queue worker error: {exc}")
        _time.sleep(30)


def start_llm_worker():
    import threading
    t = threading.Thread(target=_llm_queue_worker, daemon=True)
    t.start()


# ─── Start ───────────────────────────────────────────────────

def start_server(host="127.0.0.1", port=5000, debug=False):
    apply_v2_schema()
    migrate_users_to_v2()
    _ensure_llm_server()
    start_llm_worker()
    try:
        if check_llm_health():
            process_queue()
    except Exception:
        pass
    print(f"  Phantom Compliance Web UI: http://{host}:{port}")
    print(f"  Login with your admin credentials")
    app.run(host=host, port=port, debug=debug)


# Module-level startup — runs on import (flask run, main.py, launcher.py)
import threading as _thr
_thr.Thread(target=lambda: (apply_v2_schema(), migrate_users_to_v2(), _ensure_llm_server(), start_llm_worker()), daemon=True).start()

if __name__ == "__main__":
    start_server(debug=True)
