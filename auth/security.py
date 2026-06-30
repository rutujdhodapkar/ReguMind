"""
Enhanced Security Module
- Rate limiting per IP
- Account lockout after N failed attempts
- Session timeout configuration
- IP tracking in audit logs
"""

import time
import logging
import threading
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger("phantom_compliance.security")

_lock = threading.Lock()

# Rate limiting: IP -> list of timestamps
_rate_limit: dict[str, list[float]] = defaultdict(list)

# Account lockout: username -> {attempts, locked_until}
_login_attempts: dict[str, dict] = defaultdict(lambda: {"attempts": 0, "locked_until": 0})

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 30
SESSION_TIMEOUT_HOURS = 8


def check_rate_limit(ip: str) -> bool:
    now = time.time()
    with _lock:
        _rate_limit[ip] = [t for t in _rate_limit[ip] if now - t < RATE_LIMIT_WINDOW]
        if len(_rate_limit[ip]) >= RATE_LIMIT_MAX:
            logger.warning(f"Rate limit exceeded for IP: {ip}")
            return False
        _rate_limit[ip].append(now)
    return True


def record_failed_login(username: str):
    with _lock:
        record = _login_attempts[username]
        record["attempts"] += 1
        if record["attempts"] >= MAX_LOGIN_ATTEMPTS:
            record["locked_until"] = time.time() + (LOCKOUT_DURATION_MINUTES * 60)
            logger.warning(f"Account locked: {username} for {LOCKOUT_DURATION_MINUTES} minutes")


def reset_login_attempts(username: str):
    with _lock:
        if username in _login_attempts:
            del _login_attempts[username]


def is_account_locked(username: str) -> bool:
    with _lock:
        record = _login_attempts.get(username)
        if record and record["locked_until"] > time.time():
            return True
        if record and record["locked_until"] > 0 and record["locked_until"] <= time.time():
            del _login_attempts[username]
        return False


def get_lockout_remaining_seconds(username: str) -> int:
    with _lock:
        record = _login_attempts.get(username)
        if record and record["locked_until"] > time.time():
            return int(record["locked_until"] - time.time())
    return 0


def get_session_timeout_seconds() -> int:
    return SESSION_TIMEOUT_HOURS * 3600
