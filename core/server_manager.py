"""
PHANTOM COMPLIANCE — Llama Server Manager
Subprocess lifecycle management for the local LLM inference server.
Starts llama-server.exe, monitors health, auto-restarts on crash.
"""

import os
import sys
import signal
import time
import json
import logging
import subprocess
import urllib.request
import urllib.error
from pathlib import Path

from config.settings import get_app_paths, load_config

logger = logging.getLogger("phantom_compliance.server_manager")

LLM_HEALTH_URL = "http://localhost:8080/health"
LLM_COMPLETION_URL = "http://localhost:8080/completion"
SERVER_CHECK_INTERVAL = 1
SERVER_MAX_WAIT = 60
MAX_RESTART_ATTEMPTS = 2


def get_server_pid_path() -> Path:
    paths = get_app_paths()
    return paths["TEMP_DIR"] / "server.pid"


def save_pid(pid: int):
    pid_path = get_server_pid_path()
    pid_path.write_text(str(pid))


def read_pid() -> int | None:
    pid_path = get_server_pid_path()
    if pid_path.exists():
        try:
            return int(pid_path.read_text().strip())
        except (ValueError, OSError):
            return None
    return None


def is_pid_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (OSError, PermissionError):
        return False


def is_server_online() -> bool:
    try:
        req = urllib.request.Request(LLM_HEALTH_URL, method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except (urllib.error.URLError, TimeoutError, OSError):
        try:
            req = urllib.request.Request(
                LLM_COMPLETION_URL,
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status == 200
        except (urllib.error.URLError, TimeoutError, OSError):
            return False


def find_llama_server() -> Path | None:
    paths = get_app_paths()
    base = Path(__file__).resolve().parent.parent

    # When running as a PyInstaller EXE, look beside the executable first
    if getattr(sys, 'frozen', False):
        exe_dir = Path(sys.executable).parent
    else:
        exe_dir = base

    candidates = [
        exe_dir / "llama-server.exe",                                        # beside the EXE
        exe_dir / "resources" / "llama-server.exe",                          # resources/ beside EXE
        base / "resources" / "llama-server.exe",                             # dev: source/resources/
        paths["INSTALL_DIR"] / "resources" / "llama-server.exe",
        base / "models" / "text" / "llama-b7996-bin-win-cuda-12.4-x64" / "llama-server.exe",
        paths["INSTALL_DIR"] / "llama-server.exe",
        Path(".") / "resources" / "llama-server.exe",
        Path(".") / "llama-server.exe",
    ]
    for c in candidates:
        if c.exists():
            return c.resolve()
    return None


def start_server() -> bool:
    """Start llama-server.exe as a hidden subprocess. Returns True if online."""
    existing_pid = read_pid()
    if existing_pid and is_pid_running(existing_pid):
        if is_server_online():
            logger.info(f"Server already running (PID {existing_pid})")
            return True
        else:
            logger.warning(f"PID {existing_pid} exists but server not responding")

    llama_exe = find_llama_server()
    if not llama_exe:
        logger.error("llama-server.exe not found in install directory")
        return False

    cfg = load_config()
    model_path = cfg.get("model_path", "")
    if not model_path or not Path(model_path).exists():
        logger.error("Model file not found. Run setup first.")
        return False

    ctx_size = cfg.get("ctx_size", 2048)
    threads = cfg.get("threads", 6)
    args = [
        str(llama_exe),
        "-m", model_path,
        "--port", "8080",
        "--ctx-size", str(ctx_size),
        "-t", str(threads),
        "--host", "127.0.0.1",
        "--mlock",
    ]

    try:
        startupinfo = None
        if os.name == "nt":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        proc = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        save_pid(proc.pid)
        logger.info(f"llama-server started (PID {proc.pid})")

        for _ in range(SERVER_MAX_WAIT):
            if is_server_online():
                logger.info("llama-server is online and responding")
                return True
            time.sleep(SERVER_CHECK_INTERVAL)

        logger.warning("Server started but not responding within timeout")
        return False

    except FileNotFoundError as e:
        logger.error(f"Failed to start llama-server: {e}")
        return False


def stop_server():
    """Terminate the llama-server subprocess."""
    pid = read_pid()
    if pid and is_pid_running(pid):
        try:
            if os.name == "nt":
                os.kill(pid, signal.CTRL_BREAK_EVENT)
            else:
                os.kill(pid, signal.SIGTERM)
            logger.info(f"Sent termination signal to PID {pid}")
            for _ in range(10):
                if not is_pid_running(pid):
                    break
                time.sleep(0.5)
        except (OSError, PermissionError) as e:
            logger.error(f"Failed to stop server: {e}")
    pid_path = get_server_pid_path()
    if pid_path.exists():
        pid_path.unlink()


auto_restart_count = 0


def ensure_server_online() -> bool:
    """Health check loop. Auto-restarts once if crashed."""
    global auto_restart_count

    if is_server_online():
        auto_restart_count = 0
        return True

    if auto_restart_count < MAX_RESTART_ATTEMPTS:
        auto_restart_count += 1
        logger.warning(f"Server offline, restart attempt {auto_restart_count}")
        stop_server()
        time.sleep(2)
        return start_server()

    logger.error("Server crashed and max restart attempts reached")
    return False
