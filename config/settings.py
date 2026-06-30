import os
import sys
import json
import platform
from pathlib import Path


APP_NAME = "PhantomCompliance"
FALLBACK_DIR = Path.home() / ".phantom_compliance"


def get_app_paths():
    """
    Resolve real Windows paths for the Phantom Compliance application.
    Creates all required directories on first run if they don't exist.

    Windows layout:
      Program Files/PhantomCompliance/  -> executable, model, resources (read-only)
      AppData/Local/PhantomCompliance/  -> database, logs, temp
      AppData/Roaming/PhantomCompliance/ -> config, session

    Linux/Mac dev fallback: ~/.phantom_compliance/
    """
    is_windows = platform.system() == "Windows"

    if is_windows:
        prog_files = Path(os.environ.get("ProgramFiles", "C:\\Program Files"))
        local_app = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        roaming_app = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))

        install_dir = prog_files / APP_NAME
        local_dir = local_app / APP_NAME
        roaming_dir = roaming_app / APP_NAME
    else:
        install_dir = FALLBACK_DIR
        local_dir = FALLBACK_DIR
        roaming_dir = FALLBACK_DIR

    paths = {
        "INSTALL_DIR": install_dir,
        "DATABASE_DIR": local_dir / "database",
        "LOGS_DIR": local_dir / "logs",
        "TEMP_DIR": local_dir / "temp",
        "CONFIG_DIR": roaming_dir,
        "MODELS_DIR": install_dir / "models",
        "RESOURCES_DIR": install_dir / "resources",
        "INBOX_DIR": local_dir / "inbox",
        "DB_PATH": local_dir / "database" / "compliance.db",
        "CHAIN_PATH": local_dir / "database" / "chain.json",
        "LOG_PATH": local_dir / "logs" / "system.log",
        "CONFIG_PATH": roaming_dir / "config.json",
        "SESSION_PATH": roaming_dir / "session.token",
        "SECRET_PATH": roaming_dir / ".jwt_secret",
    }

    for key in ("DATABASE_DIR", "LOGS_DIR", "TEMP_DIR", "CONFIG_DIR", "INBOX_DIR"):
        try:
            paths[key].mkdir(parents=True, exist_ok=True)
        except (PermissionError, OSError):
            fallback = FALLBACK_DIR / key.lower()
            fallback.mkdir(parents=True, exist_ok=True)
            paths[key] = fallback
            if key == "DB_PATH":
                paths["DB_PATH"] = fallback / "compliance.db"
                paths["CHAIN_PATH"] = fallback / "chain.json"
            if key == "LOG_PATH":
                paths["LOG_PATH"] = fallback / "system.log"
            if key == "INBOX_DIR":
                paths["INBOX_DIR"] = fallback

    return paths


def load_config():
    paths = get_app_paths()
    cfg_path = paths["CONFIG_PATH"]
    if cfg_path.exists():
        return json.loads(cfg_path.read_text(encoding="utf-8"))
    return {}


def save_config(cfg: dict):
    paths = get_app_paths()
    cfg_path = paths["CONFIG_PATH"]
    cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def load_jwt_secret(paths: dict) -> str:
    secret_path = paths["SECRET_PATH"]
    if secret_path.exists():
        return secret_path.read_text(encoding="utf-8").strip()
    import secrets
    secret = secrets.token_hex(32)
    try:
        secret_path.write_text(secret, encoding="utf-8")
    except (PermissionError, OSError):
        pass
    return secret
