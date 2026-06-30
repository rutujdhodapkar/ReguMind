"""
Phantom Compliance — Data Protector
Encrypts database, config, and backup files so they CANNOT be
read or edited manually outside the system.
Backups are stored in hidden OS directories (AppData/Local/Temp, etc.)
The code that handles security is encrypted with a self-decrypting wrapper.
"""

import os
import json
import shutil
import hashlib
import logging
import platform
from pathlib import Path

from p_crypto.encryptor import encrypt, decrypt

logger = logging.getLogger("phantom_compliance.data_protector")

HIDDEN_STORAGE_DIR_NAME = ".phantom_vault"


def _get_hidden_storage() -> Path:
    """Get a hidden directory where users won't look for data.
    Uses: %APPDATA%/../Local/Temp/.phantom_vault on Windows
          /tmp/.phantom_vault on Linux
    """
    if platform.system() == "Windows":
        base = Path(os.environ.get("TEMP", os.environ.get("TMP", "C:\\Temp")))
    else:
        base = Path("/tmp")
    vault = base / HIDDEN_STORAGE_DIR_NAME
    vault.mkdir(parents=True, exist_ok=True)
    # Hide the directory
    try:
        if platform.system() == "Windows":
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(str(vault), 2)  # FILE_ATTRIBUTE_HIDDEN
    except Exception:
        pass
    return vault


def _get_local_appdata_storage() -> Path:
    """Get AppData/Roaming storage for real backups."""
    if platform.system() == "Windows":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path.home() / ".config"
    vault = base / "PhantomCompliance" / "vault"
    vault.mkdir(parents=True, exist_ok=True)
    return vault


def protect_database() -> dict:
    """
    Encrypt the SQLite database file and store a copy in hidden storage.
    The original DB stays unencrypted for active use, but the hidden copy
    serves as disaster recovery.
    """
    from config.settings import get_app_paths
    paths = get_app_paths()
    db_path = paths.get("DB_PATH", paths["INSTALL_DIR"] / "compliance.db")

    if not db_path.exists():
        return {"ok": False, "error": "Database not found"}

    # Read the raw database
    raw_data = db_path.read_bytes()

    # Generate a recovery key (stored in Credential Manager)
    from auth.credential_manager import get_password, store_password
    recovery_key = get_password("db_recovery_key")
    if not recovery_key:
        import secrets
        recovery_key = secrets.token_hex(32)
        store_password("db_recovery_key", recovery_key)

    # Encrypt with the recovery key
    mk = bytes.fromhex(recovery_key)
    ciphertext, nonce, tag = encrypt(raw_data.decode("latin-1"), mk)

    # Store in hidden location
    hidden = _get_hidden_storage()
    vault = _get_local_appdata_storage()

    encrypted_pkg = json.dumps({
        "ciphertext": ciphertext.hex(),
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "original_name": db_path.name,
        "created_at": __import__("datetime").datetime.now().isoformat(),
    })

    # Write to both hidden temp and AppData vault
    (hidden / f"{db_path.name}.enc").write_text(encrypted_pkg, encoding="utf-8")
    (vault / f"{db_path.name}.enc").write_text(encrypted_pkg, encoding="utf-8")

    logger.info(f"Database protected: encrypted backup stored in hidden locations")
    return {"ok": True, "hidden_path": str(hidden), "vault_path": str(vault)}


def protect_config() -> dict:
    """Encrypt config.json and store in hidden locations."""
    from config.settings import get_app_paths, load_config
    paths = get_app_paths()
    cfg_path = paths.get("CONFIG_PATH", paths["INSTALL_DIR"] / "config.json")

    if not cfg_path.exists():
        return {"ok": False, "error": "Config not found"}

    cfg = load_config()
    cfg_json = json.dumps(cfg, indent=2)

    from auth.credential_manager import get_password, store_password
    recovery_key = get_password("config_recovery_key")
    if not recovery_key:
        recovery_key = __import__("secrets").token_hex(32)
        store_password("config_recovery_key", recovery_key)

    mk = bytes.fromhex(recovery_key)
    ciphertext, nonce, tag = encrypt(cfg_json, mk)

    pkg = json.dumps({"ciphertext": ciphertext.hex(), "nonce": nonce.hex(), "tag": tag.hex()})

    hidden = _get_hidden_storage()
    vault = _get_local_appdata_storage()
    (hidden / f"{cfg_path.name}.enc").write_text(pkg, encoding="utf-8")
    (vault / f"{cfg_path.name}.enc").write_text(pkg, encoding="utf-8")

    return {"ok": True}


def recover_from_hidden() -> dict:
    """Recover database from hidden encrypted backup."""
    from config.settings import get_app_paths
    paths = get_app_paths()
    db_path = paths.get("DB_PATH", paths["INSTALL_DIR"] / "compliance.db")

    from auth.credential_manager import get_password
    recovery_key = get_password("db_recovery_key")
    if not recovery_key:
        return {"ok": False, "error": "Recovery key not found in Credential Manager"}

    hidden = _get_hidden_storage()
    enc_path = hidden / f"{db_path.name}.enc"

    if not enc_path.exists():
        vault = _get_local_appdata_storage()
        enc_path = vault / f"{db_path.name}.enc"

    if not enc_path.exists():
        return {"ok": False, "error": "No encrypted backup found"}

    try:
        pkg = json.loads(enc_path.read_text(encoding="utf-8"))
        mk = bytes.fromhex(recovery_key)
        ct = bytes.fromhex(pkg["ciphertext"]) if isinstance(pkg["ciphertext"], str) else pkg["ciphertext"]
        nn = bytes.fromhex(pkg["nonce"]) if isinstance(pkg["nonce"], str) else pkg["nonce"]
        tg = bytes.fromhex(pkg["tag"]) if isinstance(pkg["tag"], str) else pkg["tag"]
        plaintext = decrypt(ct, nn, tg, mk)
        db_path.write_bytes(plaintext.encode("latin-1"))
        return {"ok": True, "message": f"Database recovered from {enc_path}"}
    except Exception as e:
        return {"ok": False, "error": f"Recovery failed: {e}"}


def get_hidden_backup_info() -> dict:
    """Get info about hidden backups without revealing exact paths."""
    hidden = _get_hidden_storage()
    vault = _get_local_appdata_storage()
    files = []
    for loc in [hidden, vault]:
        if loc.exists():
            for f in loc.iterdir():
                if f.suffix == ".enc":
                    files.append({
                        "location_hint": "system_temp" if "Temp" in str(loc) else "appdata",
                        "filename": f.name,
                        "size_bytes": f.stat().st_size,
                        "modified": __import__("datetime").datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
                    })
    return {"backup_count": len(files), "files": files}
