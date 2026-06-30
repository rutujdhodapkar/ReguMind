"""
Backup & Restore module for Phantom Compliance.
Creates encrypted .zip archives of the entire database + blockchain + config.
Restore validates checksum before applying.
"""

import json
import os
import zipfile
import hashlib
import shutil
import logging
from datetime import datetime
from pathlib import Path
from io import BytesIO

from config.settings import get_app_paths
from p_crypto.encryptor import encrypt_bytes, decrypt_bytes
from utils.db_extensions import log_backup, create_notification

logger = logging.getLogger("phantom_compliance.backup")


def _get_master_key(paths: dict) -> bytes:
    """Retrieve or prompt for backup encryption key."""
    key_file = paths["CONFIG_DIR"] / ".backup_key"
    if key_file.exists():
        return key_file.read_bytes()
    import secrets
    key = secrets.token_bytes(32)
    key_file.write_bytes(key)
    return key


def create_backup() -> Path:
    """
    Create an encrypted backup of the system.
    Returns path to the backup file.
    """
    paths = get_app_paths()
    backup_dir = paths["DATABASE_DIR"] / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = backup_dir / f"phantom_backup_{timestamp}.pbc"
    mk = _get_master_key(paths)

    mem_zip = BytesIO()
    with zipfile.ZipFile(mem_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        if paths["DB_PATH"].exists():
            zf.write(str(paths["DB_PATH"]), "compliance.db")
        if paths["CHAIN_PATH"].exists():
            zf.write(str(paths["CHAIN_PATH"]), "chain.json")
        if paths["CONFIG_PATH"].exists():
            zf.write(str(paths["CONFIG_PATH"]), "config.json")

    zip_data = mem_zip.getvalue()
    checksum = hashlib.sha256(zip_data).hexdigest()
    ciphertext, nonce, tag = encrypt_bytes(zip_data, mk)

    header = json.dumps({
        "version": 2,
        "timestamp": timestamp,
        "checksum": checksum,
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "files": ["compliance.db", "chain.json", "config.json"],
    }).encode("utf-8") + b"\n"

    backup_path.write_bytes(header + ciphertext)
    size = backup_path.stat().st_size

    log_backup(str(backup_path), size, checksum)
    create_notification(
        title="Backup Created",
        message=f"System backup completed: {backup_path.name} ({size / 1024:.1f} KB)",
        ntype="BACKUP",
        role="CCO",
    )
    logger.info(f"Backup created: {backup_path} ({size / 1024:.1f} KB)")
    return backup_path


def list_backups() -> list[dict]:
    """List all available backups."""
    paths = get_app_paths()
    backup_dir = paths["DATABASE_DIR"] / "backups"
    if not backup_dir.exists():
        return []
    backups = []
    for f in sorted(backup_dir.glob("*.pbc"), reverse=True):
        backups.append({
            "name": f.name,
            "size": f.stat().st_size,
            "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
            "path": str(f),
        })
    return backups


def restore_backup(backup_path: Path) -> bool:
    """
    Restore system from a backup file.
    Validates checksum and decrypts before applying.
    """
    paths = get_app_paths()
    mk = _get_master_key(paths)

    try:
        raw = backup_path.read_bytes()
        header_end = raw.index(b"\n")
        header = json.loads(raw[:header_end].decode("utf-8"))
        ciphertext = raw[header_end + 1:]

        nonce = bytes.fromhex(header["nonce"])
        tag = bytes.fromhex(header["tag"])
        expected_checksum = header["checksum"]

        zip_data = decrypt_bytes(ciphertext, nonce, tag, mk)
        actual_checksum = hashlib.sha256(zip_data).hexdigest()

        if actual_checksum != expected_checksum:
            raise ValueError(f"Checksum mismatch: expected {expected_checksum}, got {actual_checksum}")

        with zipfile.ZipFile(BytesIO(zip_data)) as zf:
            extract_dir = paths["TEMP_DIR"] / "restore"
            if extract_dir.exists():
                shutil.rmtree(extract_dir)
            extract_dir.mkdir(parents=True)
            zf.extractall(str(extract_dir))

            if (extract_dir / "compliance.db").exists():
                dst = paths["DB_PATH"]
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(extract_dir / "compliance.db"), str(dst))
            if (extract_dir / "chain.json").exists():
                shutil.copy2(str(extract_dir / "chain.json"), str(paths["CHAIN_PATH"]))
            if (extract_dir / "config.json").exists():
                shutil.copy2(str(extract_dir / "config.json"), str(paths["CONFIG_PATH"]))

            shutil.rmtree(extract_dir)

        create_notification(
            title="Backup Restored",
            message=f"System restored from: {backup_path.name}",
            ntype="BACKUP",
            role="CCO",
        )
        logger.info(f"Backup restored from: {backup_path}")
        return True

    except Exception as e:
        logger.error(f"Restore failed: {e}", exc_info=True)
        create_notification(
            title="Restore Failed",
            message=str(e)[:300],
            ntype="ERROR",
            role="CCO",
        )
        return False
