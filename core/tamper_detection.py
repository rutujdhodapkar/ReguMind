"""
Phantom Compliance — Tamper Detection
Hashes executable, config, schema, and rule files on startup.
If anything changed since last recorded hash, block launch and log.
"""

import os
import hashlib
import json
import logging
import sys
from pathlib import Path

logger = logging.getLogger("phantom_compliance.tamper_detection")

CRITICAL_PATTERNS = [
    "*.py",
    "config/*.json",
    "config/*.sql",
    "auth/*.py",
    "crypto/*.py",
    "core/*.py",
    "agents/*.py",
    "utils/*.py",
    "web/*.py",
    "main.py",
]

HASH_STORE_FILENAME = ".integrity_hashes"


def _hash_file(filepath: Path) -> str:
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def _get_project_root() -> Path:
    return Path(__file__).parent.parent.resolve()


def _get_hash_store_path() -> Path:
    from config.settings import get_app_paths
    paths = get_app_paths()
    return paths.get("DATABASE_DIR", paths["INSTALL_DIR"]) / HASH_STORE_FILENAME


def _scan_critical_files() -> dict[str, str]:
    """Scan all critical files and return {relative_path: sha256_hash}."""
    root = _get_project_root()
    files = {}
    import fnmatch
    for pattern in CRITICAL_PATTERNS:
        for filepath in sorted(root.rglob(pattern)):
            if "__pycache__" in str(filepath) or ".git" in str(filepath) or "models" in str(filepath) or "venv" in str(filepath):
                continue
            if filepath.is_file():
                rel_path = str(filepath.relative_to(root))
                try:
                    files[rel_path] = _hash_file(filepath)
                except (OSError, PermissionError) as e:
                    logger.error(f"Cannot hash {rel_path}: {e}")
    return files


def _save_hashes(hashes: dict[str, str]):
    store_path = _get_hash_store_path()
    try:
        store_path.parent.mkdir(parents=True, exist_ok=True)
        # Make writable first if exists (for re-baseline)
        if store_path.exists():
            try:
                os.chmod(store_path, 0o644)
            except (OSError, PermissionError):
                pass
        store_path.write_text(
            json.dumps(hashes, sort_keys=True, indent=2),
            encoding="utf-8",
        )
        # Make the hash store read-only for normal users
        try:
            os.chmod(store_path, 0o444)
        except (OSError, PermissionError):
            pass
        logger.info(f"Saved integrity hashes for {len(hashes)} files to {store_path}")
    except OSError as e:
        logger.error(f"Failed to save integrity hashes: {e}")


def _load_hashes() -> dict[str, str]:
    store_path = _get_hash_store_path()
    if not store_path.exists():
        return {}
    try:
        return json.loads(store_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Failed to load integrity hashes: {e}")
        return {}


def verify_integrity() -> dict:
    """
    Verify all critical files against stored hashes.
    Returns {"valid": bool, "changed_files": [...], "new_files": [...], "total": int, "errors": [...]}
    """
    current = _scan_critical_files()
    stored = _load_hashes()

    if not stored:
        logger.info("First run — recording integrity hashes")
        _save_hashes(current)
        return {"valid": True, "changed_files": [], "new_files": [], "total": len(current), "errors": [], "first_run": True}

    changed = []
    new_files = []
    errors = []

    for path, hash_val in current.items():
        if path in stored:
            if stored[path] != hash_val:
                changed.append(path)
        else:
            new_files.append(path)

    if changed or new_files:
        logger.warning(f"INTEGRITY VIOLATION: {len(changed)} changed, {len(new_files)} new files")
        for f in changed:
            logger.error(f"FILE TAMPERED: {f}")
        return {"valid": False, "changed_files": changed, "new_files": new_files, "total": len(current), "errors": errors}

    logger.info(f"Integrity check PASSED — {len(current)} files verified")
    return {"valid": True, "changed_files": [], "new_files": [], "total": len(current), "errors": errors}


def block_if_tampered() -> bool:
    """
    Run integrity check. If tampered, block launch and return False.
    Returns True if system should proceed.
    """
    result = verify_integrity()
    if not result["valid"]:
        msg = "\n" + "=" * 70 + "\n"
        msg += "  !! SECURITY VIOLATION - SYSTEM BLOCKED\n"
        msg += "=" * 70 + "\n"
        msg += f"\n  {len(result['changed_files'])} file(s) have been modified:\n"
        for f in result["changed_files"]:
            msg += f"    x {f}\n"
        for f in result.get("new_files", []):
            msg += f"    ? {f} (new file)\n"
        msg += "\n  Possible tampering detected. The system will not start.\n"
        msg += "  Contact your security administrator.\n"
        msg += "=" * 70 + "\n"
        sys.stderr.write(msg)
        return False
    if result.get("first_run"):
        sys.stderr.write("\n  OK First-run integrity baseline recorded.\n")
    else:
        sys.stderr.write(f"\n  OK Integrity check passed ({result['total']} files verified).\n")
    return True


def record_new_baseline():
    """Force-record a new integrity baseline (admin function)."""
    current = _scan_critical_files()
    _save_hashes(current)
    logger.info(f"New integrity baseline recorded: {len(current)} files")
    return len(current)
