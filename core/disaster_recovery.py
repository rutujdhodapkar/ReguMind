"""
Phantom Compliance — Disaster Recovery & Offline Updates
Creates signed offline recovery archives with full system export.
Update packages use cryptographic signing to prevent tampered updates.
"""

import os
import json
import hashlib
import hmac
import logging
import shutil
import zipfile
from pathlib import Path
from datetime import datetime

from p_crypto.encryptor import encrypt, decrypt

logger = logging.getLogger("phantom_compliance.disaster_recovery")

RECOVERY_SIGNING_KEY = b"phantom_disaster_recovery_v1_signing_key"


def _get_recovery_signing_key() -> bytes:
    from auth.credential_manager import get_password, store_password
    import secrets
    key_b64 = get_password("dr_signing_key")
    if not key_b64:
        key = secrets.token_hex(32)
        store_password("dr_signing_key", key)
        return key.encode("utf-8")
    return key_b64.encode("utf-8")


def _sign_manifest(manifest: dict) -> str:
    key = _get_recovery_signing_key()
    serialized = json.dumps(manifest, sort_keys=True, default=str).encode("utf-8")
    return hmac.new(key, serialized, hashlib.sha256).hexdigest()


def create_disaster_recovery_package(output_dir: str | Path = None) -> dict:
    """
    Create a complete disaster recovery package:
    - Database dump
    - Config
    - Blockchain
    - Integrity hashes
    - Signed manifest
    """
    from config.settings import get_app_paths, load_config, save_config

    paths = get_app_paths()
    if output_dir is None:
        output_dir = paths.get("DATABASE_DIR", paths["INSTALL_DIR"]) / "dr_packages"

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    package_name = f"phantom_dr_{timestamp}.zip"
    package_path = output_dir / package_name

    manifest = {
        "package_name": package_name,
        "created_at": datetime.now().isoformat(),
        "system": "Phantom Compliance Disaster Recovery Package",
        "contents": [],
        "version": "1.0",
    }

    with zipfile.ZipFile(package_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Database
        db_path = paths.get("DB_PATH", paths["INSTALL_DIR"] / "compliance.db")
        if db_path.exists():
            zf.write(db_path, "compliance.db")
            manifest["contents"].append({"file": "compliance.db", "type": "database"})

        # Blockchain
        chain_path = paths.get("CHAIN_PATH", paths["INSTALL_DIR"] / "blockchain.json")
        if chain_path.exists():
            zf.write(chain_path, "blockchain.json")
            manifest["contents"].append({"file": "blockchain.json", "type": "blockchain"})

        # Config
        cfg_path = paths.get("CONFIG_PATH", paths["INSTALL_DIR"] / "config.json")
        if cfg_path.exists():
            zf.write(cfg_path, "config.json")
            manifest["contents"].append({"file": "config.json", "type": "config"})

        # Integrity hashes
        hash_store = paths.get("DATABASE_DIR", paths["INSTALL_DIR"]) / ".integrity_hashes"
        if hash_store.exists():
            zf.write(hash_store, ".integrity_hashes")
            manifest["contents"].append({"file": ".integrity_hashes", "type": "integrity"})

        # Signed manifest
        manifest_hash = hashlib.sha256(json.dumps(manifest, default=str).encode()).hexdigest()
        manifest["manifest_hash"] = manifest_hash
        manifest["signature"] = _sign_manifest(manifest)

        zf.writestr("manifest.json", json.dumps(manifest, indent=2, default=str))

    signature_path = package_path.with_suffix(".sig")
    signature_path.write_text(manifest["signature"])

    # Also save a hidden copy
    try:
        from core.data_protector import _get_hidden_storage, _get_local_appdata_storage
        for loc in [_get_hidden_storage(), _get_local_appdata_storage()]:
            dr_dir = loc / "dr_packages"
            dr_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(package_path, dr_dir / package_name)
            shutil.copy2(signature_path, dr_dir / signature_path.name)
    except Exception:
        pass

    logger.info(f"Disaster recovery package created: {package_path}")
    return {
        "ok": True,
        "package_path": str(package_path),
        "package_name": package_name,
        "size_bytes": package_path.stat().st_size,
        "contents": manifest["contents"],
        "signature": manifest["signature"][:16] + "...",
    }


def verify_dr_package(package_path: str | Path) -> dict:
    """Verify a disaster recovery package signature and integrity."""
    package_path = Path(package_path)
    if not package_path.exists():
        return {"valid": False, "error": "Package not found"}

    try:
        with zipfile.ZipFile(package_path, "r") as zf:
            if "manifest.json" not in zf.namelist():
                return {"valid": False, "error": "No manifest in package"}

            manifest = json.loads(zf.read("manifest.json"))
            stored_sig = manifest.pop("signature", "")
            stored_hash = manifest.pop("manifest_hash", "")

            # Verify hash
            actual_hash = hashlib.sha256(json.dumps(manifest, default=str).encode()).hexdigest()
            if actual_hash != stored_hash:
                return {"valid": False, "error": "Manifest hash mismatch"}

            # Verify signature
            manifest["manifest_hash"] = stored_hash
            expected_sig = _sign_manifest(manifest)
            if expected_sig != stored_sig:
                return {"valid": False, "error": "Signature mismatch (tampered)"}

        return {"valid": True, "manifest": manifest}
    except Exception as e:
        return {"valid": False, "error": str(e)}


def list_dr_packages() -> list[dict]:
    """List all DR packages across all storage locations."""
    from config.settings import get_app_paths
    paths = get_app_paths()
    locations = [
        paths.get("DATABASE_DIR", paths["INSTALL_DIR"]) / "dr_packages",
    ]
    try:
        from core.data_protector import _get_hidden_storage, _get_local_appdata_storage
        locations.append(_get_hidden_storage() / "dr_packages")
        locations.append(_get_local_appdata_storage() / "dr_packages")
    except Exception:
        pass

    packages = []
    for loc in locations:
        if loc.exists():
            for f in sorted(loc.glob("*.zip"), key=lambda x: x.stat().st_mtime, reverse=True):
                sig_file = f.with_suffix(".sig")
                packages.append({
                    "name": f.name,
                    "path_hint": "hidden" if "Temp" in str(loc) or ".phantom" in str(loc) else "appdata",
                    "size_bytes": f.stat().st_size,
                    "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
                    "has_signature": sig_file.exists(),
                })
    return packages
