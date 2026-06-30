"""
Phantom Compliance — Safe File Sandbox
Restricted parser layer for PDFs, DOCX, XLSX, and images.
Never trust files from the outside world.
Folder allowlisting: only ingest from /inbox, /approved, /evidence.
"""

import os
import json
import hashlib
import logging
import mimetypes
from pathlib import Path
from datetime import datetime

logger = logging.getLogger("phantom_compliance.file_sandbox")

ALLOWED_FOLDERS = ["inbox", "approved", "evidence", "uploads"]
ALLOWED_EXTENSIONS = {".pdf", ".docx", ".doc", ".xlsx", ".xls", ".png", ".jpg", ".jpeg", ".tiff", ".txt"}
MAX_FILE_SIZE_MB = 50
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

DANGEROUS_PATTERNS = [
    b"%PDF",  # Legitimate PDF header
    b"PK",    # ZIP-based formats (docx, xlsx)
    b"\xff\xd8\xff",  # JPEG
    b"\x89PNG",  # PNG
]


def get_allowed_folder_paths() -> list[Path]:
    """Return resolved paths for all allowed ingestion folders."""
    from config.settings import get_app_paths
    paths = get_app_paths()
    base = paths.get("INSTALL_DIR", Path.cwd())
    folders = []
    for folder_name in ALLOWED_FOLDERS:
        fpath = base / folder_name
        if not fpath.exists():
            fpath.mkdir(parents=True, exist_ok=True)
        folders.append(fpath.resolve())
    return folders


def is_path_allowed(filepath: str | Path) -> bool:
    """Check if a file path is within an allowed ingestion folder."""
    filepath = Path(filepath).resolve()
    allowed = get_allowed_folder_paths()
    for folder in allowed:
        try:
            filepath.relative_to(folder)
            return True
        except ValueError:
            continue
    return False


def validate_file_type(filepath: Path) -> tuple[bool, str]:
    """Validate file type by extension AND magic bytes."""
    ext = filepath.suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"File type {ext} not allowed. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}"

    try:
        with open(filepath, "rb") as f:
            header = f.read(16)

        is_valid = False
        for pattern in DANGEROUS_PATTERNS:
            if header.startswith(pattern):
                is_valid = True
                break

        if not is_valid:
            return False, "File header does not match known file format"

        return True, "OK"

    except OSError as e:
        return False, f"Cannot read file: {e}"


def validate_file_size(filepath: Path) -> tuple[bool, str]:
    size = filepath.stat().st_size
    if size == 0:
        return False, "File is empty"
    if size > MAX_FILE_SIZE_BYTES:
        return False, f"File exceeds {MAX_FILE_SIZE_MB}MB limit ({size / 1024 / 1024:.1f}MB)"
    return True, "OK"


def compute_file_hash(filepath: Path) -> str:
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def sandbox_ingestion(filepath: str | Path, expected_hash: str = "") -> dict:
    """
    Full sandbox check before ingestion.
    - Checks path is in allowed folder
    - Validates file type (extension + magic bytes)
    - Validates file size
    - Computes SHA256 hash
    - Checks against expected hash (for USB imports)
    Returns dict with {ok: bool, error: str, hash: str, metadata: dict}
    """
    filepath = Path(filepath)
    result = {"ok": False, "error": "", "hash": "", "metadata": {}}

    if not filepath.exists():
        result["error"] = "File not found"
        return result

    if not is_path_allowed(filepath):
        result["error"] = f"File not in allowed folder. Must be in: {', '.join(ALLOWED_FOLDERS)}"
        return result

    ok, msg = validate_file_type(filepath)
    if not ok:
        result["error"] = msg
        return result

    ok, msg = validate_file_size(filepath)
    if not ok:
        result["error"] = msg
        return result

    file_hash = compute_file_hash(filepath)
    result["hash"] = file_hash

    if expected_hash and file_hash != expected_hash:
        result["error"] = f"Hash mismatch. Expected {expected_hash}, got {file_hash}"
        return result

    result["ok"] = True
    result["metadata"] = {
        "filename": filepath.name,
        "size_bytes": filepath.stat().st_size,
        "extension": filepath.suffix.lower(),
        "last_modified": datetime.fromtimestamp(filepath.stat().st_mtime).isoformat(),
    }
    return result


def extract_text_safe(filepath: Path) -> str:
    """Extract text from a file using safe parsers based on type."""
    ext = filepath.suffix.lower()
    if ext == ".pdf":
        try:
            import fitz
            doc = fitz.open(filepath)
            text = "\n".join(page.get_text() for page in doc)
            doc.close()
            return text
        except ImportError:
            # Fallback: try PyPDF2/pdfminer
            try:
                from pdfminer.high_level import extract_text as pdf_extract
                return pdf_extract(str(filepath))
            except ImportError:
                return f"[PDF text extraction unavailable for {filepath.name}]"
    # Add more parsers as needed
    try:
        return filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return f"[Cannot read {filepath.name}]"
