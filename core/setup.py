"""
PHANTOM COMPLIANCE — Auto Setup Module
First-run detection, model validation, config initialization.
ZERO internet calls — model must be placed manually by the user.
"""

import os
import sys
import hashlib
import logging
from pathlib import Path

from config.settings import get_app_paths, load_config, save_config

logger = logging.getLogger("phantom_compliance.setup")

MODEL_FILENAME = "Llama-3.2-3B-Instruct-Q4_K_M.gguf"
MODEL_EXPECTED_SHA256 = ""


def is_first_run() -> bool:
    cfg_path = get_app_paths()["CONFIG_PATH"]
    return not cfg_path.exists()


def get_model_path() -> Path:
    r"""
    Resolve the GGUF model file path.

    Search order (highest priority first):
      1. Path stored in config.json ("model_path" key) - user-customised.
      2. Folder next to the running EXE / script (portable: place .gguf beside the exe).
      3. <exe_dir>\models\ subfolder beside the EXE.
      4. CUDA bundle directory inside the source tree (dev mode).
      5. Source tree models\ directory (dev mode).
      6. AppData MODELS_DIR (installed mode).
    """
    # 0. Honour an explicit override saved in config
    try:
        cfg = load_config()
        saved = cfg.get("model_path", "")
        if saved and Path(saved).exists():
            return Path(saved)
    except Exception:
        pass

    # Determine the directory that contains the running executable/script
    if getattr(sys, 'frozen', False):
        # Running inside a PyInstaller bundle
        exe_dir = Path(sys.executable).parent
    else:
        # Running as plain Python — use the source root
        exe_dir = Path(__file__).resolve().parent.parent

    # 1. Right next to the EXE
    beside_exe = exe_dir / MODEL_FILENAME
    if beside_exe.exists():
        return beside_exe

    # 2. models\ subfolder beside the EXE  ← USER-ACCESSIBLE FOLDER
    models_beside = exe_dir / "models" / MODEL_FILENAME
    if models_beside.exists():
        return models_beside

    # 3. CUDA bundle (dev)
    base = Path(__file__).resolve().parent.parent
    cuda_model = base / "models" / "text" / "llama-b7996-bin-win-cuda-12.4-x64" / MODEL_FILENAME
    if cuda_model.exists():
        return cuda_model

    # 4. Source tree models\ (dev)
    local_model = base / "models" / MODEL_FILENAME
    if local_model.exists():
        return local_model

    # 5. AppData MODELS_DIR (installed / fallback)
    paths = get_app_paths()
    model_dir = paths.get("MODELS_DIR", paths["INSTALL_DIR"] / "models")
    try:
        model_dir.mkdir(parents=True, exist_ok=True)
    except (PermissionError, OSError):
        model_dir = Path.home() / ".phantom_compliance" / "models"
        model_dir.mkdir(parents=True, exist_ok=True)
    return model_dir / MODEL_FILENAME



def is_model_downloaded() -> bool:
    model_path = get_model_path()
    if not model_path.exists():
        return False
    size_mb = model_path.stat().st_size / (1024 * 1024)
    if size_mb < 500:
        return False
    cfg = load_config()
    downloaded = cfg.get("model_downloaded", False)
    if not downloaded:
        cfg["model_downloaded"] = True
        cfg["model_path"] = str(model_path)
        save_config(cfg)
        return True
    return downloaded


def verify_model_checksum() -> bool:
    if not MODEL_EXPECTED_SHA256:
        return True
    model_path = get_model_path()
    if not model_path.exists():
        return False
    sha256 = hashlib.sha256()
    with open(model_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest() == MODEL_EXPECTED_SHA256


def print_model_instructions():
    model_path = get_model_path()
    print()
    print("=" * 70)
    print("  MODEL REQUIRED — Fully Offline Setup")
    print("=" * 70)
    print()
    print(f"  Place the GGUF model file at:")
    print(f"    {model_path}")
    print()
    print("  Download it on an internet-connected machine from:")
    print("    https://huggingface.co/bartowski/Llama-3.2-3B-Instruct-GGUF/")
    print("    resolve/main/Llama-3.2-3B-Instruct-Q4_K_M.gguf")
    print()
    print("  Alternatively, use any compatible GGUF model — update the")
    print("  path or MODEL_FILENAME in core/setup.py.")
    print()
    print("  The SQL-based LLM fallback will be used until a model is")
    print("  detected. The system functions in degraded mode without it.")
    print("=" * 70)
    print()


def run_first_run_setup() -> dict:
    """Execute first-run setup. ZERO internet calls."""
    results = {"model_downloaded": False, "checksum_ok": False, "error": None}

    cfg = load_config()
    cfg["first_run_complete"] = True
    cfg["llm_url"] = "http://localhost:8080/completion"
    cfg["model_downloaded"] = False
    save_config(cfg)

    model_path = get_model_path()
    if model_path.exists():
        ok = verify_model_checksum()
        cfg = load_config()
        cfg["model_downloaded"] = True
        cfg["model_checksum_verified"] = ok
        cfg["model_path"] = str(model_path)
        save_config(cfg)
        if ok:
            logger.info(f"Model verified: {model_path.name}")
            results["model_downloaded"] = True
            results["checksum_ok"] = True
        else:
            logger.warning("Model file exists but checksum mismatch")
            results["error"] = "Checksum mismatch"
    else:
        logger.info("No model file found — printing placement instructions")
        print_model_instructions()
        results["error"] = "Model not found — see instructions above"

    return results
