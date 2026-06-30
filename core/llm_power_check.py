"""
Phantom Compliance — LLM Power Warning & System Check
Displays disclaimer before heavy LLM calls, checks system capability,
shows high-level warning if system cannot support the requested operation.
"""

import os
import time
import logging
import platform
from typing import Optional

logger = logging.getLogger("phantom_compliance.power_check")

SYSTEM_REQUIREMENTS = {
    "min_ram_gb": 16,
    "min_disk_gb": 10,
    "recommended_cpu_cores": 4,
}


def get_system_info() -> dict:
    import psutil
    info = {
        "ram_total_gb": round(psutil.virtual_memory().total / (1024**3), 1),
        "ram_available_gb": round(psutil.virtual_memory().available / (1024**3), 1),
        "cpu_cores": psutil.cpu_count(logical=True),
        "disk_free_gb": 0,
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "llm_available": False,
        "model_path": "",
        "model_exists": False,
    }
    try:
        from config.settings import get_app_paths, load_config, save_config
        paths = get_app_paths()
        if "DATABASE_DIR" in paths:
            import shutil
            usage = shutil.disk_usage(paths["DATABASE_DIR"])
            info["disk_free_gb"] = round(usage.free / (1024**3), 1)
        cfg = load_config()
        info["llm_available"] = not os.environ.get("PHANTOM_NO_LLM", "")
        info["model_path"] = cfg.get("model_path", "")
        if not info["model_path"]:
            from core.setup import get_model_path as gmp
            mp = gmp()
            if mp.exists():
                info["model_path"] = str(mp)
                cfg["model_path"] = str(mp)
                save_config(cfg)
        info["model_exists"] = os.path.exists(info["model_path"]) if info["model_path"] else False
    except Exception:
        pass
    return info


def get_llm_disclaimer() -> str:
    return (
        "This operation uses the local LLM (Mistral-7B) which requires:\n"
        f"  • RAM: {SYSTEM_REQUIREMENTS['min_ram_gb']}GB minimum\n"
        f"  • Disk: {SYSTEM_REQUIREMENTS['min_disk_gb']}GB free\n"
        f"  • CPU: {SYSTEM_REQUIREMENTS['recommended_cpu_cores']}+ cores\n\n"
        "The model runs entirely on your hardware. No data leaves this machine.\n"
        "This operation may take 30–120 seconds depending on your hardware."
    )


def check_system_capability() -> dict:
    info = get_system_info()
    warnings = []
    critical = []

    if info["ram_total_gb"] < SYSTEM_REQUIREMENTS["min_ram_gb"]:
        msg = f"Low RAM: {info['ram_total_gb']}GB (recommended {SYSTEM_REQUIREMENTS['min_ram_gb']}GB)"
        if info["ram_total_gb"] < 8:
            critical.append(msg)
        else:
            warnings.append(msg)

    if info["disk_free_gb"] < SYSTEM_REQUIREMENTS["min_disk_gb"]:
        warnings.append(f"Low disk space: {info['disk_free_gb']}GB free (recommended {SYSTEM_REQUIREMENTS['min_disk_gb']}GB)")

    if info["cpu_cores"] < SYSTEM_REQUIREMENTS["recommended_cpu_cores"]:
        warnings.append(f"Low CPU cores: {info['cpu_cores']} (recommended {SYSTEM_REQUIREMENTS['recommended_cpu_cores']})")

    if not info["llm_available"]:
        warnings.append("LLM is disabled (--no-llm flag). Using SQL fallback.")

    if not info["model_exists"] and info["llm_available"]:
        critical.append("Model file not found. Place GGUF model in models/ directory.")

    return {
        "system": info,
        "warnings": warnings,
        "critical": critical,
        "can_run_llm": len(critical) == 0 and info["llm_available"],
        "disclaimer": get_llm_disclaimer(),
        "degraded_mode": len(critical) > 0 or not info["model_exists"],
    }


def require_llm_warning() -> dict:
    """Show warning and capability check before any LLM call. Returns dict consumers should display."""
    result = check_system_capability()
    if result["critical"]:
        result["level"] = "CRITICAL"
        result["message"] = "⚠️  SYSTEM CANNOT RUN LLM OPERATIONS\n" + "\n".join(result["critical"])
    elif result["warnings"]:
        result["level"] = "WARNING"
        result["message"] = "⚠️  System may have degraded performance\n" + "\n".join(result["warnings"])
    else:
        result["level"] = "OK"
        result["message"] = "System meets all requirements."
    return result
