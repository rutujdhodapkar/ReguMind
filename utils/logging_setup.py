"""
Centralized logging setup for Phantom Compliance.
Logs go to AppData/Local/PhantomCompliance/logs/system.log.
"""

import logging
import sys
from pathlib import Path
from config.settings import get_app_paths


def setup_logging():
    paths = get_app_paths()
    log_path = paths["LOG_PATH"]

    logger = logging.getLogger("phantom_compliance")
    logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_fmt)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_fmt = logging.Formatter("%(levelname)-8s | %(message)s")
    console_handler.setFormatter(console_fmt)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
