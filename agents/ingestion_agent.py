"""
INGESTION AGENT
Monitors /inbox folder for new PDF circulars using watchdog.
On new PDF: extract text via PyMuPDF, extract metadata via regex,
encrypt body, store in circulars table, append blockchain block.
"""

import time
import json
import hashlib
import logging
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from config.settings import get_app_paths
from utils.pdf_parser import extract_text_from_pdf, extract_circular_metadata
from utils.database import store_circular
from p_crypto.blockchain import Blockchain

logger = logging.getLogger("phantom_compliance.ingestion")


class CircularHandler(FileSystemEventHandler):
    def __init__(self, blockchain: Blockchain):
        self.blockchain = blockchain
        self.processed = set()

    def on_created(self, event):
        if event.is_directory:
            return
        if not event.src_path.lower().endswith(".pdf"):
            return
        if event.src_path in self.processed:
            return
        self.processed.add(event.src_path)
        self._process_pdf(event.src_path)

    def _process_pdf(self, pdf_path: str):
        logger.info(f"Ingesting circular: {pdf_path}")
        try:
            full_text = extract_text_from_pdf(pdf_path)
            if not full_text.strip():
                logger.warning(f"Empty text extracted from {pdf_path}")
                return

            meta = extract_circular_metadata(full_text)
            cid = store_circular(
                circular_number=meta["circular_number"],
                dept_code=meta["department_code"],
                issue_date=meta["issue_date"],
                addressee=meta["addressee"],
                subject=meta["subject_line"],
                body_text=full_text,
            )

            payload = {
                "circular_id": cid,
                "circular_number": meta["circular_number"],
                "department_code": meta["department_code"],
                "subject": meta["subject_line"],
                "file": pdf_path,
            }
            block = self.blockchain.add_entry("CIRCULAR_INGESTED", payload)
            logger.info(
                f"Circular #{meta['circular_number']} ingested (id={cid}, "
                f"block={block['index']})"
            )
            self._record_run(cid)
            try:
                from agents.pipeline import run_post_ingestion_pipeline
                run_post_ingestion_pipeline(cid, self.blockchain, source="drop")
            except Exception as pipeline_error:
                logger.error(
                    f"Post-ingestion pipeline failed for circular {cid}: {pipeline_error}",
                    exc_info=True,
                )
        except Exception as e:
            logger.error(f"Failed to ingest {pdf_path}: {e}", exc_info=True)

    def _record_run(self, cid):
        try:
            from core.agent_viz import record_agent_run
            record_agent_run("Ingestion Agent", "COMPLETED", tasks_processed=1)
        except Exception:
            pass


def start_watching(inbox_path: Path, blockchain: Blockchain):
    """Start the watchdog observer on the inbox directory."""
    observer = Observer()
    handler = CircularHandler(blockchain)
    observer.schedule(handler, str(inbox_path), recursive=False)
    observer.start()
    logger.info(f"Watching inbox: {inbox_path}")
    return observer


def ingest_single(pdf_path: str, blockchain: Blockchain) -> int:
    """Ingest a single PDF file directly (for manual upload from dashboard)."""
    logger.info(f"Manual ingest: {pdf_path}")
    full_text = extract_text_from_pdf(pdf_path)
    meta = extract_circular_metadata(full_text)
    cid = store_circular(
        circular_number=meta["circular_number"],
        dept_code=meta["department_code"],
        issue_date=meta["issue_date"],
        addressee=meta["addressee"],
        subject=meta["subject_line"],
        body_text=full_text,
    )
    payload = {
        "circular_id": cid,
        "circular_number": meta["circular_number"],
        "department_code": meta["department_code"],
        "subject": meta["subject_line"],
    }
    blockchain.add_entry("CIRCULAR_INGESTED", payload)
    logger.info(f"Manual ingest complete: circular_id={cid}")
    try:
        from core.agent_viz import record_agent_run
        record_agent_run("Ingestion Agent", "COMPLETED", tasks_processed=1)
    except Exception:
        pass
    return cid
