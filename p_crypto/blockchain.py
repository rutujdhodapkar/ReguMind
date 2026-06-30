"""
Local tamper-proof blockchain ledger for Phantom Compliance.

Every compliance action creates a new block appended to chain.json.
The chain is validated by recomputing every block's hash and checking
that each block's prev_hash matches the previous block's block_hash.

Block structure:
  {
    "index": int,
    "timestamp": "ISO-8601",
    "action": str,           // e.g. CIRCULAR_INGESTED, MAPS_GENERATED, etc.
    "data_hash": str,        // SHA-256 hex of the action payload JSON
    "prev_hash": str,        // SHA-256 hex of the previous block
    "block_hash": str        // SHA-256 hex of everything above except this field
  }

Actions tracked:
  CIRCULAR_INGESTED, MAPS_GENERATED, MAP_ASSIGNED, EVIDENCE_SUBMITTED,
  MAP_VALIDATED, DEADLINE_BREACHED, ESCALATED_TO_CCO, BLOCKCHAIN_INIT

Chain verification:
  verify_chain() walks the entire chain and returns (is_valid, errors_list).
  Any tampering (modified index, timestamp, action, data_hash, or prev_hash)
  causes a hash mismatch and is detected.
"""

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class Blockchain:
    def __init__(self, chain_path: Path):
        self.chain_path = chain_path
        self._chain: list[dict] = []
        self._load()

    def _load(self):
        if self.chain_path.exists():
            with open(self.chain_path, "r", encoding="utf-8") as f:
                self._chain = json.load(f)
        else:
            genesis = self._create_block(
                index=0,
                action="BLOCKCHAIN_INIT",
                data_hash=hashlib.sha256(b"PHANTOM_COMPLIANCE_GENESIS").hexdigest(),
                prev_hash="0" * 64,
            )
            self._chain = [genesis]
            self._persist()

    def _persist(self):
        with open(self.chain_path, "w", encoding="utf-8") as f:
            json.dump(self._chain, f, indent=2)

    def _compute_block_hash(self, block: dict) -> str:
        block_copy = {k: v for k, v in block.items() if k != "block_hash"}
        raw = json.dumps(block_copy, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def _create_block(self, index: int, action: str, data_hash: str, prev_hash: str) -> dict:
        timestamp = datetime.now(timezone.utc).isoformat()
        block = {
            "index": index,
            "timestamp": timestamp,
            "action": action,
            "data_hash": data_hash,
            "prev_hash": prev_hash,
            "block_hash": "",
        }
        block["block_hash"] = self._compute_block_hash(block)
        return block

    def add_entry(self, action: str, payload: dict) -> dict:
        """
        Add a new block to the chain. The payload dict is serialized,
        hashed with SHA-256, and stored as data_hash in the new block.
        """
        data_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()

        prev_block = self._chain[-1]
        new_block = self._create_block(
            index=prev_block["index"] + 1,
            action=action,
            data_hash=data_hash,
            prev_hash=prev_block["block_hash"],
        )
        self._chain.append(new_block)
        self._persist()
        return new_block

    def verify_chain(self) -> tuple[bool, list[str]]:
        """
        Walk the entire chain and verify integrity.
        Returns (is_valid, list_of_error_messages).
        Empty error list means the chain is intact.
        """
        errors = []
        for i, block in enumerate(self._chain):
            expected_hash = self._compute_block_hash(block)
            if block["block_hash"] != expected_hash:
                errors.append(
                    f"Block {block['index']}: hash mismatch. "
                    f"Expected {expected_hash}, got {block['block_hash']}"
                )
            if i > 0:
                prev_block = self._chain[i - 1]
                if block["prev_hash"] != prev_block["block_hash"]:
                    errors.append(
                        f"Block {block['index']}: prev_hash mismatch. "
                        f"Expected {prev_block['block_hash']}, got {block['prev_hash']}"
                    )
        return len(errors) == 0, errors

    def get_chain(self) -> list[dict]:
        return list(self._chain)

    def corrupt_block(self, index: int, field: str, new_value):
        """Intentionally corrupt a block for tamper-testing demo purposes."""
        if 0 <= index < len(self._chain):
            self._chain[index][field] = new_value
            self._persist()
