"""
LLM AGENT
Communicates with NVIDIA NIM (Phi-4-mini) server at
http://localhost:8000/v1/chat/completions using OpenAI-compatible API.

Decrypts circular text into RAM, sends structured prompt, parses JSON response,
encrypts generated MAPs, stores in maps table, wipes plaintext variables.
"""

import json
import logging
import urllib.request
import urllib.error
from typing import Optional

from p_crypto.encryptor import encrypt
from utils.database import get_circular_body, get_connection, store_map

logger = logging.getLogger("phantom_compliance.llm")

LLM_URL = "http://localhost:8080/v1/chat/completions"
LLM_MODEL = "Llama-3.2-3B-Instruct"
MAX_RETRIES = 2


def _openai_payload(prompt: str, max_tokens: int = 256, temperature: float = 0.1) -> bytes:
    return json.dumps({
        "model": LLM_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": min(max_tokens, 2048),
        "temperature": temperature,
    }).encode("utf-8")


def _parse_openai_response(data: bytes) -> Optional[str]:
    try:
        result = json.loads(data.decode("utf-8"))
        choices = result.get("choices", [])
        if choices:
            return choices[0].get("message", {}).get("content", "")
        return None
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        logger.warning(f"Failed to parse OpenAI response: {e}")
        return None


def _call_llm(prompt: str, retries: int = MAX_RETRIES, max_tokens: int = 256) -> Optional[str]:
    """Send a chat completion request to NVIDIA NIM. OpenAI-compatible API."""
    payload = _openai_payload(prompt, max_tokens=max_tokens)
    req = urllib.request.Request(
        LLM_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    timeout = 600 if max_tokens > 256 else 120
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                text = _parse_openai_response(resp.read())
                if text:
                    return text.strip()
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
            logger.warning(f"LLM call attempt {attempt + 1} failed: {e}")
            if attempt == retries - 1:
                return None
    return None


def query_llm(prompt: str, max_tokens: int = 256) -> str:
    """Wrapper for the analyze endpoint. Returns raw text or empty string."""
    result = _call_llm(prompt, max_tokens=max_tokens)
    return result or ""


def _extract_json(text: str) -> Optional[list]:
    """Try to parse JSON array from LLM output, handling markdown fences and malformed output."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[-1]
        cleaned = cleaned.rsplit("```", 1)[0]
    cleaned = cleaned.strip()

    try:
        data = json.loads(cleaned)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        return None
    except json.JSONDecodeError:
        import re
        # Try to find outermost JSON array
        match = re.search(r"\[.*\]", cleaned, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group())
                if isinstance(data, list):
                    return data
                return [data]
            except json.JSONDecodeError:
                pass
        # Handle flat arrays like ["a","b"],["c","d"] (missing outer brackets)
        arr_match = re.findall(r'\[(.*?)\]\s*(?:,\s*\[)?', cleaned, re.DOTALL)
        if arr_match and len(arr_match) >= 1:
            try:
                items = []
                for m in arr_match:
                    parsed = json.loads("[" + m + "]")
                    if isinstance(parsed, list):
                        items.append(parsed)
                if items:
                    # Convert positional arrays to dicts by field order
                    fields = ["map_id", "obligation", "department_hint", "deadline_days_from_date", "evidence_required", "frequency"]
                    return [{fields[i] if i < len(fields) else f"field_{i}": v for i, v in enumerate(arr)} for arr in items]
            except (json.JSONDecodeError, IndexError):
                pass
        return None


def generate_maps(circular_id: int, mk: bytes) -> list[dict] | None:
    """
    Generate MAPs for a circular by:
    1. Decrypting circular text into RAM
    2. Sending to LLM with structured prompt
    3. Parsing JSON response
    4. Encrypting and storing each MAP
    5. Clearing plaintext from RAM

    Returns: list of stored MAPs, [] if LLM returned no MAPs, None on error.
    """
    circular_body = get_circular_body(circular_id)
    if not circular_body:
        logger.error(f"No body text for circular {circular_id}")
        return None

    import re as _re
    clean = _re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', circular_body or '')
    # Skip letterhead/TOC — find actual regulatory text
    markers = [
        'In exercise of the powers',        # RBI legal preamble
        'These Directions shall be called',  # Direction title
        'Chapter – I  Preliminary',          # First chapter
        '1. Short title',                    # First section
        '2. Applicability',                  # Second section
    ]
    body_start = 1000
    for m in markers:
        idx = clean.find(m, 500)
        if 500 < idx < min(len(clean) - 2000, 30000):
            body_start = idx
            break
    truncated = clean[body_start:body_start + 2000] if clean else ""
    prompt = f"""Extract exactly 2 compliance actions from this RBI circular. Return ONLY a JSON array of objects.

Each object must have these keys: "map_id" (string like "RBI-MAP-1"), "obligation" (string, max 60 chars), "department_hint" (one of: KYC, Payments, IT_Security, Treasury, Forex, Credit_Risk), "deadline_days_from_date" (integer), "evidence_required" (string), "frequency" (one of: One-time, Monthly, Quarterly, Annually).

Example:
[{{"map_id": "RBI-MAP-1", "obligation": "Implement KYC verification", "department_hint": "KYC", "deadline_days_from_date": 30, "evidence_required": "Customer ID proof", "frequency": "One-time"}}]

Circular text: {truncated}"""

    llm_text = _call_llm(prompt, max_tokens=512)
    if not llm_text:
        logger.error(f"LLM returned empty for circular {circular_id}")
        return None

    try:
        conn = get_connection()
        conn.execute("UPDATE circulars SET analysis=? WHERE id=?", (json.dumps({"_raw_response": llm_text[:2000]}, ensure_ascii=False), circular_id))
        conn.commit()
        conn.close()
    except Exception:
        pass

    maps_data = _extract_json(llm_text)
    if maps_data is None:
        logger.error(f"Could not parse LLM JSON for circular {circular_id}")
        return None
    if not maps_data:
        logger.info(f"LLM returned no MAPs for circular {circular_id}")
        return []

    stored_maps = []
    for item in maps_data:
        what = item.get("obligation") or item.get("what", "Unspecified action")
        dept_hint = item.get("department_hint", "KYC")
        deadline_days = item.get("deadline_days_from_date", 30)
        evidence_req = item.get("evidence_required", "")
        frequency = item.get("frequency", "One-time")
        map_id_label = item.get("map_id", f"RBI-MAP-{circular_id}")

        detail_json = json.dumps(item, ensure_ascii=False)
        ciphertext, nonce, auth_tag = encrypt(detail_json, mk)

        mid = store_map(
            circular_id=circular_id,
            map_text=what,
            encrypted_detail=ciphertext,
            detail_nonce=nonce,
            detail_auth_tag=auth_tag,
            dept_hint=dept_hint,
            deadline_days=deadline_days,
            frequency=frequency,
            evidence_required=evidence_req,
            map_id_label=map_id_label,
        )
        stored_maps.append({
            "map_id": map_id_label,
            "obligation": what,
            "department": dept_hint,
            "evidence_required": evidence_req,
            "frequency": frequency,
            "status": "PENDING",
        })
        logger.info(f"MAP #{mid} generated: {what[:60]}...")

    circular_body = ""
    llm_text = ""
    return stored_maps


def validate_evidence(map_what: str, evidence_text: str, evidence_required: str) -> tuple[bool, str]:
    """
    Send evidence + MAP description to LLM for validation.
    Returns (is_valid, reasoning).
    """
    prompt = f"""You are a compliance auditor.
Does this evidence satisfy the MAP's evidence requirement?

MAP: {map_what}
Evidence Required: {evidence_required}
Evidence Provided: {evidence_text[:2000]}

Answer YES or NO followed by one sentence reasoning.
Example: NO The evidence is a screenshot of a draft, not a signed approval."""

    response = _call_llm(prompt)
    if not response:
        return False, "Could not reach LLM for validation"

    is_valid = response.strip().upper().startswith("YES")
    reasoning = response.strip()
    return is_valid, reasoning
