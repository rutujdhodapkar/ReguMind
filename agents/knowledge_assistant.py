"""
Phantom Compliance — Knowledge Assistant Agent
Answers queries about regulations, policies, and circulars using
TF-IDF retrieval from local data. No LLM dependency.
"""

import re
import json
import math
import logging
from collections import Counter
from datetime import datetime
from typing import Optional
from utils.database import get_connection

logger = logging.getLogger("phantom_compliance.knowledge_assistant")


class TFIDFSearch:
    """Simple TF-IDF vector search over circulars and policies."""

    def __init__(self):
        self._documents = []
        self._vocab = set()
        self._idf = {}
        self._tf_matrix = []
        self._built = False

    def _tokenize(self, text: str) -> list[str]:
        return re.findall(r"[a-zA-Z_]+", text.lower())

    def build_index(self, documents: list[dict]):
        """Build TF-IDF index from document list [{id, text, title, type}]."""
        self._documents = documents
        all_tokens = []
        for doc in documents:
            tokens = self._tokenize(doc.get("text", "") + " " + doc.get("title", ""))
            all_tokens.append(tokens)
            self._vocab.update(tokens)

        self._idf = {}
        for term in self._vocab:
            df = sum(1 for tokens in all_tokens if term in tokens)
            self._idf[term] = math.log((len(documents) + 1) / (df + 1)) + 1

        self._tf_matrix = []
        for tokens in all_tokens:
            tf = Counter(tokens)
            max_freq = max(tf.values()) if tf else 1
            tf_vector = {term: (tf.get(term, 0) / max_freq) * self._idf.get(term, 1) for term in self._vocab}
            self._tf_matrix.append(tf_vector)

        self._built = True
        logger.info(f"TF-IDF index built: {len(documents)} documents, {len(self._vocab)} terms")

    def search(self, query: str, top_k: int = 5) -> list[dict]:
        if not self._built:
            return []
        query_tokens = self._tokenize(query)
        if not query_tokens:
            return []
        q_tf = Counter(query_tokens)
        q_max = max(q_tf.values()) if q_tf else 1
        q_vector = {term: (q_tf.get(term, 0) / q_max) * self._idf.get(term, 1) for term in self._vocab if term in q_tf}

        scores = []
        for i, doc_tf in enumerate(self._tf_matrix):
            score = sum(q_vector.get(term, 0) * doc_tf.get(term, 0) for term in q_vector)
            scores.append((i, score))

        scores.sort(key=lambda x: x[1], reverse=True)
        results = []
        for i, score in scores[:top_k]:
            if score > 0:
                doc = dict(self._documents[i])
                doc["relevance_score"] = round(score, 4)
                results.append(doc)
        return results


_search_engine = TFIDFSearch()


def _build_index_from_db():
    """Build TF-IDF index from all circulars and rules in the database."""
    conn = get_connection()
    documents = []

    # Load circulars
    try:
        circs = conn.execute(
            "SELECT id, circular_number, subject_line, body_text, department_code, issue_date FROM circulars"
        ).fetchall()
        for c in circs:
            d = dict(c)
            documents.append({
                "id": f"circular_{d['id']}",
                "title": f"{d['circular_number']}: {d.get('subject_line', '')}",
                "text": (d.get("body_text", "") or "") + " " + (d.get("subject_line", "") or ""),
                "type": "circular",
                "ref_id": d["id"],
                "department": d.get("department_code", ""),
                "date": d.get("issue_date", ""),
            })
    except Exception:
        pass

    # Load rules
    try:
        rules = conn.execute("SELECT id, pattern, category, action, description FROM compliance_rules").fetchall()
        for r in rules:
            d = dict(r)
            documents.append({
                "id": f"rule_{d['id']}",
                "title": f"Rule: {d.get('pattern', '')}",
                "text": (d.get('description', '') or '') + ' ' + (d.get('category', '') or ''),
                "type": "rule",
                "ref_id": d["id"],
                "category": d.get("category", ""),
                "action": d.get("action", ""),
            })
    except Exception:
        pass

    conn.close()
    _search_engine.build_index(documents)
    return len(documents)


def query(query_text: str, top_k: int = 5) -> dict:
    """Query the knowledge base. Returns relevant documents."""
    _build_index_from_db()
    results = _search_engine.search(query_text, top_k)
    return {
        "query": query_text,
        "results": results,
        "total_found": len(results),
        "answer": _format_answer(query_text, results),
    }


def _format_answer(query: str, results: list) -> str:
    if not results:
        return "I couldn't find any relevant information in the knowledge base."
    lines = [f"Found {len(results)} relevant result(s):"]
    for r in results:
        lines.append(f"\n  [{r['type'].upper()}] {r['title']}")
        if r.get("department"):
            lines.append(f"  Department: {r['department']}")
        if r.get("date"):
            lines.append(f"  Date: {r['date']}")
        lines.append(f"  Relevance: {r.get('relevance_score', 0)*100:.1f}%")
    return "\n".join(lines)


def get_answer(question: str) -> str:
    """Simple Q&A using keyword matching for common questions."""
    question_lower = question.lower()

    if "how many" in question_lower or "count" in question_lower:
        conn = get_connection()
        circs = conn.execute("SELECT count(*) FROM circulars").fetchone()[0]
        maps = conn.execute("SELECT count(*) FROM maps").fetchone()[0]
        conn.close()
        return f"Currently there are {circs} circulars and {maps} action plans in the system."

    if "latest" in question_lower or "recent" in question_lower or "new" in question_lower:
        conn = get_connection()
        rows = conn.execute(
            "SELECT circular_number, subject_line, issue_date FROM circulars ORDER BY issue_date DESC LIMIT 5"
        ).fetchall()
        conn.close()
        if not rows:
            return "No circulars found."
        lines = ["Latest 5 circulars:"]
        for r in rows:
            lines.append(f"  • {r['circular_number']}: {r['subject_line'][:80]} ({r['issue_date']})")
        return "\n".join(lines)

    # Fallback to TF-IDF search
    result = query(question)
    return result["answer"]


def ensure_assistant_tables():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS knowledge_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query TEXT NOT NULL,
            answer TEXT,
            result_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS compliance_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT NOT NULL,
            category TEXT DEFAULT '',
            action TEXT DEFAULT '',
            description TEXT DEFAULT '',
            severity TEXT DEFAULT 'MEDIUM',
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    conn.close()


def store_knowledge_query(query: str, answer: str, result_count: int):
    conn = get_connection()
    conn.execute(
        "INSERT INTO knowledge_queries (query, answer, result_count) VALUES (?, ?, ?)",
        (query, answer, result_count),
    )
    conn.commit()
    conn.close()


def seed_default_rules():
    """Seed default RBI pattern rules."""
    conn = get_connection()
    existing = conn.execute("SELECT count(*) FROM compliance_rules").fetchone()[0]
    if existing > 0:
        conn.close()
        return

    default_rules = [
        ("within \\d+ days?", "deadline", "parse_deadline", "Days-based compliance deadline", "HIGH"),
        ("effective immediately", "deadline", "immediate_action", "Immediate compliance required", "CRITICAL"),
        ("shall ensure", "obligation", "mandatory_action", "Mandatory compliance obligation", "HIGH"),
        ("must report", "reporting", "reporting_obligation", "Reporting requirement", "HIGH"),
        ("quarterly", "periodicity", "quarterly_report", "Quarterly reporting requirement", "MEDIUM"),
        ("annually", "periodicity", "annual_report", "Annual reporting requirement", "MEDIUM"),
        ("within (a )?fortnight", "deadline", "fortnight_deadline", "14-day compliance deadline", "MEDIUM"),
        ("within (a )?month", "deadline", "monthly_deadline", "30-day compliance deadline", "MEDIUM"),
        ("with immediate effect", "deadline", "immediate_action", "Immediate compliance required", "CRITICAL"),
        ("supersedes", "supersession", "override_detection", "This circular supersedes a previous one", "HIGH"),
        ("replaces", "supersession", "override_detection", "This circular replaces a previous one", "HIGH"),
        ("KYC|know your customer", "category", "kyc_compliance", "KYC-related compliance requirement", "HIGH"),
        ("AML|anti.money laundering", "category", "aml_compliance", "AML compliance requirement", "HIGH"),
        ("cyber|information security|IT system", "category", "cyber_compliance", "Cybersecurity compliance requirement", "CRITICAL"),
        ("fraud|fraudulent", "category", "fraud_prevention", "Fraud prevention requirement", "CRITICAL"),
        ("UPI|payment system|digital payment", "category", "payments_compliance", "Payments system compliance", "HIGH"),
        ("interest rate|repo rate|policy rate", "category", "monetary_policy", "Monetary policy compliance", "MEDIUM"),
        ("capital|basel|capital adequacy", "category", "capital_compliance", "Capital adequacy requirement", "HIGH"),
        ("reporting|submit report|file report", "reporting", "regulatory_reporting", "Regulatory reporting obligation", "HIGH"),
        ("penalty|fine|penal interest", "penalty", "penalty_provision", "Penalty provision for non-compliance", "CRITICAL"),
    ]
    for pattern, cat, action, desc, severity in default_rules:
        conn.execute(
            "INSERT INTO compliance_rules (pattern, category, action, description, severity) VALUES (?, ?, ?, ?, ?)",
            (pattern, cat, action, desc, severity),
        )
    conn.commit()
    conn.close()
    logger.info(f"Seeded {len(default_rules)} default compliance rules")
