"""
Phantom Compliance — Compliance Knowledge Graph
Builds dynamic D3.js-compatible knowledge graphs from compliance data.
"""

import logging
import re
from utils.database import get_connection

logger = logging.getLogger("phantom_compliance.knowledge_graph")

def ensure_graph_tables():
    pass

def build_graph_for_circular(circular_id: int) -> dict:
    conn = get_connection()
    circular = conn.execute("SELECT * FROM circulars WHERE id=?", (circular_id,)).fetchone()
    if not circular:
        conn.close()
        return {"nodes": [], "edges": []}
    nodes = []
    edges = []
    circ_node = {
        "id": f"circular-{circular['id']}",
        "label": circular.get("title", f"Circular #{circular['id']}"),
        "type": "circular",
        "group": 1,
        "status": circular.get("status", "unknown"),
    }
    nodes.append(circ_node)
    maps = conn.execute("SELECT * FROM maps WHERE circular_id=?", (circular_id,)).fetchall()
    for m in maps:
        map_id = f"map-{m['id']}"
        nodes.append({
            "id": map_id,
            "label": f"MAP #{m['id']}",
            "type": "policy",
            "group": 2,
            "status": m.get("status", "unknown"),
        })
        edges.append({"source": circ_node["id"], "target": map_id, "relationship": "maps_to"})
        dept_code = m.get("department_code")
        if dept_code:
            dept_id = f"team-{dept_code}"
            nodes.append({
                "id": dept_id,
                "label": f"Dept: {dept_code}",
                "type": "team",
                "group": 4,
                "status": "active",
            })
            edges.append({"source": map_id, "target": dept_id, "relationship": "assigned_to"})
    inspections = conn.execute(
        "SELECT * FROM inspection_packages WHERE circular_id=?", (circular_id,)
    ).fetchall()
    for insp in inspections:
        insp_id = f"inspection-{insp['id']}"
        nodes.append({
            "id": insp_id,
            "label": f"Inspection #{insp['id']}",
            "type": "evidence",
            "group": 5,
            "status": insp.get("status", "unknown"),
        })
        edges.append({"source": circ_node["id"], "target": insp_id, "relationship": "inspected_by"})
    conn.close()
    return {"nodes": nodes, "edges": edges}

def get_graph_for_department(dept_code: str) -> dict:
    conn = get_connection()
    maps = conn.execute(
        "SELECT * FROM maps WHERE department_code=?", (dept_code,)
    ).fetchall()
    nodes = []
    edges = []
    seen = set()
    for m in maps:
        map_id = f"map-{m['id']}"
        if map_id not in seen:
            seen.add(map_id)
            nodes.append({
                "id": map_id,
                "label": f"MAP #{m['id']}",
                "type": "policy",
                "group": 2,
                "status": m.get("status", "unknown"),
            })
        dept_id = f"team-{dept_code}"
        if dept_id not in seen:
            seen.add(dept_id)
            nodes.append({
                "id": dept_id,
                "label": f"Dept: {dept_code}",
                "type": "team",
                "group": 4,
                "status": "active",
            })
        edges.append({"source": map_id, "target": dept_id, "relationship": "assigned_to"})
        circ_id = m.get("circular_id")
        if circ_id:
            circ_key = f"circular-{circ_id}"
            if circ_key not in seen:
                seen.add(circ_key)
                circ = conn.execute("SELECT * FROM circulars WHERE id=?", (circ_id,)).fetchone()
                if circ:
                    nodes.append({
                        "id": circ_key,
                        "label": circ.get("title", f"Circular #{circ_id}"),
                        "type": "circular",
                        "group": 1,
                        "status": circ.get("status", "unknown"),
                    })
            edges.append({"source": circ_key, "target": map_id, "relationship": "maps_to"})
    conn.close()
    return {"nodes": nodes, "edges": edges}

def answer_graph_query(query: str) -> dict:
    conn = get_connection()
    q = query.lower()
    result = {"query": query, "interpretation": "", "paths": []}
    if "kyc" in q and ("rbi" in q or "change" in q):
        result["interpretation"] = "Systems impacted by KYC rule changes"
        policies = conn.execute(
            "SELECT * FROM maps WHERE title LIKE '%KYC%' OR description LIKE '%KYC%'"
        ).fetchall()
        for p in policies:
            circ = conn.execute("SELECT * FROM circulars WHERE id=?", (p["circular_id"],)).fetchone()
            result["paths"].append({
                "regulated_system": f"MAP #{p['id']}",
                "circular": circ["title"] if circ else "Unknown",
                "impact": "KYC verification systems, customer onboarding workflows, document management",
                "recommendation": "Review MAP implementation for KYC updates"
            })
    elif "data" in q and ("local" in q or "protection" in q):
        result["interpretation"] = "Systems impacted by data localization requirements"
        result["paths"].append({
            "regulated_system": "Data Storage Infrastructure",
            "circular": "Data Localization Policy",
            "impact": "Data residency, cross-border transfer mechanisms, cloud infrastructure",
            "recommendation": "Audit data storage locations and update data residency policies"
        })
    else:
        result["interpretation"] = "General compliance graph query"
        result["paths"].append({
            "regulated_system": "Entire compliance framework",
            "circular": "All active circulars",
            "impact": "Cross-cutting compliance obligations",
            "recommendation": "Review all MAPs for completeness"
        })
    conn.close()
    return result
