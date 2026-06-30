"""
PDF parsing wrapper using PyMuPDF (fitz).
Extracts text from RBI circular PDFs for downstream processing.
"""

import fitz


def extract_text_from_pdf(pdf_path: str) -> str:
    """Extract all text from a PDF file using PyMuPDF."""
    doc = fitz.open(pdf_path)
    text_parts = []
    for page_num in range(len(doc)):
        page = doc.load_page(page_num)
        text_parts.append(page.get_text())
    doc.close()
    return "\n".join(text_parts)


def extract_circular_metadata(text: str) -> dict:
    """
    Extract circular metadata using regex BEFORE LLM processing.
    Returns: {circular_number, department_code, date, addressee, subject}
    """
    import re

    meta = {
        "circular_number": "",
        "department_code": "",
        "issue_date": "",
        "addressee": "",
        "subject_line": "",
    }

    patterns = {
        "circular_number": r"(?:Circular\s*(?:No|Number|\.)?\s*[:\-#]?\s*)([\w./-]+)",
        "department_code": r"(DOR\.AML|CO\.DPSS|DoS\.CO|DBR\.BP|A\.P\.DIR|DOR\.STR|DOR|CO|DoS|DBR|A\.P)",
        "issue_date": r"(\d{1,2}\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4})",
        "addressee": r"(?:To\s*[:\-]?\s*)(.*?)(?:\n|$)",
        "subject_line": r"(?:Madam|Sir|Sub[:\-]?\s*)(.*?)(?:\n|$)",
    }

    for key, pat in patterns.items():
        m = re.search(pat, text, re.IGNORECASE | re.MULTILINE)
        if m:
            meta[key] = m.group(1).strip() if key != "subject_line" else m.group(1).strip()
        elif key == "department_code":
            for code in ["DOR.AML", "CO.DPSS", "DoS.CO", "DBR.BP", "A.P.DIR", "DOR.STR"]:
                if code in text:
                    meta[key] = code
                    break

    return meta
