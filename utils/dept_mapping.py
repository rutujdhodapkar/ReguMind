"""
Mapping of RBI department codes to internal bank departments.
Used by the Routing Agent to assign MAPs correctly.
"""

RBI_TO_BANK_DEPT = {
    "DOR.AML": "KYC",
    "CO.DPSS": "Payments",
    "DoS.CO": "IT_Security",
    "DBR.BP": "Treasury",
    "A.P.DIR": "Forex",
    "DOR.STR": "Credit_Risk",
    "DOR": "KYC",
    "CO": "Payments",
    "DoS": "IT_Security",
    "DBR": "Treasury",
    "A.P": "Forex",
}

DEPT_DISPLAY_NAMES = {
    "KYC": "KYC / Compliance",
    "Payments": "Payments / IT",
    "IT_Security": "IT Security / Audit",
    "Treasury": "Treasury / Risk",
    "Forex": "Forex / Treasury",
    "Credit_Risk": "Credit / Stressed Assets",
}


def map_department(rbi_code: str) -> str:
    """Map an RBI department code to an internal bank department role."""
    internal = {dept.upper(): dept for dept in DEPT_DISPLAY_NAMES}
    normalized = (rbi_code or "").strip()
    if normalized.upper() in internal:
        return internal[normalized.upper()]
    if rbi_code in RBI_TO_BANK_DEPT:
        return RBI_TO_BANK_DEPT[rbi_code]
    for prefix, dept in RBI_TO_BANK_DEPT.items():
        if normalized.startswith(prefix):
            return dept
    return "KYC"


def get_display_name(dept_role: str) -> str:
    return DEPT_DISPLAY_NAMES.get(dept_role, dept_role)
