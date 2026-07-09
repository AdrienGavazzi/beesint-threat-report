from __future__ import annotations

# ponytail: noms des CWE les plus fréquents dans les feeds NVD (OWASP Top 25) — pas de base
# MITRE complète embarquée, fallback sur l'id brut si absent de la table.
_CWE_NAMES: dict[str, str] = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-Site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-119": "Buffer Overflow",
    "CWE-120": "Buffer Copy Without Checking Size of Input",
    "CWE-125": "Out-of-Bounds Read",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-269": "Improper Privilege Management",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-287": "Improper Authentication",
    "CWE-284": "Improper Access Control",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-362": "Race Condition",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-416": "Use After Free",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-611": "Improper Restriction of XML External Entity Reference",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-787": "Out-of-Bounds Write",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-843": "Type Confusion",
    "CWE-863": "Incorrect Authorization",
    "CWE-918": "Server-Side Request Forgery",
    "NVD-CWE-Other": "Other / Unclassified",
    "NVD-CWE-noinfo": "Insufficient Information",
}


def cwe_name(cwe_id: str | None) -> str:
    if not cwe_id:
        return "Unclassified"
    return _CWE_NAMES.get(cwe_id, cwe_id)
