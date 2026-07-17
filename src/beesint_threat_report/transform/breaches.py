from __future__ import annotations

# Portée depuis beesint-jobs/src/beesint_jobs/jobs/format_c.py::_severity() — mêmes sets
# CRITICAL/HIGH (cf. CDC Phase P5), sans les emoji du post social (ce rapport n'a pas la
# contrainte de longueur d'un post réseau social).
_CRITICAL_DATA_CLASSES = {
    "Passwords",
    "Credit cards",
    "Bank account numbers",
    "Social security numbers",
    "PIN numbers",
    "Partial credit card data",
    "CVV numbers",
}
_HIGH_DATA_CLASSES = {
    "Health records",
    "Medical records",
    "Physical addresses",
    "Private messages",
    "Government issued IDs",
    "Financial transactions",
    "Tax records",
}


def severity_bucket(data_classes: list[str]) -> str:
    """CRITICAL (au moins une donnée financière/identité) > HIGH (au moins une donnée sensible
    non-financière) > MEDIUM (des data_classes existent mais aucune n'est critique/haute) > LOW
    (aucune donnée exposée connue)."""
    classes = set(data_classes)
    if classes & _CRITICAL_DATA_CLASSES:
        return "CRITICAL"
    if classes & _HIGH_DATA_CLASSES:
        return "HIGH"
    if data_classes:
        return "MEDIUM"
    return "LOW"
