from __future__ import annotations

# ponytail: mapping fait à la main (pas de fetch du bundle STIX complet — vérifié 47 Mo pour
# un besoin de ~20 lignes, largement disproportionné) — même esprit que cwe_names.py : pas de
# base MITRE complète embarquée, fallback liste vide si la famille n'est pas dans la table.
# Techniques sourcées manuellement depuis les pages Software de attack.mitre.org (comportement
# de delivery/C2 le plus caractéristique de chaque famille, pas exhaustif).
_MALWARE_TECHNIQUES: dict[str, list[str]] = {
    "emotet": ["T1071.001", "T1105", "T1204.002"],
    "qakbot": ["T1071.001", "T1105", "T1547.001"],
    "icedid": ["T1071.001", "T1105"],
    "trickbot": ["T1071.001", "T1105", "T1055"],
    "dridex": ["T1071.001", "T1204.002"],
    "asyncrat": ["T1071.001", "T1573"],
    "remcos": ["T1071.001", "T1547.001"],
    "nanocore": ["T1071.001", "T1547.001"],
    "njrat": ["T1071.001", "T1547.001"],
    "cobalt strike": ["T1071.001", "T1055", "T1059.001"],
    "bazarloader": ["T1071.001", "T1105"],
    "gozi": ["T1071.001", "T1055"],
    "darkcomet": ["T1071.001", "T1547.001"],
    "redlinestealer": ["T1071.001", "T1555"],
    "agenttesla": ["T1071.001", "T1056.001"],
    "formbook": ["T1071.001", "T1055"],
    "lokibot": ["T1071.001", "T1555"],
}

# Alias : même famille, nom différent selon la source ou l'époque (ex. FeodoTracker a
# historiquement appelé Emotet "Heodo") — jamais de doublon d'entrée dans la table ci-dessus.
_MALWARE_ALIASES: dict[str, str] = {
    "heodo": "emotet",
    "qbot": "qakbot",
    "ursnif": "gozi",
}


def mitre_technique_ids(malware: str | None) -> list[str]:
    if not malware:
        return []
    key = malware.strip().lower()
    key = _MALWARE_ALIASES.get(key, key)
    return _MALWARE_TECHNIQUES.get(key, [])
