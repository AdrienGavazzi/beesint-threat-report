from beesint_threat_report.load.mitre_attack_map import mitre_technique_ids


def test_known_family_returns_techniques():
    assert mitre_technique_ids("Emotet") == ["T1071.001", "T1105", "T1204.002"]


def test_alias_resolves_to_canonical_family():
    assert mitre_technique_ids("Heodo") == mitre_technique_ids("Emotet")
    assert mitre_technique_ids("Qbot") == mitre_technique_ids("QakBot")


def test_case_and_whitespace_insensitive():
    assert mitre_technique_ids("  EMOTET  ") == mitre_technique_ids("emotet")


def test_unknown_family_returns_empty_list():
    assert mitre_technique_ids("SomeBrandNewMalware2027") == []


def test_none_or_empty_returns_empty_list():
    assert mitre_technique_ids(None) == []
    assert mitre_technique_ids("") == []
