from beesint_threat_report.transform.breaches import severity_bucket


def test_severity_bucket_critical_when_passwords_exposed():
    assert severity_bucket(["Email addresses", "Passwords"]) == "CRITICAL"


def test_severity_bucket_high_when_physical_addresses_exposed_without_critical_data():
    assert severity_bucket(["Email addresses", "Physical addresses"]) == "HIGH"


def test_severity_bucket_medium_when_only_low_sensitivity_data_exposed():
    assert severity_bucket(["Email addresses", "Usernames"]) == "MEDIUM"


def test_severity_bucket_low_when_no_data_classes():
    assert severity_bucket([]) == "LOW"


def test_severity_bucket_critical_takes_priority_over_high():
    assert severity_bucket(["Physical addresses", "Passwords"]) == "CRITICAL"
