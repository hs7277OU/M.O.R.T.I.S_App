from app.scanner.risk import make_finding


def test_findings_are_sorted_by_severity_score():
    findings = [
        make_finding("Cookie Audit", "Missing SameSite", "Low", "desc", "rec"),
        make_finding("Headers", "Missing CSP", "Medium", "desc", "rec"),
        make_finding("TLS", "Expired certificate", "Critical", "desc", "rec"),
        make_finding("Injection", "SQL error disclosure", "High", "desc", "rec"),
    ]

    sorted_findings = sorted(
        findings,
        key=lambda finding: finding.get("score", 0),
        reverse=True
    )

    severities = [finding["severity"] for finding in sorted_findings]

    assert severities == ["Critical", "High", "Medium", "Low"]