from app.scanner.risk import make_finding, overall_rating

def test_overall_rating_uses_highest_finding():
    findings = [
        make_finding("Test", "Low item", "Low", "desc", "rec"),
        make_finding("Test", "High item", "High", "desc", "rec"),
    ]
    score, rating = overall_rating(findings)
    assert score == 8
    assert rating == "High"

def test_make_finding_returns_expected_dictionary():
    finding = make_finding(
        "Security Headers",
        "Missing CSP",
        "Medium",
        "Content-Security-Policy header is missing",
        "Add a suitable Content-Security-Policy header"
    )

    assert finding["category"] == "Security Headers"
    assert finding["title"] == "Missing CSP"
    assert finding["severity"] == "Medium"
    assert finding["description"] == "Content-Security-Policy header is missing"
    assert finding["recommendation"] == "Add a suitable Content-Security-Policy header"