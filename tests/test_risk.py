from app.scanner.risk import make_finding, overall_rating, score_finding

def test_score_finding_returns_expected_scores():
    assert score_finding("Info") == 0
    assert score_finding("Low") == 2
    assert score_finding("Medium") == 5
    assert score_finding("High") == 8
    assert score_finding("Critical") == 10

def test_unknown_severity_scores_zero():
    assert score_finding("Unknown") == 0

def test_overall_rating_with_no_findings_is_low():
    score, rating = overall_rating([])
    assert score == 0
    assert rating == "Low"

def test_overall_rating_with_only_info_findings():
    findings = [
        make_finding("Test", "Info item", "Info", "desc", "rec")
    ]
    score, rating = overall_rating(findings)
    assert score == 0
    assert rating == "Info"

def test_overall_rating_uses_highest_finding():
    findings = [
        make_finding("Test", "Low item", "Low", "desc", "rec"),
        make_finding("Test", "High item", "High", "desc", "rec"),
    ]
    score, rating = overall_rating(findings)
    assert score == 8
    assert rating == "High"

