from app.reporting import generate_report, _local_summary


def _findings():
    return [
        {"title": "Missing CSP", "severity": "Medium", "score": 5,
         "description": "No CSP header.", "recommendation": "Add a CSP header."},
    ]


def test_local_summary_lists_risky_findings():
    text = _local_summary("https://example.com", _findings(), "Medium")
    assert "Missing CSP" in text
    assert "review" in text.lower()


def test_generate_report_falls_back_to_local_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    text = generate_report("https://example.com", _findings(), "Medium")
    assert "example.com" in text
