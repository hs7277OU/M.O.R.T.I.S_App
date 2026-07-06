from app.scanner.access import check_access_control, COMMON_PATHS


def test_returns_info_finding_when_unreachable():
    # An unroutable target yields no 200s, so we expect the reassuring Info item.
    findings = check_access_control("http://localhost:1", timeout=1)
    assert findings
    assert findings[-1]["severity"] == "Info"
    assert findings[-1]["module"] == "Access Control"


def test_common_paths_are_defined():
    assert "/admin" in COMMON_PATHS
    assert "/.env" in COMMON_PATHS
