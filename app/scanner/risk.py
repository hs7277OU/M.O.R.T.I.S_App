from cvss import CVSS4

SEVERITY_SCORES = {
    "Info": 0,
    "Low": 2,
    "Medium": 5,
    "High": 8,
    "Critical": 10,
}

def score_finding(severity: str) -> int:
    return SEVERITY_SCORES.get(severity, 0)

# --- CVSS v4.0 base score --------------------------------------------------
# Scoring is delegated to the maintained `cvss` library rather than hand-rolled,
# so results match the official CVSS v4.0 reference implementation.


def cvss_base_score(vector: str) -> tuple[float, str]:
    """Compute the CVSS v4.0 base score and qualitative rating from a vector
    string such as
    'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N'.
    Returns (score, rating).
    """
    metrics = CVSS4(vector)
    return metrics.base_score, metrics.severity

def overall_rating(findings: list[dict]) -> tuple[int, str]:
    if not findings:
        return 0, "Low"
    max_score = max(f.get("score", 0) for f in findings)
    if max_score >= 10:
        return max_score, "Critical"
    if max_score >= 8:
        return max_score, "High"
    if max_score >= 5:
        return max_score, "Medium"
    if max_score >= 2:
        return max_score, "Low"
    return max_score, "Info"

def make_finding(module: str, title: str, severity: str, description: str, recommendation: str,
                  cvss_vector: str | None = None) -> dict:
    finding = {
        "module": module,
        "title": title,
        "severity": severity,
        "score": score_finding(severity),
        "description": description,
        "recommendation": recommendation,
    }
    if cvss_vector:
        cvss_score, cvss_rating = cvss_base_score(cvss_vector)
        finding["cvss_vector"] = cvss_vector
        finding["cvss_score"] = cvss_score
        finding["cvss_rating"] = cvss_rating
    return finding
