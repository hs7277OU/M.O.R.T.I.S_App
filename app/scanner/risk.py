SEVERITY_SCORES = {
    "Info": 0,
    "Low": 2,
    "Medium": 5,
    "High": 8,
    "Critical": 10,
}

def score_finding(severity: str) -> int:
    return SEVERITY_SCORES.get(severity, 0)

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

def make_finding(module: str, title: str, severity: str, description: str, recommendation: str) -> dict:
    return {
        "module": module,
        "title": title,
        "severity": severity,
        "score": score_finding(severity),
        "description": description,
        "recommendation": recommendation,
    }
