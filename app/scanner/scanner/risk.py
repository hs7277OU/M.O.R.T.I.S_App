SEVERITY_SCORES = {
    "Info": 0,
    "Low": 2,
    "Medium": 5,
    "High": 8,
    "Critical": 10,
}

def score_finding(severity: str) -> int:
    return SEVERITY_SCORES.get(severity, 0)

# --- CVSS v3.1 base score calculator -----------------------------------
# Standard base-metric weights from the CVSS v3.1 specification. Privileges
# Required (PR) is the one metric whose weight also depends on Scope (S).
_CVSS_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}

_CVSS_RATING_BANDS = (
    (9.0, "Critical"), (7.0, "High"), (4.0, "Medium"), (0.1, "Low"), (0.0, "None"),
)


def _cvss_roundup(value: float) -> float:
    """CVSS 'round up to nearest 0.1' as defined by the spec (avoids float drift)."""
    int_value = round(value * 100000)
    if int_value % 10000 == 0:
        return int_value / 100000
    return (int_value // 10000 + 1) / 10.0


def cvss_rating_for_score(score: float) -> str:
    for threshold, label in _CVSS_RATING_BANDS:
        if score >= threshold:
            return label
    return "None"


def cvss_base_score(vector: str) -> tuple[float, str]:
    """Compute the CVSS v3.1 base score/rating from a vector string like
    'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N'. Returns (score, qualitative rating).
    """
    metrics = dict(part.split(":") for part in vector.split("/") if ":" in part)
    scope = metrics.get("S", "U")

    av = _CVSS_WEIGHTS["AV"][metrics["AV"]]
    ac = _CVSS_WEIGHTS["AC"][metrics["AC"]]
    pr = _CVSS_WEIGHTS["PR"]["C" if scope == "C" else "U"][metrics["PR"]]
    ui = _CVSS_WEIGHTS["UI"][metrics["UI"]]
    c = _CVSS_WEIGHTS["C"][metrics["C"]]
    i = _CVSS_WEIGHTS["I"][metrics["I"]]
    a = _CVSS_WEIGHTS["A"][metrics["A"]]

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base_score = 0.0
    elif scope == "U":
        base_score = _cvss_roundup(min(impact + exploitability, 10))
    else:
        base_score = _cvss_roundup(min(1.08 * (impact + exploitability), 10))

    return base_score, cvss_rating_for_score(base_score)

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
