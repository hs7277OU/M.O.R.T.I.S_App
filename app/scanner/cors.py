import requests
from .risk import make_finding

def check_cors(url: str, timeout: int = 8) -> list[dict]:
    findings = []
    evil_origin = "https://evil.example"
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True, headers={"Origin": evil_origin, "User-Agent": "MORTIS-PROTOTYPE/1.0"})
    except requests.RequestException as exc:
        return [make_finding("CORS", "CORS check failed", "Medium", str(exc), "Confirm the target is reachable and retry.")]

    acao = response.headers.get("Access-Control-Allow-Origin", "")
    acac = response.headers.get("Access-Control-Allow-Credentials", "")
    if acao == "*":
        findings.append(make_finding("CORS", "Wildcard CORS policy", "Medium", "Access-Control-Allow-Origin is set to *, which may expose responses to any origin.", "Restrict CORS to trusted origins only.",
                                     cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"))
    if acao == evil_origin and acac.lower() == "true":
        findings.append(make_finding("CORS", "Reflected origin with credentials", "High", "The application reflected an untrusted Origin and allows credentials.", "Use an allow-list of trusted origins and avoid credentialed wildcard/reflected CORS.",
                                     cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"))
    if not findings:
        findings.append(make_finding("CORS", "No obvious CORS misconfiguration detected", "Info", "The initial response did not expose a risky CORS configuration.", "Review authenticated/API endpoints separately during deeper testing."))
    return findings
