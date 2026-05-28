import requests
from .risk import make_finding

def check_cookies(url: str, timeout: int = 8) -> list[dict]:
    findings = []
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent": "MORTIS-PROTOTYPE/1.0"})
    except requests.RequestException as exc:
        return [make_finding("Cookie Audit", "Cookie check failed", "Medium", str(exc), "Confirm the target is reachable and retry.")]

    raw_cookies = response.headers.getlist("Set-Cookie") if hasattr(response.headers, "getlist") else response.headers.get("Set-Cookie", "")
    if isinstance(raw_cookies, str):
        raw_cookies = [raw_cookies] if raw_cookies else []

    if not raw_cookies:
        return [make_finding("Cookie Audit", "No cookies observed", "Info", "No Set-Cookie headers were observed on the initial response.", "No action required unless authenticated areas use cookies that need review.")]

    for cookie in raw_cookies:
        name = cookie.split("=", 1)[0]
        lower = cookie.lower()
        if "httponly" not in lower:
            findings.append(make_finding("Cookie Audit", f"Cookie {name} missing HttpOnly", "Medium", "A cookie was set without the HttpOnly flag, increasing script access risk.", "Set HttpOnly on session or sensitive cookies."))
        if url.startswith("https://") and "secure" not in lower:
            findings.append(make_finding("Cookie Audit", f"Cookie {name} missing Secure", "Medium", "A cookie on an HTTPS site was set without Secure.", "Set Secure so the cookie is only sent over HTTPS."))
        if "samesite" not in lower:
            findings.append(make_finding("Cookie Audit", f"Cookie {name} missing SameSite", "Low", "A cookie was set without a SameSite attribute.", "Set SameSite=Lax or SameSite=Strict where appropriate."))
    return findings
