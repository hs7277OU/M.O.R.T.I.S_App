"""Broken Access Control checks (OWASP A01).

A deliberately lightweight, non-destructive probe for common sensitive paths
that should not be reachable without authentication. It only issues GET
requests and never attempts to exploit anything.
"""
import requests
from .risk import make_finding

COMMON_PATHS = [
    "/admin",
    "/administrator",
    "/.git/config",
    "/.env",
    "/backup",
    "/config.php",
    "/server-status",
    "/phpinfo.php",
]


def check_access_control(url: str, timeout: int = 8) -> list[dict]:
    findings = []
    for path in COMMON_PATHS:
        try:
            response = requests.get(
                url + path,
                timeout=timeout,
                allow_redirects=False,
                headers={"User-Agent": "MORTIS-PROTOTYPE/1.0"},
            )
        except requests.RequestException:
            continue
        if response.status_code == 200:
            findings.append(make_finding(
                "Access Control",
                f"Sensitive path reachable without authentication: {path}",
                "High",
                f"{path} returned HTTP 200 without requiring authentication.",
                "Restrict access, require authentication, or remove the resource.",
            ))

    if not findings:
        findings.append(make_finding(
            "Access Control",
            "No common sensitive paths exposed",
            "Info",
            "No default admin/config paths were reachable without authentication.",
            "Confirm object-level authorisation (IDOR) during deeper authorised testing.",
        ))
    return findings
