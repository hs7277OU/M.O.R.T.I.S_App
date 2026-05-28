from bs4 import BeautifulSoup
import requests
from urllib.parse import urljoin
from .risk import make_finding

SQLI_PAYLOADS = ["'", "' OR '1'='1", "\" OR \"1\"=\"1"]
SQL_ERRORS = ["sql syntax", "mysql", "sqlite", "postgresql", "odbc", "ora-"]

def check_basic_injection(url: str, timeout: int = 8) -> list[dict]:
    findings = []
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent": "MORTIS-PROTOTYPE/1.0"})
    except requests.RequestException as exc:
        return [make_finding("Injection", "Injection check failed", "Medium", str(exc), "Confirm the target is reachable and retry.")]

    soup = BeautifulSoup(response.text, "html.parser")
    forms = soup.find_all("form")
    if not forms:
        return [make_finding("Injection", "No forms found on initial page", "Info", "No HTML forms were found on the landing page.", "Use deeper crawling later to identify input points across the application.")]

    for form in forms[:3]:
        action = urljoin(url, form.get("action") or url)
        method = (form.get("method") or "get").lower()
        inputs = [i.get("name") for i in form.find_all(["input", "textarea"]) if i.get("name")]
        if not inputs:
            continue
        payload_data = {name: SQLI_PAYLOADS[0] for name in inputs}
        try:
            if method == "post":
                test_response = requests.post(action, data=payload_data, timeout=timeout)
            else:
                test_response = requests.get(action, params=payload_data, timeout=timeout)
            body = test_response.text.lower()
            if any(error in body for error in SQL_ERRORS):
                findings.append(make_finding("Injection", "Possible SQL error disclosure", "High", "A basic SQL-style payload appeared to trigger database error text.", "Use parameterised queries, server-side validation and generic error handling."))
        except requests.RequestException:
            continue

    if not findings:
        findings.append(make_finding("Injection", "Basic injection smoke test completed", "Info", "No obvious SQL error disclosure was found using limited non-destructive probes.", "Perform deeper authorised testing against known input points."))
    return findings
