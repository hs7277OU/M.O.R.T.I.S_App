SECURITY_HEADERS = {
 "Content-Security-Policy": "Helps reduce cross-site scripting and content injection risk.",
 "Strict-Transport-Security": "Forces browsers to use HTTPS for future requests.",
 "X-Frame-Options": "Helps prevent clickjacking by controlling iframe embedding.",
 "X-Content-Type-Options": "Prevents MIME-type sniffing when set to nosniff.",
 "Referrer-Policy": "Controls how much referrer information is shared.",
}

def check_security_headers(url: str, timeout: int = 8) -> list[dict]:
    findings = []
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent": "MORTIS-MVP/1.0"})
    except requests.RequestException as exc:
        return [make_finding("Security Headers", "Target could not be reached", "Medium", str(exc), "Confirm the URL is correct and reachable from this machine.")]
    
    headers = response.headers
    for header, purpose in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append(make_finding(
                "Security Headers",
                f"Missing {header}",
                "Medium" if header in {"Content-Security-Policy", "Strict-Transport-Security"} else "Low",
                f"The response does not include {header}. {purpose}",
                f"Configure the web server/application to send a suitable {header} value."
            ))
    server = headers.get("Server", "")

    if server:
        findings.append(make_finding(
            "Security Headers",
            "Server header reveals technology information",
            "Low",
            f"The Server header is present: {server}. This can reveal platform details to attackers.",
            "Reduce or remove version/banner information where possible."
        ))
    return findings 