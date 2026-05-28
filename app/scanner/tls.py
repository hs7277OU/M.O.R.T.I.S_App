import socket
import ssl
from datetime import datetime, timezone
from .utils import hostname_from_url
from .risk import make_finding

def check_tls(url: str, timeout: int = 8) -> list[dict]:
    findings = []
    if not url.startswith("https://"):
        return [make_finding("SSL/TLS", "Target is not using HTTPS", "High", "The target URL uses HTTP rather than HTTPS.", "Enable HTTPS and redirect HTTP traffic to HTTPS.")]

    host = hostname_from_url(url)
    if not host:
        return [make_finding("SSL/TLS", "Could not determine hostname", "Medium", "The scanner could not extract a hostname from the URL.", "Check the submitted URL.")]
    
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()
    except Exception as exc:
        return [make_finding("SSL/TLS", "TLS handshake or certificate validation failed", "High", str(exc), "Check certificate validity, hostname matching, trust chain and TLS configuration.")]
    
    not_after = cert.get("notAfter")
    if not_after:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expiry - datetime.now(timezone.utc)).days
        if days_left < 0:
            findings.append(make_finding("SSL/TLS", "TLS certificate has expired", "Critical", f"The certificate expired {abs(days_left)} days ago.", "Renew and deploy a valid certificate immediately."))
    elif days_left < 30:
        findings.append(make_finding("SSL/TLS", "TLS certificate expires soon", "Medium", f"The certificate expires in {days_left} days.", "Renew the certificate before expiry."))

    if tls_version in {"TLSv1", "TLSv1.1"}:
        findings.append(make_finding("SSL/TLS", f"Outdated TLS version supported: {tls_version}", "High", "An outdated TLS  protocol was negotiated.", "Disable TLS 1.0/1.1 and require TLS 1.2+ or TLS 1.3."))
    if not findings:
        findings.append(make_finding("SSL/TLS", "TLS certificate appears valid", "Info", f"A valid TLS connection was established using {tls_version}.", "Continue to monitor expiry dates and cipher configuration."))
    return findings

