from .utils import normalise_url
from .headers import check_security_headers
from .cookies import check_cookies
from .cors import check_cors
from .tls import check_tls
from .injection import check_basic_injection
from .risk import overall_rating

def run_scan(target_url: str) -> dict:
    url = normalise_url(target_url)
    findings = []
    for module in (check_security_headers, check_tls, check_cookies, check_cors, check_basic_injection):
        findings.extend(module(url))
    score, rating = overall_rating(findings)
    return {
        "target_url": url,
        "findings": findings,
        "overall_score": score,
        "overall_rating": rating,
    }
