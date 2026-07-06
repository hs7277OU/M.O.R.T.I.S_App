import os
import time

from .utils import normalise_url
from .headers import check_security_headers
from .cookies import check_cookies
from .cors import check_cors
from .tls import check_tls
from .access import check_access_control
from .injection import check_basic_injection
from .risk import overall_rating

# Delay between modules so MORTIS behaves as a polite, low-impact scanner.
# Configurable via the MORTIS_DELAY environment variable (seconds).
REQUEST_DELAY = float(os.environ.get("MORTIS_DELAY", "0.3"))

# Registry of available modules, keyed by the name used in the scan form
# (RE14: lets a user pick which checks to run).
MODULES = {
    "headers": check_security_headers,
    "tls": check_tls,
    "cookies": check_cookies,
    "cors": check_cors,
    "access": check_access_control,
    "injection": check_basic_injection,
}

# Active-probe modules skipped on a "quick" scan depth, since they issue
# extra requests per form/path rather than a single GET.
ACTIVE_PROBE_MODULES = {"access", "injection"}


def run_scan(target_url: str, enabled_modules=None, depth: str = "standard", on_progress=None) -> dict:
    """Run the selected scanner modules against target_url.

    If given, on_progress(name, done_count, total_count) is called just before
    each module starts, so a caller (e.g. a background scan thread) can report
    real-time progress (RE8).
    """
    url = normalise_url(target_url)
    findings = []

    if enabled_modules is None:
        selected = list(MODULES.keys())
    else:
        selected = [name for name in MODULES if name in enabled_modules]

    if depth == "quick":
        selected = [name for name in selected if name not in ACTIVE_PROBE_MODULES]

    total = len(selected)
    for done, name in enumerate(selected):
        if on_progress:
            on_progress(name, done, total)
        findings.extend(MODULES[name](url))
        time.sleep(REQUEST_DELAY)  # rate-limit / throttle between checks

    if on_progress:
        on_progress(None, total, total)

    # Sort findings from most serious to least serious
    findings = sorted(
        findings,
        key=lambda finding: finding.get("score", 0),
        reverse=True,
    )

    score, rating = overall_rating(findings)

    return {
        "target_url": url,
        "findings": findings,
        "overall_score": score,
        "overall_rating": rating,
    }
