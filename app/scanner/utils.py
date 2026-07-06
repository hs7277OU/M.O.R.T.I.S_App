from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}
LOCAL_HOSTS = ("localhost", "127.0.0.1")


def normalise_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise ValueError("A target URL is required.")

    if "://" not in url:
        # Local test targets (e.g. DVWA on localhost:8080) are served over HTTP,
        # so default those to http:// and everything else to https://.
        host_part = url.split("/", 1)[0].lower()
        if host_part.startswith(LOCAL_HOSTS):
            url = "http://" + url
        else:
            url = "https://" + url

    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES or not parsed.netloc:
        raise ValueError("Enter a valid http:// or https:// URL.")
    return url.rstrip("/")


def hostname_from_url(url: str) -> str:
    return urlparse(url).hostname or ""
