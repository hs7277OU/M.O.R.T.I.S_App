from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}

def normalise_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise ValueError("A target URL is required.")
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES or not parsed.netloc:
        raise ValueError("Enter a valid http:// or https:// URL.")
    return url.rstrip("/")

def hostname_from_url(url: str) -> str:
    return urlparse(url).hostname or ""
