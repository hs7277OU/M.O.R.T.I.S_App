import pytest
from app.scanner.utils import normalise_url, hostname_from_url


def test_normalise_url_adds_https_when_missing():
    assert normalise_url("example.com") == "https://example.com"


def test_normalise_url_removes_trailing_slash():
    assert normalise_url("https://example.com/") == "https://example.com"


def test_normalise_url_rejects_blank_value():
    with pytest.raises(ValueError):
        normalise_url("")


def test_normalise_url_rejects_invalid_scheme():
    with pytest.raises(ValueError):
        normalise_url("ftp://example.com")


def test_hostname_from_url_extracts_hostname():
    assert hostname_from_url("https://example.com/test") == "example.com"

def test_normalise_url_defaults_localhost_to_http():
    assert normalise_url("localhost:8080") == "http://localhost:8080"
    assert normalise_url("127.0.0.1:5000") == "http://127.0.0.1:5000"
