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