"""Tests for IndicatorUtilities indicator extraction."""

import logging

import pytest

from cyvoreos.indicator_utilities import IndicatorUtilities


def _test_logger() -> logging.Logger:
    log = logging.getLogger("test")
    log.handlers.clear()
    log.addHandler(logging.NullHandler())
    log.propagate = False
    return log


@pytest.mark.parametrize(
    ("text", "expected_emails"),
    [
        ("contact me at user@example.com today", {"user@example.com"}),
        (
            "a@b.co and x_y@host.example.org",
            {"a@b.co", "x_y@host.example.org"},
        ),
        (
            "mailto:global.client.experience@jpmchase.com",
            {"global.client.experience@jpmchase.com"},
        ),
        (
            "Reach us at mailto:global.client.experience@jpmchase.com please.",
            {"global.client.experience@jpmchase.com"},
        ),
    ],
)
def test_extract_email_addresses(text, expected_emails):
    logger = _test_logger()
    result = IndicatorUtilities.extract_email_addresses(text, logger)
    emails = {v for tag, v in result if tag == "email"}
    assert emails == expected_emails


@pytest.mark.parametrize(
    ("text", "expected_ips"),
    [
        ("Server 192.168.0.1 is up", {"192.168.0.1"}),
        (
            "IPv6 ::1 and full 2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            {
                "0000:0000:0000:0000:0000:0000:0000:0001",
                "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            },
        ),
    ],
)
def test_extract_ips_valid(text, expected_ips):
    logger = _test_logger()
    result = IndicatorUtilities.extract_ips(text, logger)
    ips = {v for tag, v in result if tag == "ip"}
    assert ips == expected_ips


def test_extract_ips_invalid_dotted_quad_filtered():
    logger = _test_logger()
    text = "not an ip 999.999.999.999 end"
    result = IndicatorUtilities.extract_ips(text, logger)
    assert result == set()


def test_extract_url_and_domain_https_example():
    logger = _test_logger()
    text = "open https://example.com/path for info"
    result = IndicatorUtilities.extract_url_and_domain(text, logger)
    assert ("url", "https://example.com/path") in result
    assert ("domain", "example.com") in result


@pytest.mark.parametrize(
    "text",
    [
        "mailto:global.client.experience@jpmchase.com",
        "Please use mailto:global.client.experience@jpmchase.com to reply.",
    ],
)
def test_mailto_not_extracted_as_url(text):
    """Regression: mailto links yield email only, not URL indicators."""
    logger = _test_logger()
    url_result = IndicatorUtilities.extract_url_and_domain(text, logger)
    urls = {v for tag, v in url_result if tag == "url"}
    assert urls == set()

    emails = IndicatorUtilities.extract_email_addresses(text, logger)
    assert ("email", "global.client.experience@jpmchase.com") in emails


def test_extract_indicators_mailto_no_url_integration():
    logger = _test_logger()
    text = "mailto:global.client.experience@jpmchase.com"
    result = IndicatorUtilities.extract_indicators(
        text, logger, include_crypto=False
    )
    assert ("email", "global.client.experience@jpmchase.com") in result
    assert not any(tag == "url" for tag, _ in result)


def test_extract_indicators_crypto_smoke():
    logger = _test_logger()
    # Sample satisfies BTCREG in cyvoreos.regex_patterns
    text = "pay 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa today"
    result = IndicatorUtilities.extract_indicators(
        text, logger, include_crypto=True
    )
    assert ("crypto", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") in result
