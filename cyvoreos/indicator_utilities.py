import ipaddress
import logging
import re
from urllib.parse import urlparse

import tldextract

from .regex_patterns import COINS, EMAILREGEX, IPV4REGEX, IPV6REGEX, URLREGEX
from .resources.tlds import TLDS


class IndicatorUtilities:
    """
    Utilities to extract different types of indicators from data.
    """

    @staticmethod
    def extract_indicators(
        data: str,
        logger: logging.Logger = logging,
        include_crypto: bool = False,
    ) -> list[tuple[str, str]]:
        """
        Extract indicators from string, indicator could be of type url/ip/email/crypto wallet.

        Args:
            data (str): data to search for indicators
            logger (Logger): logger to use (optional)
            include_crypto (bool): whether to include crypto wallet indicators (optional)

        Returns:
            list[tuple[str, str]]: list of indicators

        """
        indicators: set[tuple[str, str]] = set()

        url_indicators = IndicatorUtilities.extract_url_and_domain(data, logger)
        indicators.update(url_indicators)

        ip_indicators = IndicatorUtilities.extract_ips(data, logger)
        indicators.update(ip_indicators)

        email_indicators = IndicatorUtilities.extract_email_addresses(data, logger)
        indicators.update(email_indicators)

        wallet_indicators = set()
        if include_crypto:
            wallet_indicators = IndicatorUtilities.extract_wallets(data, logger)
            indicators.update(wallet_indicators)

        logger.debug(
            "Created %d indicators: %d url, %d ip, %d email, %d wallet",
            len(indicators),
            len(url_indicators),
            len(ip_indicators),
            len(email_indicators),
            len(wallet_indicators),
        )

        return indicators

    @staticmethod
    def extract_url_and_domain(
        data: str,
        logger: logging.Logger = logging,
    ) -> set[tuple[str, str]]:
        """
        Find all urls and domains occurrences in a string.

        Args:
            data (str): data to search for urls
            logger (Logger): logger to use (optional)

        Returns:
            list[tuple[str, str]]: list of indicators

        """
        indicators: set[tuple[str, str]] = set()

        try:
            urls = {match.group(0) for match in re.finditer(URLREGEX, data)}

            for url in urls:
                indicators.update(IndicatorUtilities._handle_url(url))

        except Exception:
            logger.exception("Error extracting url and domain indicators")

        return indicators

    @staticmethod
    def extract_ips(
        data: str, logger: logging.Logger = logging
    ) -> set[tuple[str, str]]:
        """
        Find all ips occurrences in a string.

        Args:
            data (str): data to search for ips
            logger (Logger): logger to use (optional)

        Returns:
            list[tuple[str, str]]: list of indicators

        """
        ips = {*re.findall(IPV4REGEX, data), *re.findall(IPV6REGEX, data)}
        indicators: set[tuple[str, str]] = set()

        for cur_ip in ips:
            try:
                ip = ipaddress.ip_address(cur_ip)
                indicators.add(("ip", ip.exploded))

            except ValueError:
                logger.debug("Address/netmask is invalid: %s", cur_ip)

            except Exception:
                logger.exception("Couldn't extract ip from: %s", cur_ip)

        return indicators

    @staticmethod
    def extract_email_addresses(
        data: str,
        logger: logging.Logger = logging,
    ) -> set[tuple[str, str]]:
        """
        Find all email addresses occurrences in a string.

        Args:
            data (str): data to search for email addresses
            logger (Logger): logger to use (optional)

        Returns:
            list[tuple[str, str]]: list of indicators

        """
        try:
            return {("email", addr) for addr in re.findall(EMAILREGEX, data)}
        except Exception:
            logger.exception("Error extracting email addresses indicators")

        return set()

    @staticmethod
    def extract_wallets(
        data: str, logger: logging.Logger = logging
    ) -> set[tuple[str, str]]:
        """
        Find all crypto addresses occurrences in a string.

        Args:
            data (str): data to search for crypto addresses
            logger (Logger): logger to use (optional)

        Returns:
            list[tuple[str, str]]: list of indicators

        """
        try:
            return {
                ("crypto", addr) for coin in COINS for addr in re.findall(coin, data)
            }

        except Exception:
            logger.exception("Error extracting crypto addresses indicators")

        return set()

    @staticmethod
    def _handle_url(
        url: str,
        logger: logging.Logger = logging,
    ) -> set[tuple[str, str]]:
        """
        Handle url and extract domain and tld.

        Args:
            url (str): url to handle
            logger (Logger): logger to use (optional)

        Returns:
            list[tuple[str, str]]: list of indicators

        """
        try:
            # Skip email addresses
            if EMAILREGEX.match(url):
                return set()

            domain, hostnames, tld = IndicatorUtilities._extract_hostname_indicators(
                url
            )

            if not domain:
                return set()

            if tld not in TLDS:
                logger.debug(
                    "Skipping url: %s because tld is not allowed: %s", url, tld
                )
                return set()

            url_ = url

            # Add logic for expanding shortened URLs

            parsed_url = urlparse(url_)

            if not parsed_url.scheme:
                url_ = "https://" + url_

            return {
                ("url", url_),
                ("domain", domain),
                *[("subdomain", hostname) for hostname in hostnames],
            }

        except Exception as e:
            logger.warning("Couldn't expand url: %s, error: %s", url, e)
            return set()

    @staticmethod
    def _extract_hostname_indicators(url: str) -> tuple[str, list[str], str]:
        """
        Extract domain and tld from url.

        Args:
            url (str): url to extract domain from

        Returns:
            tuple[str, list[str], str]:
            - domain: domain name
            - hostnames: list of hostnames (full hostname and progressive parent domains)
            - tld: top level domain

        """
        default_protocol = "https://"

        parsed_url_for_schema = urlparse(url)

        if not parsed_url_for_schema.netloc:
            parsed_url_for_schema = urlparse(default_protocol + url)

        parsed_url = tldextract.extract(url)

        if not parsed_url.domain:
            return None, [], None

        parts = [parsed_url.domain, parsed_url.suffix]
        domain = ".".join(parts)

        hostnames = []
        if parsed_url.subdomain:
            full_hostname = f"{parsed_url.subdomain}.{domain}"
            hostnames.append(full_hostname)

            subdomain_parts = parsed_url.subdomain.split(".")
            for i in range(1, len(subdomain_parts)):
                parent_hostname = ".".join(subdomain_parts[i:]) + "." + domain
                hostnames.append(parent_hostname)

        tld = parsed_url.suffix
        return domain, hostnames, tld
