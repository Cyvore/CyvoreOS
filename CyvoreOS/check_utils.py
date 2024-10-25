from typing import List
from urllib.parse import urlparse
from uuid import uuid4
import ipaddress
import logging
import re
import urlexpander

# MIME libraries
import eml_parser
import extract_msg

from .check_types import Check
from .regex_patterns import IPV4REGEX, IPV6REGEX, URLREGEX, EMAILREGEX, COINS

def extract_url_and_domain_checks(data: str, logger: logging.Logger = logging) -> List[Check]:
    """
    Creates check for every unique url in data

    Parameters:
        data (str): data to search for urls
        logger (Logger): logger to use (optional)

    Returns:
        List[Check]: list of checks
    """

    checks = []

    try:
        logger.debug("extractUrlAndDomainChecks Querying for URLs")
        urls_matches = re.findall(URLREGEX, data)
        urls = [url[0] for url in urls_matches]

        if len(urls) > 0:
            urls = set(urls)

            for url in urls:
                if not url:
                    continue

                try:
                    # Expand shortened URLs
                    if urlexpander.is_short(url):
                        url = urlexpander.expand(url)
                    checks.append(Check(data=url, tag="url"))
                    
                except Exception as e:
                    logger.warning(f"Couldn't expand url: {url} - {e}")

                try:
                    # Extract domain from url
                    domain = _extract_domain(url)

                    checks.append(Check(data=domain, tag="domain"))

                except Exception as e:
                    logger.warning(f"Couldn't extract domain from url: {url} - {e}")

        else:
            logger.warning("No URLs found in case.")

    except Exception as e:
        logger.info(e)

    return checks

def extract_ips_checks(data: str, logger: logging.Logger = logging) -> List[Check]:
    """
    Creates check for every unique ip in data

    Parameters:
        data (str): data to search for ips
        logger (Logger): logger to use (optional)

    Returns:
        List[Check]: list of checks
    """

    logger.debug("Querying for IPs")
    ips = re.findall(IPV4REGEX, data) + re.findall(IPV6REGEX, data)
    checks = []

    if len(ips) > 0:
        ips = set(ips)

        for cur_ip in ips:
            try:
                ip = ipaddress.ip_address(cur_ip)
                checks.append(Check(data=ip.exploded, tag="ip", instanceID=str(uuid4())))

            except ValueError:
                logger.debug(f'address/netmask is invalid: {cur_ip}')

            except Exception as e:
                logger.warning(f"Couldn't extract ip from: {cur_ip} - {e}")

    else:
        logger.warning("No IPs found in case.")

    return checks

def extract_email_addresses_checks(data: str, logger: logging.Logger = logging) -> List[Check]:
    """
    Create check for every unique email addresses in raw data

    Parameters:
        data (str): data to search for email addresses
        logger (Logger): logger to use (optional)

    Returns:
        List[Check]: list of checks
    """

    checks = []

    try:
        logger.debug("Querying for Email addresses")
        emails_addrs = re.findall(EMAILREGEX, data)

        if len(emails_addrs) > 0:
            logger.debug("Create checks for Email addresses:")
            emails_addrs = set(emails_addrs)

            for addr in emails_addrs:
                checks.append(Check(data=addr, tag="email", instanceID=str(uuid4())))
                logger.debug(f"\t{addr}")

        else:
            logger.warning("No Email addresses found in case.")

    except Exception as e:
        logger.info(e)

    return checks

def extract_wallets_checks(data: str, logger: logging.Logger = logging) -> List[Check]:
    """
    Create check for every unique crypto addresses in raw data

    Parameters:
        data (str): data to search for crypto addresses
        logger (Logger): logger to use (optional)

    Returns:
        List[Check]: list of checks
    """

    checks = []

    try:
        logger.debug("Querying for crypto addresses")

        for coin in COINS:
            wallat_addrs = re.findall(coin, data)

            if len(wallat_addrs) > 0:
                logger.debug("Create checks for crypto addresses:")

                for cur_wallet in wallat_addrs:
                    checks.append(Check(data=cur_wallet, tag="crypto", instanceID=str(uuid4())))

            else:
                logger.warning("No Crypto addresses found in case.")

    except Exception as e:
        logger.info(e)

    return checks

def email_file_check(data: str, logger: logging.Logger = logging) -> List[Check]:
    """
    Create check for email file (.eml or .msg)
    """

    checks = []
    magicNumbers = {'eml': [bytes([0x44, 0x65, 0x6c, 0x69, 0x76, 0x65, 0x72, 0x65, 0x64]),
                            bytes([0x52, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x2d, 0x50]),
                            bytes([0x46, 0x72, 0x6f, 0x6d]),
                            bytes([0x58, 0x2d]),
                            bytes([0x23, 0x21, 0x20, 0x72, 0x6e, 0x65, 0x77, 0x73]),
                            bytes([0x46, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x20, 0x74, 0x6f]),
                            bytes([0x46, 0x72, 0x6f, 0x6d, 0x3a]),
                            bytes([0x4e, 0x23, 0x21, 0x20, 0x72, 0x6e, 0x65, 0x77, 0x73]),
                            bytes([0x50, 0x69, 0x70, 0x65, 0x20, 0x74, 0x6f]),
                            bytes([0x52, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x64, 0x3a]),
                            bytes([0x52, 0x65, 0x6c, 0x61, 0x79, 0x2d, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
                                    0x3a]),
                            bytes([0x52, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x2d, 0x50, 0x61, 0x74, 0x68, 0x3a]),
                            bytes([0x52, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x2d, 0x70, 0x61, 0x74, 0x68, 0x3a]),
                            bytes([0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x3a, 0x20])],
                    'msg': bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])}
    
    try:
        parsedMime = {}

        # gmail- eml
        if any(data.startswith(magicNumber) for magicNumber in magicNumbers['eml']):
            ep = eml_parser.EmlParser(include_raw_body=True, include_attachment_data=True)
            parsedMime = ep.decode_email_bytes(data)

            if parsedMime['header']['header'].get('reply-to'):
                checks.append(Check(
                    data=str(parsedMime['header']['header'].get('reply-to') or []), 
                    tag="email", 
                    instanceID=str(uuid4())
                ))
            if parsedMime['header']['header'].get('from'):
                checks.append(Check(
                    data=str(parsedMime['header']['header'].get('from') or []), 
                    tag="email", 
                    instanceID=str(uuid4())
                ))
            if parsedMime['header']['header'].get('to'):
                checks.append(Check(
                    data=str(parsedMime['header']['header'].get('to') or []), 
                    tag="email", 
                    instanceID=str(uuid4())
                ))
            if parsedMime['header']['header'].get('cc'):
                checks.append(Check(
                    data=str(parsedMime['header']['header'].get('cc') or []), 
                    tag="email", 
                    instanceID=str(uuid4())
                ))
            if parsedMime['header']['header'].get('bcc'):
                checks.append(Check(
                    data=str(parsedMime['header']['header'].get('bcc') or []), 
                    tag="email", 
                    instanceID=str(uuid4())
                ))

            checks.append(Check(data=str(parsedMime), tag="mail", instanceID=str(uuid4())))

        # outlook- msg
        elif data.startswith(magicNumbers['msg']):
            parsedMime = extract_msg.openMsg(data)
            # parsedMime = str(parsedMime.attachments)
            parsedMime = str(parsedMime.inReplyTo) + str(parsedMime.body)
            checks.append(Check(data=str(parsedMime), tag="mail", instanceID=str(uuid4())))
        else:
            logger.warning("Received a file that is not .eml or .msg")

    except Exception as e:
        logger.info(e)

    return checks

def create_checks(data: str, logger: logging.Logger = logging) -> List[Check]:
    """
    Create checks array from data, check could be either one url/file/crypto wallet.

    Parameters:
        data (str): data to search for checks
        logger (Logger): logger to use (optional)

    Returns:
        List[Check]: list of checks
    """

    logger.info("Creating Checks...")
    checks = []

    try:
        url_checks = extract_url_and_domain_checks(data, logger)

        if url_checks:
            logger.debug(f"Created {len(url_checks)} url checks")
            checks.extend(url_checks)

    except Exception as e:
        logger.warning(e)

    try:
        ip_checks = extract_ips_checks(data, logger)
        logger.debug(f"Created {len(ip_checks)} ip checks")

        if ip_checks:
            checks.extend(ip_checks)

    except Exception as e:
        logger.warning(e)

    try:
        email_checks = extract_email_addresses_checks(data, logger)
        logger.debug(f"Created {len(email_checks)} email checks")

        if email_checks:
            checks.extend(email_checks)

    except Exception as e:
        logger.warning(e)

    try:
        wallet_checks = extract_wallets_checks(data, logger)
        logger.debug(f"Created {len(wallet_checks)} wallet checks")

        if wallet_checks:
            checks.extend(wallet_checks)
            
    except Exception as e:
        logger.warning(e)

    logger.info(f"Created total {len(checks)} checks")
    return checks

def _extract_domain(url: str):
    """
    Extract domain from url

    Parameters:
        url (str): url to extract domain from
    
    Returns:
        str: domain with protocol
    """

    DEFAULT_PROTOCOL = "http://"

    # Parse the URL
    parsed_url = urlparse(url)

    # If no domain was found, try to add the default protocol
    if not parsed_url.netloc:
        parsed_url = urlparse(DEFAULT_PROTOCOL + url)

    # Get the domain
    domain = parsed_url.scheme + "://" + parsed_url.netloc

    # Remove "www." if present
    if domain.startswith("www."):
        domain = domain[4:]

    return domain
