import logging
import re
import ipaddress
import urlexpander
from urllib.parse import urlparse
from uuid import uuid4
from .checkTypes import Check, Plugin
from typing import List
from .regex_patterns import IPV4REGEX, IPV6REGEX, URLREGEX, EMAILREGEX, COINS
# MIME libraries
import eml_parser
import extract_msg


def extractUrlAndDomainChecks(data: str) -> List[Check]:
    """
    extractUrlAndDomainChecks - Creates check for every unique url in data
    """
    checks = []
    try:
        logging.debug("extractUrlAndDomainChecks Querying for URLs")
        urls = re.findall(URLREGEX, data)
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
                    logging.warn(f"Couldn't expand url: {url} - {e}")
                try:
                    # Extract domain from url
                    domain = urlparse(url).scheme + '://' + urlparse(url).netloc
                    if domain.startswith("www."):
                        domain = domain[4::]
                    checks.append(Check(data=domain, tag="domain"))
                except Exception as e:
                    logging.warn(f"Couldn't extract domain from url: {url} - {e}")
        else:
            logging.warning(f"No URLs found in case.")
    except Exception as e:
        logging.info(e)
    return checks

def extractIpsChecks(data: str) -> List[Check]:
    """
    extractIps - Creates check for every unique ip in data
    """
    logging.debug("Querying for IPs")
    ips = re.findall(IPV4REGEX, data) + re.findall(IPV6REGEX, data)
    checks = []
    if len(ips) > 0:
        ips = set(ips)
        for cur_ip in ips:
            try:
                ip = ipaddress.ip_address(cur_ip)
                checks.append(Check(data=ip.exploded, tag="ip", instanceID=str(uuid4())))
            except ValueError:
                logging.debug(f'address/netmask is invalid: {cur_ip}')
            except Exception as e:
                logging.warn(f"Couldn't extract ip from: {cur_ip} - {e}")
    else:
        logging.warning(f"No IPs found in case.")
    return checks

def extractEmailAddressesChecks(data: str) -> List[Check]:
    """
    Create check for every unique email addresses in raw data
    """
    checks = []
    try:
        logging.debug("Querying for Email addresses")
        emails_addrs = re.findall(EMAILREGEX, data)
        if len(emails_addrs) > 0:
            logging.debug("Create checks for Email addresses:")
            emails_addrs = set(emails_addrs)
            for addr in emails_addrs:
                checks.append(Check(data=addr, tag="email", instanceID=str(uuid4())))
                logging.debug(f"\t{addr}")
        else:
            logging.warning(f"No Email addresses found in case.")
    except Exception as e:
        logging.info(e)
    return checks

def extractWalletsChecks(data: str) -> List[Check]:
    """
    Create check for every unique crypto addresses in raw data
    """
    checks = []
    try:
        logging.debug("Querying for crypto addresses")
        for coin in COINS:
            wallat_addrs = re.findall(coin, data)
            if len(wallat_addrs) > 0:
                logging.debug("Create checks for crypto addresses:")
                for cur_wallet in wallat_addrs:
                    checks.append(Check(data=cur_wallet, tag="crypto", instanceID=str(uuid4())))
            else:
                logging.warning(f"No Crypto addresses found in case.")
    except Exception as e:
        logging.info(e)
    return checks

def emailFileCheck(data: str) -> List[Check]:
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
                checks.append(Check(data=str(parsedMime['header']['header'].get('reply-to') or []), tag="email", instanceID=str(uuid4())))
            if parsedMime['header']['header'].get('from'):
                checks.append(Check(data=str(parsedMime['header']['header'].get('from') or []), tag="email", instanceID=str(uuid4())))
            if parsedMime['header']['header'].get('to'):
                checks.append(Check(data=str(parsedMime['header']['header'].get('to') or []), tag="email", instanceID=str(uuid4())))
            if parsedMime['header']['header'].get('cc'):
                checks.append(Check(data=str(parsedMime['header']['header'].get('cc') or []), tag="email", instanceID=str(uuid4())))
            if parsedMime['header']['header'].get('bcc'):
                checks.append(Check(data=str(parsedMime['header']['header'].get('bcc') or []), tag="email", instanceID=str(uuid4())))

            checks.append(Check(data=str(parsedMime), tag="mail", instanceID=str(uuid4())))

        # outlook- msg
        elif data.startswith(magicNumbers['msg']):
            parsedMime = extract_msg.openMsg(data)
            # parsedMime = str(parsedMime.attachments)
            parsedMime = str(parsedMime.inReplyTo) + str(parsedMime.body)
            checks.append(Check(data=str(parsedMime), tag="mail", instanceID=str(uuid4())))
        else:
            logging.warn("Received a file that is not .eml or .msg")

    except Exception as e:
        logging.info(e)
    return checks

def createChecks(data: str) -> List[Check]:
    """
    Create checks array from data, check could be either one url/file/crypto wallet.
    """

    # TODO: Add check for file type (email, pdf, doc, etc)
    # First create check MUST be emailFileCheck
    # try:
    #     self.emailFileCheck()
    # except Exception as e:
    #     logging.warning(e)
    logging.info("Creating Checks...")
    checks = []
    try:
        urlChecks = extractUrlAndDomainChecks(data)
        if urlChecks:
            logging.debug(f"Created {len(urlChecks)} url checks")
            checks.extend(urlChecks)
    except Exception as e:
        logging.warning(e)
    try:
        ipChecks = extractIpsChecks(data)
        logging.debug(f"Created {len(ipChecks)} ip checks")
        if ipChecks:
            checks.extend(ipChecks)
    except Exception as e:
        logging.warning(e)
    try:
        emailChecks = extractEmailAddressesChecks(data)
        logging.debug(f"Created {len(emailChecks)} email checks")
        if emailChecks:
            checks.extend(emailChecks)
    except Exception as e:
        logging.warning(e)
    try:
        walletChecks = extractWalletsChecks(data)
        logging.debug(f"Created {len(walletChecks)} wallet checks")
        if walletChecks:
            checks.extend(walletChecks)
    except Exception as e:
        logging.warning(e)

    logging.info(f"Created total {len(checks)} checks")
    return checks
