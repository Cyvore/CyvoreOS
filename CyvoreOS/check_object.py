"""
This file will be deprecated in the future.
"""

import re
import json
import logging
from uuid import uuid4
from datetime import datetime
import ipaddress
from urllib.parse import urlparse
import jsonpickle
import urlexpander

# MIME libraries
import eml_parser
import extract_msg

import cyvoreos.regex_patterns as regex_patterns

class Plugin:
    """
    Plugin is part of check type which holds all plugins output for a check
    """

    def __init__(self, checkID, pluginName, raw, output):
        self.checkID = checkID
        self.pluginName = pluginName
        self.raw = raw
        self.output = output
        self.timestamp = datetime.now().strftime("%m%d%Y%H%M%S")

    def get_dict(self):
        """
        Convert plugin object into dictionary
        """
        plugin_dict = {
            "checkID": self.checkID,
            "pluginName": self.pluginName,
            "raw": self.raw,
            "output": self.output,
        }
        return plugin_dict

    def to_json(self):
        return jsonpickle.encode(self, unpicklable=False)

    @classmethod
    def from_json(cls, json_str, logger: logging.Logger = logging):
        """
        Create a Plugin object from a json string
        """

        logger.info(f"from_json - json_str: {json_str}, type: {type(json_str)}")

        json_dict = json.loads(json_str)

        instance = cls(
            json_dict["checkID"],
            json_dict["pluginName"],
            json_dict["raw"],
            json_dict["output"],
        )
        instance.timestamp = json_dict["timestamp"]
        return instance


class Check:
    """
    Check is an object to test against new plugins.
    When check is made as part of a Case object it will hold one value, url/file/crypto wallet.
    When check is self made it could hold all types of data in raw.
    """

    def __init__(self, guid, raw, tags):
        self.raw = raw
        self.reputation = 0
        self.hash = ""
        self.plugins = []
        self.guid = guid or str(uuid4())
        self.tags = []
        self.timestemp = datetime.now().strftime("%m%d%Y%H%M%S")

        if tags and isinstance(tags, list):
            self.tags = tags

    def get_dict(self):
        """
        Convert check object into dictionary
        """
        check_dict = {
            "rawData": self.raw,
            "reputation": self.reputation,
            "checkID": self.guid,
            "plugins": [],
            "hash": self.hash,
        }
        for plg in self.plugins:
            check_dict["plugins"].append(plg.getDict())
        return check_dict

    def is_empty(self):
        """
        Boolean funtion: return false if any of the fields is set.
         - hash
         - url
         - wallet
         - checkID
        """
        if self.raw == "":
            return True
        return False

    def add_plugin(self, pluginName, output):
        """
        Boolean function: returns true if plugin successfully added
        """
        if output == "":
            return False
        current_plugin = Plugin(self.guid, pluginName, self.raw, output)
        self.plugins.append(current_plugin)
        return True

    def to_json(self):
        return jsonpickle.encode(self, unpicklable=False)


class Case:
    """
    Case is an object to investigate multiple leads from the same source.
    checkArray will hold every lead and will only repersent one value - url/file/crypto wallet.
    """

    def __init__(
        self, raw, empty=False, customID=None, logger: logging.Logger = logging
    ):
        logger.info("Initializing Case")

        self.id = customID or str(uuid4())
        self.checkArray = []
        self.raw = raw
        if not empty:
            self.create_checks()
        self.timestemp = datetime.now().strftime("%m%d%Y%H%M%S")

        logger.debug(f"Created case {self.id} with {self.size()} checks")

    def url_and_domain_checks(self, logger: logging.Logger = logging):
        """
        Create check for every unique urls and domain in raw data

        Parameters:
            logger (Logger): logger to use (optional)

        Returns:
            None
        """
        try:
            logger.info("Querying for URLs")
            urls = re.findall(regex_patterns.URLREGEX, self.raw)
            if len(urls) > 0:
                logger.debug("Create checks for URLs and Domains:")
                urls = [url[0] for url in urls]
                # Casting for getUniques.
                if not isinstance(urls, list) or not isinstance(urls, tuple):
                    urls = list(urls)
                for url in self.get_uniques_urls(urls):
                    try:
                        if urlexpander.is_short(url):
                            url = urlexpander.expand(url)
                    except Exception as e:
                        logger.info(e)
                    tmpChk = Check(str(uuid4()), url, ["url"])
                    self.checkArray.append(tmpChk)
                    logger.debug(f"\t{url}")
                    try:
                        domain = urlparse(url).scheme + "://" + urlparse(url).netloc
                        if domain.startswith("www."):
                            domain = domain[4::]
                        tmpChk = Check(str(uuid4()), domain, ["domain"])
                        self.checkArray.append(tmpChk)
                    except Exception as e:
                        logger.info(e)

            else:
                logger.warning("No URLs found in case.")
        except Exception as e:
            logger.info(e)
            return ""

    def ip_checks(self, logger: logging.Logger = logging):
        """
        Create check for every unique ip in raw data

        Parameters:
            logger (Logger): logger to use (optional)
        """
        logger.info("Querying for IPs")
        ips = re.findall(regex_patterns.IPV4REGEX, self.raw) + re.findall(regex_patterns.IPV6REGEX, self.raw)
        if len(ips) > 0:
            logger.debug("Create checks for URLs:")
            for cur_ip in self.get_uniques(ips):
                try:
                    ip = ipaddress.ip_address(cur_ip)
                    tmpChk = Check(str(uuid4()), ip.exploded, ["ip"])
                    self.checkArray.append(tmpChk)
                    logger.debug(f"\t{ip.exploded}")
                except ValueError:
                    logger.debug(f"address/netmask is invalid: {cur_ip}")

    def email_checks(self, logger: logging.Logger = logging):
        """
        Create check for every unique email addresses in raw data

        Parameters:
            logger (Logger): logger to use (optional)

        Returns:
            None
        """
        try:
            logger.info("Querying for Email addresses")
            emails_ad = re.findall(regex_patterns.EMAILREGEX, self.raw)
            if len(emails_ad) > 0:
                logger.debug("Create checks for Email addresses:")

                # Casting for getUniques.
                if not isinstance(email_ad, list) or not isinstance(email_ad, tuple):
                    email_ad = list(emails_ad)
                for email_ad in self.get_uniques(emails_ad):
                    tmpChk = Check(str(uuid4()), email_ad, ["email"])
                    self.checkArray.append(tmpChk)
                    logger.debug(f"\t{email_ad}")
            else:
                logger.warning("No Email addresses found in case.")
        except Exception as e:
            logger.info(e)
            return ""

    def wallets_check(self, logger: logging.Logger = logging):
        """
        Create check for every unique crypto addresses in raw data

        Parameters:
            logger (Logger): logger to use (optional)

        Returns:
            None
        """
        try:
            logger.info("Querying for crypto addresses")
            for coin in regex_patterns.COINS:
                wallat_ad = re.findall(coin, self.raw)
                if len(wallat_ad) > 0:
                    logger.debug("Create checks for crypto addresses:")
                    for cur_wallet in self.get_uniques(wallat_ad):
                        tmpChk = Check(str(uuid4()), cur_wallet, ["crypto"])
                        self.checkArray.append(tmpChk)
                        logger.debug(f"\t{cur_wallet}")
                else:
                    logger.warning("No Crypto addresses found in case.")
        except Exception as e:
            logger.info(e)
            return ""

    def get_uniques(self, data):
        unique_data = []
        for i in data:
            # check if exists in unique_list or not
            if i not in unique_data:
                unique_data.append(i)
        return unique_data

    def get_uniques_urls(self, data):
        """
        Get unique urls from a list
        """

        unique_data = []
        option1, option2 = "", ""
        for i in data:
            if not re.match(r"https?://", i):
                option1 = "https://" + i
                option2 = "http://" + i
            # check if exists in unique_list or not
            if (
                i not in unique_data
                and option1 not in unique_data
                and option2 not in unique_data
            ):
                unique_data.append(i)
        return unique_data

    def size(self):
        """
        Return the amount of checks in the case
        """
        return len(self.checkArray)

    def email_file_check(self, logger: logging.Logger = logging):
        """
        Check if the file is an email file and parse it to extract the email data
        """
        
        magicNumbers = {
            "eml": [
                bytes([0x44, 0x65, 0x6C, 0x69, 0x76, 0x65, 0x72, 0x65, 0x64]),
                bytes([0x52, 0x65, 0x74, 0x75, 0x72, 0x6E, 0x2D, 0x50]),
                bytes([0x46, 0x72, 0x6F, 0x6D]),
                bytes([0x58, 0x2D]),
                bytes([0x23, 0x21, 0x20, 0x72, 0x6E, 0x65, 0x77, 0x73]),
                bytes([0x46, 0x6F, 0x72, 0x77, 0x61, 0x72, 0x64, 0x20, 0x74, 0x6F]),
                bytes([0x46, 0x72, 0x6F, 0x6D, 0x3A]),
                bytes([0x4E, 0x23, 0x21, 0x20, 0x72, 0x6E, 0x65, 0x77, 0x73]),
                bytes([0x50, 0x69, 0x70, 0x65, 0x20, 0x74, 0x6F]),
                bytes([0x52, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x64, 0x3A]),
                bytes(
                    [
                        0x52,
                        0x65,
                        0x6C,
                        0x61,
                        0x79,
                        0x2D,
                        0x56,
                        0x65,
                        0x72,
                        0x73,
                        0x69,
                        0x6F,
                        0x6E,
                        0x3A,
                    ]
                ),
                bytes(
                    [
                        0x52,
                        0x65,
                        0x74,
                        0x75,
                        0x72,
                        0x6E,
                        0x2D,
                        0x50,
                        0x61,
                        0x74,
                        0x68,
                        0x3A,
                    ]
                ),
                bytes(
                    [
                        0x52,
                        0x65,
                        0x74,
                        0x75,
                        0x72,
                        0x6E,
                        0x2D,
                        0x70,
                        0x61,
                        0x74,
                        0x68,
                        0x3A,
                    ]
                ),
                bytes([0x53, 0x75, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x3A, 0x20]),
            ],
            "msg": bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]),
        }
        try:
            parsedMime = {}

            # gmail- eml
            if any(
                self.raw.startswith(magicNumber) for magicNumber in magicNumbers["eml"]
            ):
                ep = eml_parser.EmlParser(
                    include_raw_body=True, include_attachment_data=True
                )
                parsedMime = ep.decode_email_bytes(self.raw)
                tmpChk = Check(str(uuid4()), parsedMime, ["mail"])
                self.checkArray.append(tmpChk)
                # parsedMime = str(parsedMime.get('attachment') or '')
                parsedMime = str(parsedMime["body"]) + str(
                    parsedMime["header"]["header"].get("reply-to") or []
                )

            # outlook- msg
            elif self.raw.startswith(magicNumbers["msg"]):
                tmpChk = Check(str(uuid4()), parsedMime, ["mail"])
                self.checkArray.append(tmpChk)
                parsedMime = extract_msg.openMsg(self.raw)
                # parsedMime = str(parsedMime.attachments)
                parsedMime = str(parsedMime.inReplyTo) + str(parsedMime.body)
            else:
                return "Received a file that is not .eml or .msg"

            self.raw = parsedMime

        except Exception as e:
            logger.info(e)
            return ""

    def create_checks(self, logger: logging.Logger = logging):
        """
        Create checks array from raw data, check could be either one url/file/crypto wallet.
        Changing self.checkArray.
        """

        # First create check MUST be emailFileCheck
        logger.info("Creating Checks...")
        # try:
        #     self.emailFileCheck()
        # except Exception as e:
        #     logger.warning(e)
        try:
            self.url_and_domain_checks()
        except Exception as e:
            logger.warning(e)
        try:
            self.ip_checks()
        except Exception as e:
            logger.warning(e)
        try:
            self.email_checks()
        except Exception as e:
            logger.warning(e)
        try:
            self.wallets_check()
        except Exception as e:
            logger.warning(e)
        for chk in self.checkArray:
            logger.debug(f"\t {chk.raw}")

    def get_dict(self):
        """
        Convert case object into dictionary
        """
        case_dict = {
            "id": self.id,
            "raw": self.raw,
            "checks": [],
            "timestamp": self.timestemp,
        }
        for chk in self.checkArray:
            case_dict["checks"].append(chk.getDict())
        return case_dict

    def to_json(self):
        return jsonpickle.encode(self, unpicklable=False)
