"""
This file will be deprecated in the future.
"""
from datetime import datetime
import socket
import logging
import re
import ipaddress
import urlexpander
import json
import jsonpickle
from json import JSONEncoder
from urllib.parse import urlparse
from uuid import uuid4

# MIME libraries
import eml_parser
import extract_msg

# regex_patterns.py
IPV4REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
IPV6REGEX = re.compile(r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))")
URLREGEX = re.compile(r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))")
EMAILREGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
BTCREG = re.compile(r"(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}")
DASHREG = re.compile(r"X[1-9A-HJ-NP-Za-km-z]{33}")
LTCREG = re.compile(r"[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}")
DOGEREG = re.compile(r"D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}")
COINS = [BTCREG, DASHREG, LTCREG, DOGEREG]



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

    def getDict(self):
        """
        Convert plugin object into dictionary
        """
        plugin_dict = {"checkID": self.checkID, "pluginName": self.pluginName, "raw": self.raw, "output": self.output}
        return plugin_dict

    def to_json(self):
        return jsonpickle.encode(self, unpicklable=False)

    @classmethod
    def from_json(cls, json_str):
        logging.info(f"from_json - json_str: {json_str}, type: {type(json_str)}")
        
        json_dict = json.loads(json_str)
        
        instance = cls(
            json_dict["checkID"],
            json_dict["pluginName"],
            json_dict["raw"],
            json_dict["output"]
        )
        instance.timestamp = json_dict["timestamp"]
        return instance


def _deserialize_custom_object(obj):
    print(f"_deserialize_custom_object - obj: {obj}, type: {type(obj)}")

    if "checkID" in obj and "pluginName" in obj and "raw" in obj and "output" in obj:
        return Plugin.from_json(obj)
    
    return obj


class Check:
    """
    Check is an object to test against new plugins.
    When check is made as part of a Case object it will hold one value, url/file/crypto wallet.
    When check is self made it could hold all types of data in raw.
    """

    def __init__(self, id, raw, tag=[]):
        self.raw = raw
        self.reputation = 0
        self.hash = ""
        self.plugins = []
        self.id = id or str(uuid4())
        self.tags = []
        if tag and type(tag) == list:
            self.tags = tag
        self.timestemp = datetime.now().strftime("%m%d%Y%H%M%S")

    def getDict(self):
        """
        Convert check object into dictionary
        """
        check_dict = {"rawData": self.raw, "reputation": self.reputation, "checkID": self.id, "plugins": [],
                      "hash": self.hash}
        for plg in self.plugins:
            check_dict["plugins"].append(plg.getDict())
        return check_dict

    def isEmpty(self):
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
        current_plugin = Plugin(self.id, pluginName, self.raw, output)
        self.plugins.append(current_plugin)
        return True

    def to_json(self):
        return jsonpickle.encode(self, unpicklable=False)


class Case:
    """
    Case is an object to investigate multiple leads from the same source.
    checkArray will hold every lead and will only repersent one value - url/file/crypto wallet.
    """

    def __init__(self, raw, empty=False, customID=None):
        logging.info("Initializing Case")
        self.id = customID or str(uuid4())
        self.checkArray = []
        self.raw = raw
        if not empty:
            self.createChecks()
        self.timestemp = datetime.now().strftime("%m%d%Y%H%M%S")
        logging.debug(f"Created case {self.id} with {self.size()} checks")


    def urlAndDomainChecks(self):
        """
        Create check for every unique urls and domain in raw data
        """
        try:
            logging.info("Querying for URLs")
            urls = re.findall(URLREGEX, self.raw)
            if len(urls) > 0:
                logging.debug("Create checks for URLs and Domains:")
                urls = [url[0] for url in urls]
                # Casting for getUniques.
                if type(urls) != list or type(urls) != tuple:
                    urls = list(urls)
                for url in self.getUniquesUrls(urls):
                    try:
                        if urlexpander.is_short(url):
                            url = urlexpander.expand(url)
                    except Exception as e:
                        logging.info(e)
                    tmpChk = Check(str(uuid4()), url, ["url"])
                    self.checkArray.append(tmpChk)
                    logging.debug(f"\t{url}")
                    try:
                        domain = urlparse(url).scheme + '://' + urlparse(url).netloc
                        if domain.startswith("www."):
                            domain = domain[4::]
                        tmpChk = Check(str(uuid4()), domain, ["domain"])
                        self.checkArray.append(tmpChk)
                    except Exception as e:
                        logging.info(e)

            else:
                logging.warning(f"No URLs found in case.")
        except Exception as e:
            logging.info(e)
            return ""

    def ipChecks(self):
        """
        Create check for every unique ip in raw data
        """
        logging.info("Querying for IPs")
        ips = re.findall(IPV4REGEX, self.raw) + re.findall(IPV6REGEX, self.raw)
        if len(ips) > 0:
            logging.debug("Create checks for URLs:")
            for cur_ip in self.getUniques(ips):
                try:
                    ip = ipaddress.ip_address(cur_ip)
                    tmpChk = Check(str(uuid4()), ip.exploded, ["ip"])
                    self.checkArray.append(tmpChk)
                    logging.debug(f"\t{ip.exploded}")
                except ValueError:
                    logging.debug(f'address/netmask is invalid: {cur_ip}')

    def emailChecks(self):
        """
        Create check for every unique email addresses in raw data
        """
        try:
            logging.info("Querying for Email addresses")
            emails_ad = re.findall(EMAILREGEX, self.raw)
            if len(emails_ad) > 0:
                logging.debug("Create checks for Email addresses:")

                # Casting for getUniques.
                if type(emails_ad) != list or type(emails_ad) != tuple:
                    email_ad = list(emails_ad)
                for email_ad in self.getUniques(emails_ad):
                    tmpChk = Check(str(uuid4()), email_ad, ["email"])
                    self.checkArray.append(tmpChk)
                    logging.debug(f"\t{email_ad}")
            else:
                logging.warning(f"No Email addresses found in case.")
        except Exception as e:
            logging.info(e)
            return ""

    def walletsCheck(self):
        """
        Create check for every unique crypto addresses in raw data
        """
        try:
            logging.info("Querying for crypto addresses")
            for coin in COINS:
                wallat_ad = re.findall(coin, self.raw)
                if len(wallat_ad) > 0:
                    logging.debug("Create checks for crypto addresses:")
                    for cur_wallet in self.getUniques(wallat_ad):
                        tmpChk = Check(str(uuid4()), cur_wallet, ["crypto"])
                        self.checkArray.append(tmpChk)
                        logging.debug(f"\t{cur_wallet}")
                else:
                    logging.warning(f"No Crypto addresses found in case.")
        except Exception as e:
            logging.info(e)
            return ""

    def getUniques(self, data):
        unique_data = []
        for i in data:
            # check if exists in unique_list or not
            if i not in unique_data:
                unique_data.append(i)
        return unique_data

    def getUniquesUrls(self, data):
        unique_data = []
        option1, option2 = '', ''
        for i in data:
            if not re.match(r"https?://", i):
                option1 = 'https://' + i
                option2 = 'http://' + i
            # check if exists in unique_list or not
            if i not in unique_data and option1 not in unique_data and option2 not in unique_data:
                unique_data.append(i)
        return unique_data

    def size(self):
        """
        Return the amount of checks in the case
        """
        return len(self.checkArray)

    def emailFileCheck(self):
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
            if any(self.raw.startswith(magicNumber) for magicNumber in magicNumbers['eml']):
                ep = eml_parser.EmlParser(include_raw_body=True, include_attachment_data=True)
                parsedMime = ep.decode_email_bytes(self.raw)
                tmpChk = Check(str(uuid4()), parsedMime, ["mail"])
                self.checkArray.append(tmpChk)
                # parsedMime = str(parsedMime.get('attachment') or '')
                parsedMime = str(parsedMime['body']) + str(parsedMime['header']['header'].get('reply-to') or [])

            # outlook- msg
            elif self.raw.startswith(magicNumbers['msg']):
                tmpChk = Check(str(uuid4()), parsedMime, ["mail"])
                self.checkArray.append(tmpChk)
                parsedMime = extract_msg.openMsg(self.raw)
                # parsedMime = str(parsedMime.attachments)
                parsedMime = str(parsedMime.inReplyTo) + str(parsedMime.body)
            else:
                return "Received a file that is not .eml or .msg"

            self.raw = parsedMime

        except Exception as e:
            logging.info(e)
            return ""

    def createChecks(self):
        """
        Create checks array from raw data, check could be either one url/file/crypto wallet.
        Changing self.checkArray.
        """

        # First create check MUST be emailFileCheck
        logging.info("Creating Checks...")
        # try:
        #     self.emailFileCheck()
        # except Exception as e:
        #     logging.warning(e)
        try:
            self.urlAndDomainChecks()
        except Exception as e:
            logging.warning(e)
        try:
            self.ipChecks()
        except Exception as e:
            logging.warning(e)
        try:
            self.emailChecks()
        except Exception as e:
            logging.warning(e)
        try:
            self.walletsCheck()
        except Exception as e:
            logging.warning(e)
        for chk in self.checkArray:
            logging.debug(f"\t {chk.raw}")

    def getDict(self):
        """
        Convert case object into dictionary
        """
        case_dict = {"id": self.id, "raw": self.raw, "checks": [], "timestamp": self.timestemp}
        for chk in self.checkArray:
            case_dict["checks"].append(chk.getDict())
        return case_dict

    def to_json(self):
        return jsonpickle.encode(self, unpicklable=False)


