"""AbuseIPDB plugin for CyvoreOS"""

import json
import logging
import os
import socket
import requests
import urllib3
from cyvoreos.check_types import Check, Plugin
from cyvoreos.plugins.base_plugin import BasePlugin

try:
    ABUSE_IPDB_KEY = os.environ["ABUSE_IPDB_KEY"]
    ABUSE_IPDB_URL = "https://api.abuseipdb.com/api/v2/check"
except Exception as ex:
    logging.info("'ABUSE_IPDB_KEY' wasn't found: %s", ex)


class AbuseIPDBPlugin(BasePlugin):
    """
    This plugin query url/ip in abuse IP DB database
    """

    name = "AbuseIPDB"
    description = "This plugin query url/ip in abuse IP DB database"
    tags = ["ip", "domain"]

    @staticmethod
    def run(check: Check, logger: logging.Logger = logging) -> Plugin:
        # Stringify the data
        data = str(check.data)

        # Default output
        output = "Couldn't reach url: " + data

        if AbuseIPDBPlugin._check_url(data):
            output = AbuseIPDBPlugin._execute_plugin(data)

        return Plugin(check.id, AbuseIPDBPlugin.name, data, output)

    @staticmethod
    def print(output: str, logger: logging.Logger = logging):
        """
        Prettiy print the output of the plugin

        Parameters:
            output (str): Output of the plugin
            logger (Logger): Logger (optional)
        """
        logger.info("IP address:          ", output["data"]["ipAddress"])
        logger.info("ISP:                 ", output["data"]["isp"])
        logger.info("Ip country location: ", output["data"]["countryCode"])
        logger.info("Ip Domain:           ", output["data"]["domain"])

    @staticmethod
    def _execute_plugin(data, logger: logging.Logger = logging) -> dict:
        """
        Query url/ip in VirusTotal v3 database

        Parameters:
            url (str): url/ip to be checked
            logger (Logger): Logger (optional)

        Returns:
            dict: VirusTotal analysis
        """
        try:
            querystring = {
                "ipAddress": socket.gethostbyname(urllib3.get_host(data)[1]),
                "maxAgeInDays": "90",
            }

            headers = {"Accept": "application/json", "Key": ABUSE_IPDB_KEY}

            response = requests.request(
                method="GET",
                url=ABUSE_IPDB_URL,
                headers=headers,
                params=querystring,
                timeout=10,
            )
            
            decodedResponse = json.loads(response.text)

            return decodedResponse

        except Exception as e:
            logger.info(e)
            return "Couldn't reach url: " + data

    @staticmethod
    def _check_url(url, logger: logging.Logger = logging) -> bool:
        try:
            socket.gethostbyname(urllib3.get_host(url)[1])
            return True
        except Exception as e:
            logger.info(e)
            return False
