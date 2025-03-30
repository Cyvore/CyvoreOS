"""AbuseIPDB plugin for CyvoreOS"""

import json
import logging
import os
import socket
import requests
import urllib3
from cyvoreos.plugins.base_plugin import BasePlugin
from typing import Optional

ABUSE_IPDB_KEY = None

try:
    ABUSE_IPDB_KEY = os.environ["ABUSE_IPDB_KEY"]
    ABUSE_IPDB_URL = "https://api.abuseipdb.com/api/v2/check"
except Exception as ex:
    logging.info("'ABUSE_IPDB_KEY' wasn't found: %s", ex)


def set_abuse_ipdb_key(key: str):
    """Set the AbuseIPDB key

    Parameters:
        key (str): AbuseIPDB key
    """
    global ABUSE_IPDB_KEY
    ABUSE_IPDB_KEY = key


class AbuseIPDBPlugin(BasePlugin):
    """
    This plugin query url/ip in abuse IP DB database
    """

    name = "AbuseIPDB"
    description = "This plugin query url/ip in abuse IP DB database"
    tags = ["ip", "domain"]

    @staticmethod
    def run(data: str) -> tuple[Optional[dict], float]:
        if AbuseIPDBPlugin._check_url(data):
            output = AbuseIPDBPlugin._execute_plugin(data)

            if output is None:
                return None, 0.0

            score = AbuseIPDBPlugin._calculate_score(output)
            return output, score

        else:
            return None, 0.0

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
    def _execute_plugin(data, logger: logging.Logger = logging) -> Optional[dict]:
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
            logger.error("Error executing abuse ip db plugin", exc_info=e)
            return None

    @staticmethod
    def _check_url(url, logger: logging.Logger = logging) -> bool:
        try:
            socket.gethostbyname(urllib3.get_host(url)[1])
            return True
        except Exception as e:
            logger.error("Error checking url", exc_info=e)
            return False

    @staticmethod
    def _calculate_score(output: dict) -> float:
        score = 0.0

        if output.get("data", {}).get("isWhitelisted"):
            return score

        if output.get("data", {}).get("abuseConfidenceScore") > 24:
            score += 10.0

        # Check if the ip is tor.
        if output.get("data", {}).get("isTor"):
            score += 10.0

        # Check total reports.
        if output.get("data", {}).get("totalReports") > 0:
            score += 10.0 * output.get("data", {}).get("totalReports")

        return score
