"""Virustotal plugin for Cyvoreos"""

import os
import time
import logging
import vt
from cyvoreos.plugins.base_plugin import BasePlugin
from typing import Optional

VIRUS_TOTAL_KEY = None

try:
    VIRUS_TOTAL_KEY = os.environ["VIRUS_TOTAL_KEY"]
except Exception as ex:
    logging.info("'VIRUS_TOTAL_KEY' wasn't found: %s", ex)

WAIT = 4.5
MAX_TRIES = 4


def set_virus_total_key(key: str):
    """Set the VirusTotal key

    Parameters:
        key (str): VirusTotal key

    """
    global VIRUS_TOTAL_KEY
    VIRUS_TOTAL_KEY = key


class VirusTotalPlugin(BasePlugin):
    """
    VirusTotal plugin for CyvoreOS
    """

    name = "VirusTotal"
    description = "This plugin query url/ip in VirusTotal v3 database"
    tags = ["url", "domain"]

    @staticmethod
    def run(data: str, logger: logging.Logger = logging) -> tuple[Optional[dict], float]:
        """Run the VirusTotal plugin

        Parameters:
            data (str): url/ip to be checked
            logger (logging.Logger): logger

        Returns:
            tuple[Optional[dict], float]: VirusTotal analysis and score

        """
        if VIRUS_TOTAL_KEY is None:
            logger.warning("VirusTotal key not found")
            return None, 0.0

        output = VirusTotalPlugin._execute_plugin(data, logger)

        if output is None:
            return None, 0.0

        score = VirusTotalPlugin._calculate_score(output)

        return output, score

    @staticmethod
    def print(output: str, logger: logging.Logger = logging):
        logger.info(output)

    @staticmethod
    def _execute_plugin(url, logger: logging.Logger = logging) -> Optional[dict]:
        """
        Query url/ip in VirusTotal v3 database

        Parameters:
            url (str): url/ip to be checked

        Returns:
            dict: VirusTotal analysis

        """
        try:
            with vt.Client(VIRUS_TOTAL_KEY) as client:
                analysis = client.scan_url(url)
                try_count = 0

                while try_count < MAX_TRIES:
                    analysis = client.get_object("/analyses/{}", analysis.id)

                    if analysis.status == "completed":
                        return analysis.to_dict()
                    try_count += 1
                    time.sleep(WAIT)

        except Exception as e:
            logger.error("Error executing virus total plugin", exc_info=e)

        return None

    @staticmethod
    def _calculate_score(output: dict) -> float:
        """
        Calculate the score of the VirusTotal plugin

        Parameters:
            output (dict): VirusTotal analysis

        Returns:
            float: Score of the VirusTotal plugin

        """
        if output.get("attributes", {}).get("stats", {}).get("malicious", 0) > 0:
            return output.get("attributes", {}).get("stats", {}).get("malicious", 0) * 4.0

        return 0.0
