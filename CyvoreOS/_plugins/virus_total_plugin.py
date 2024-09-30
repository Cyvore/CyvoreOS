"""Virustotal plugin for Cyvoreos"""

import os
import time
import logging
import vt
from cyvoreos.check_types import Check, Plugin
from cyvoreos.plugins.base_plugin import BasePlugin

try:
    VIRUS_TOTAL_KEY = os.environ['VIRUS_TOTAL_KEY']
except Exception as ex:
    logging.info("'VIRUS_TOTAL_KEY' wasn't found: %s", ex)

WAIT = 4.5
MAX_TRIES = 4

class VirusTotalPlugin(BasePlugin):
    """
    VirusTotal plugin for CyvoreOS
    """

    name = "VirusTotal"
    description = "This plugin query url/ip in VirusTotal v3 database"
    tags = ["url", "domain"]

    @staticmethod
    def run(check: Check, logger: logging.Logger = logging) -> Plugin:

        # Stringify the data
        data = str(check.data)

        # Run the plugin
        output = VirusTotalPlugin._execute_plugin(data, logger)
        
        # Return the plugin
        return Plugin(check.id, VirusTotalPlugin.name, data, output)

    @staticmethod
    def print(output: str, logger: logging.Logger = logging):
        logger.info(output)
    
    @staticmethod
    def _execute_plugin(url, logger: logging.Logger = logging) -> dict:
        """
        Query url/ip in VirusTotal v3 database

        Parameters:
            url (str): url/ip to be checked

        Returns:
            dict: VirusTotal analysis
        """
        try:
            client = vt.Client(VIRUS_TOTAL_KEY)
            analysis = client.scan_url(url)
            cur = 0

            while cur < MAX_TRIES:
                analysis = client.get_object("/analyses/{}", analysis.id)

                if analysis.status == "completed":
                    return analysis.to_dict()
                cur += 1
                time.sleep(WAIT)

        except Exception as e:
            logger.info(e)

        return ""
    