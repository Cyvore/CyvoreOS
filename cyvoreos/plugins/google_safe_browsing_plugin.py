import os
import logging
import requests
from cyvoreos.plugins.base_plugin import BasePlugin
from typing import Optional

GOOGLE_SAFE_BROWSING_API_KEY = None

# Google Safe Browsing API key
try:
    GOOGLE_SAFE_BROWSING_API_KEY = os.environ["GOOGLE_SAFE_BROWSING_API_KEY"]
except Exception as ex:
    logging.info("'GOOGLE_SAFE_BROWSING_API_KEY' wasn't found: %s", ex)


def set_google_safe_browsing_api_key(key: str):
    """Set the Google Safe Browsing API key

    Parameters:
        key (str): Google Safe Browsing API key
    """
    global GOOGLE_SAFE_BROWSING_API_KEY
    GOOGLE_SAFE_BROWSING_API_KEY = key


# Google Safe Browsing API v5 URL
API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


class GoogleSafeBrowsingPlugin(BasePlugin):
    """
    GoogleSafeBrowsing plugin for CyvoreOS
    """

    name = "GoogleSafeBrowsing"
    description = "This plugin query url in GoogleSafeBrowsing database"
    tags = ["url"]

    @staticmethod
    def run(data: str, logger: logging.Logger = logging) -> tuple[Optional[dict], float]:
        output = GoogleSafeBrowsingPlugin._execute_plugin(data, logger)

        if output is None:
            return None, 0.0

        score = GoogleSafeBrowsingPlugin._calculate_score(output)

        return output, score

    @staticmethod
    def print(output: str, logger: logging.Logger = logging):
        """
        Prettiy print the output of the plugin

        Parameters:
            output (str): Output of the plugin
        """

        logger.info(output)

    @staticmethod
    def _execute_plugin(data, logger: logging.Logger = logging) -> Optional[dict]:
        try:
            # Define the payload with the URL to be checked
            payload = {
                "client": {"clientId": "cyvoreos", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["THREAT_TYPE_UNSPECIFIED", "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": data}],
                },
            }

            params = {"key": GOOGLE_SAFE_BROWSING_API_KEY}

            # Request URLhaus
            res = requests.post(API_URL, json=payload, params=params, timeout=10)

            # Check the response
            if res.status_code != 200:
                raise Exception(f"Error while querying GoogleSafeBrowsing API: {res.status_code}")

            # Parse the response
            json_response = res.json()

            if not json_response:
                return {"matches": []}

            return json_response

        except Exception as e:
            logger.error("Error executing google safe browsing plugin", exc_info=e)

        return None

    @staticmethod
    def _calculate_score(output: dict) -> float:
        score = 0.0

        if len(output.get("matches", [])) > 0:
            score = 100.0

        return score
