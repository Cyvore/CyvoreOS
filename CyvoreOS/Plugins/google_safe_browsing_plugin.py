import os
import logging
import requests
from cyvoreos.check_types import Check, Plugin
from cyvoreos.plugins.base_plugin import BasePlugin

# Google Safe Browsing API key
try:
    API_KEY = os.environ["GOOGLE_SAFE_BROWSING_API_KEY"]
except Exception as ex:
    logging.info("'GOOGLE_SAFE_BROWSING_API_KEY' wasn't found: %s", ex)

# Google Safe Browsing API v5 URL
API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'

class GoogleSafeBrowsingPlugin(BasePlugin):
    """
    GoogleSafeBrowsing plugin for CyvoreOS
    """

    name = "GoogleSafeBrowsing"
    description = "This plugin query url in GoogleSafeBrowsing database"
    tags = ["url"]

    @staticmethod
    def run(check: Check, logger: logging.Logger = logging) -> Plugin:
        # Stringify the data
        data = str(check.data)

        # Run the plugin
        output = GoogleSafeBrowsingPlugin._execute_plugin(data, logger)
        
        # Return the plugin
        return Plugin(check.id, GoogleSafeBrowsingPlugin.name, data, output)

    @staticmethod
    def print(output: str, logger: logging.Logger = logging):
        """
        Prettiy print the output of the plugin

        Parameters:
            output (str): Output of the plugin
        """

        logger.info(output)
    
    @staticmethod
    def _execute_plugin(data, logger: logging.Logger = logging) -> dict:
        try:
            # Define the payload with the URL to be checked
            payload = {
                "client": {
                    "clientId": "cyvoreos",
                    "clientVersion": "1.0"
                },
                "threatInfo": {
                    "threatTypes": ["THREAT_TYPE_UNSPECIFIED", "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{ "url": data }]
                }
            }

            params = { 'key': API_KEY }

            # Request URLhaus
            res = requests.post(API_URL, json=payload, params=params, timeout=10)

            # Check the response
            if (res.status_code != 200):
                raise Exception(f"Error while querying GoogleSafeBrowsing API: {res.status_code}")

            # Parse the response
            json_response = res.json()

            if not json_response:
                return { "matches": [] }

            return json_response
        
        except Exception as e:
            logger.warning(e)
            
        return {}
    
    