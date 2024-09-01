import logging
import requests
from cyvoreos.check_types import Check, Plugin
from cyvoreos.plugins.base_plugin import BasePlugin

class URLhausPlugin(BasePlugin):
    """
    URLhaus plugin for CyvoreOS
    """

    name = "URLhaus"
    description = "This plugin query url in URLhaus database"
    tags = ["url"]

    @staticmethod
    def run(check: Check, logger: logging.Logger = logging) -> Plugin:
        # Stringify the data
        data = str(check.data)

        # Run the plugin
        output = URLhausPlugin._execute_plugin(data, logger)
        
        # Return the plugin
        return Plugin(check.id, URLhausPlugin.name, data, output)

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
            # Request URLhaus
            res = requests.post('https://urlhaus-api.abuse.ch/v1/url/', { 'url': data }, timeout=10)

            # Check the response
            if (res.status_code != 200):
                raise Exception(f"Error while querying URLhaus API: {res.status_code}")

            # Parse the response
            json_response = res.json()

            if json_response['query_status'] == 'ok':
                return json_response
            elif json_response['query_status'] == 'no_results':
                return json_response
            else:
                raise Exception(f"Error while querying URLhaus API: {json_response['query_status']}")
        
        except Exception as e:
            logger.warning(e)
            
        return {}
    