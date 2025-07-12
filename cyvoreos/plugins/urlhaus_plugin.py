import os
import logging
import requests
from cyvoreos.plugins.base_plugin import BasePlugin
from typing import Optional

URLHAUS_KEY = None

try:
    URLHAUS_KEY = os.environ["URLHAUS_KEY"]
except Exception as ex:
    logging.info("'URLHAUS_KEY' wasn't found: %s", ex)

WAIT = 4.5
MAX_TRIES = 4


def set_urlhaus_key(key: str):
    """Set the URLhaus key

    Parameters:
        key (str): URLhaus key

    """
    global URLHAUS_KEY
    URLHAUS_KEY = key


class URLhausPlugin(BasePlugin):
    """
    URLhaus plugin for CyvoreOS
    """

    name = "URLhaus"
    description = "This plugin query url in URLhaus database"
    tags = ["url"]

    @staticmethod
    def run(data: str, logger: logging.Logger = logging) -> tuple[Optional[dict], float]:
        output = URLhausPlugin._execute_plugin(data, logger)

        if output is None:
            return None, 0.0

        score = URLhausPlugin._calculate_score(output)

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
            # Request URLhaus
            res = requests.post(
                "https://urlhaus-api.abuse.ch/v1/url/", {"url": data}, timeout=10, headers={"Auth-Key": URLHAUS_KEY}
            )

            # Check the response
            if res.status_code != 200:
                raise Exception(f"Error while querying URLhaus API: {res.status_code}")

            # Parse the response
            json_response = res.json()

            if json_response["query_status"] == "ok":
                return json_response
            elif json_response["query_status"] == "no_results":
                return json_response
            else:
                raise Exception(f"Error while querying URLhaus API: {json_response['query_status']}")

        except Exception as e:
            logger.error("Error executing urlhaus plugin", exc_info=e)

        return None

    @staticmethod
    def _calculate_score(output: dict) -> float:
        score = 0.0

        if output.get("query_status") == "ok":
            score = 100.0

        return score
