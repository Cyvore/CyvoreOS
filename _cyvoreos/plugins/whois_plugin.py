import datetime
from pathlib import Path
import logging
from typing import Optional, Union
import whois
import whois.whois
from cyvoreos.plugins.base_plugin import BasePlugin


class WhoisPlugin(BasePlugin):
    """
    Whois plugin for CyvoreOS
    """

    name = "Whois"
    description = "This plugin query domain/ip in whois database"
    tags = ["domain"]

    @staticmethod
    def run(data: str, logger: logging.Logger = logging) -> tuple[Optional[dict], float]:
        output = WhoisPlugin._execute_plugin(data, logger)

        if output is None:
            return None, 0.0

        score = WhoisPlugin._calculate_score(output)

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
            host_dict = whois.whois(data)
            host_dict = dict(host_dict)

            # change domain list from list to string
            if isinstance(host_dict.get("domain_name"), list):
                host_dict["domain_name"] = host_dict["domain_name"][0].lower()

            # search for domain in 500DB
            try:
                file_path = "cyvoreos\\resources\\top500domains.txt"
                domain_list = open(file_path, "r", encoding="utf-8").read().split("\n")

            except Exception as e:
                logger.warning(str(e))
                logger.info("try use local file instead")
                p = Path(__file__).with_name("top500domains.txt")
                domain_list = open(p, "r", encoding="utf-8").read().split("\n")

            host_dict["verified"] = True if host_dict["domain_name"] in domain_list else False

            return host_dict

        except Exception as e:
            logger.error("Error executing whois plugin", exc_info=e)

        return None

    @staticmethod
    def _calculate_score(output: dict) -> float:
        if output.get("creation_date", ""):
            creation_date: Union[datetime.datetime, list[datetime.datetime]] = output.get("creation_date", "")

            if not isinstance(creation_date, list):
                creation_date = [creation_date]

            for date in creation_date:
                date = date.astimezone(datetime.timezone.utc)

                # If the date is in the last 180 days, return 20.0
                if date > (datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(days=180)):
                    return 20.0
                # If the date is in the last 365 days, return 10.0
                elif date > (datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(days=365)):
                    return 10.0

            return 0.0
        else:
            return 0.0
