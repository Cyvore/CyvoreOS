import datetime
from pathlib import Path
import logging
from typing import Optional
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

            host_dict["domain_age"] = WhoisPlugin._calculate_domain_age(host_dict.get("creation_date"), logger)

            # change domain list from list to string
            if isinstance(host_dict.get("domain_name"), list):
                host_dict["domain_name"] = host_dict["domain_name"][0].lower()

            # search for domain in 500DB
            try:
                file_path = "cyvoreos\\resources\\top500domains.txt"
                domain_list = open(file_path, "r", encoding="utf-8").read().split("\n")

            except Exception as e:
                logger.debug(str(e))
                logger.debug("try use local file instead")
                p = Path(__file__).with_name("top500domains.txt")
                domain_list = open(p, "r", encoding="utf-8").read().split("\n")

            host_dict["verified"] = True if host_dict["domain_name"] in domain_list else False

            return host_dict

        except Exception as e:
            logger.error("Error executing whois plugin", exc_info=e)

        return None
    
    @staticmethod
    def _calculate_domain_age(creation_date: Optional[datetime.datetime], logger: logging.Logger = logging) -> Optional[int]:
        """
        Calculate the age of a domain name in days
        """
        if not creation_date:
            logger.warning("No creation date found")
            return None
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        return (datetime.datetime.now() - creation_date).days

    @staticmethod
    def _calculate_score(output: dict) -> float:
        domain_age = output.get("domain_age")
        if domain_age is None:
            return 0.0

        if domain_age <= 7:
            return 70.0
        elif domain_age <= 30:
            return 50.0
        elif domain_age <= 90:
            return 30.0
        else:
            return 0.0
