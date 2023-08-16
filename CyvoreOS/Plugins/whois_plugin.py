import whois
import logging
import requests
from pathlib import Path
from CyvoreOS.checkTypes import Check, Plugin

def whois_plugin(data):
    try:
        hostDict = whois.whois(data)
        hostDict = dict(hostDict)

        # change domain list from list to string
        if isinstance(hostDict.get('domain_name'), list):
            hostDict['domain_name'] = hostDict['domain_name'][0].lower()

        # search for domain in 500DB
        try:
            domainList = open('CyvoreOS\\Resources\\top500domains.txt', 'r').read().split('\n')
        except Exception as e:
            logging.warning(e)
            logging.info("try use local file instead")
            p = Path(__file__).with_name('top500domains.txt')
            domainList = open(p, 'r').read().split('\n')
        hostDict['verified'] = True if hostDict['domain_name'] in domainList else False

        return hostDict
    except Exception as e:
        logging.warning(e)
    return ''


def run_check(chk: Check) -> Plugin:
    plugin_name = "Whois"
    data = str(chk.data)
    output = whois_plugin(data)
    return Plugin(chk.id, plugin_name, data, output)


def describe():
    desc = """This plugin query domain/ip in whois database """
    return desc


def tags():
    # Todo: consider adding support for ips
    tags_list = ["domain"]
    return tags_list