import whois
import logging
import requests

def whois_plugin(data):
    try:
        hostDict = whois.whois(data)
        hostDict = dict(hostDict)

        # change domain list from list to string
        if isinstance(hostDict.get('domain_name'), list):
            hostDict['domain_name'] = hostDict['domain_name'][0].lower()

        # search for domain in 500DB
        domainList = open('CyvoreOS\\Resources\\top500domains.txt', 'r').read().split('\n')
        hostDict['verified'] = True if hostDict['domain_name'] in domainList else False

        return hostDict
    except Exception as e:
        logging.warning(e)
    return ''


def run_check(chk):
    plugin_name = "Whois"
    output = whois_plugin(chk.raw)
    chk.add_plugin(plugin_name,output)


def describe():
    desc = """This plugin query domain/ip in whois database """
    return desc


def tags():
    # Todo: consider adding support for ips
    tags_list = ["domain"]
    return tags_list