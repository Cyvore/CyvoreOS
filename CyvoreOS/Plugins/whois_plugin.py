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

        # add verified field
        hostDict.update({ 'verified': False })

        # search for domain in 500DB
        urlManifest = requests.get('https://raw.githubusercontent.com/Cyvore/IconDB/master/Resources/top500urls.txt').text.split('\n')
        for url in urlManifest:
            if hostDict['domain_name'] in url:
                hostDict['verified'] = True
                break

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
