import whois
import logging

def whois_plugin(data):
    try:
        hostDict = whois.whois(data)

        # change domain list from list to string
        if isinstance(hostDict.get('domain_name'), list):
            hostDict['domain_name'] = hostDict['domain_name'][0].lower()

        # add verified field
        hostDict.update({ 'verified': False })

        # search for domain in 500DB
        with open ('CyvoreOS/Resources/top500urls.txt', 'r') as urls:
            for url in urls:
                if hostDict['domain_name'] in url:
                    hostDict['verified'] = True
                    break
            urls.close()
        
        return hostDict
    except Exception as e:
        logging.warning(e)

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