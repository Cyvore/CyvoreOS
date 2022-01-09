import whois
import logging

def whois_plugin(data):
    try:
        hostDict = whois.whois(data)
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
    tags_list = ["domain", "ip"]
    return tags_list
