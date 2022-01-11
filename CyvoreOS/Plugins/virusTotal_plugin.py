import requests
import json
import time
from colorama import init, Fore, Back, Style
import os
import logging

VIRUS_TOTAL_KEY = os.environ['VIRUS_TOTAL_KEY']
VIRUS_TOTAL_URL = 'https://www.virustotal.com/vtapi/v2/url/scan'
urlvtreport = 'https://www.virustotal.com/vtapi/v2/url/report' 


def vturlcheck(myurl, param):
    output = []
    pos = ''
    total = ''
    vttext = ''
    response = ''
    resource = ''
    bkg = 0
    try:
        resource = myurl
        params = {'apikey': VIRUS_TOTAL_KEY , 'url': resource, 'allinfo': True}
        response = requests.post(VIRUS_TOTAL_URL, params=params)
        vttext = json.loads(response.text)
        output.append(vttext)
        rc = (vttext['response_code'])
        if (rc == 0):
            logging.info('Error during URL checking')
            return
        try:

            resource=vttext['url']
            params = {'apikey': VIRUS_TOTAL_KEY , 'resource': resource}
            response = requests.get(urlvtreport, params=params)
            vttext = json.loads(response.text)
            output.append(vttext)
            rc = (vttext['response_code'])
            if (rc == 0):
                logging.info('Error gathering the Report.')
                return
            return output
            

        except ValueError:
            logging.info("Error while connecting to Virus Total!\n")

    except ValueError:
        logging.info("Error while connecting to Virus Total!\n")

def virusTotalCheck(url):
    params = {'apikey': VIRUS_TOTAL_KEY, 'url':url}
    response = requests.post(VIRUS_TOTAL_URL, data=params)
    return response

def run_check(chk):
    plugin_name = "virusTotal"
    output = vturlcheck(chk.raw, 'params')
    chk.add_plugin(plugin_name,output)
        
def describe():
    desc = """This plugin query url/ip in VirusTotal database """
    return desc

def tags():
    tags_list = ["url", "file", "ip", "hash", "domain"]
    return tags_list
