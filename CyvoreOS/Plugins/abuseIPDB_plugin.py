
import requests
import socket
import urllib3
import json
from Output import PrettyPrint
import logging

# To Do:
# Tokens and keys in config.yaml file.
ABUSE_IPDB_KEY = '8309daf376e609ab1ed5438210d57283d11f806b4688711732f200cd9acadbc5fdbaec4242d5fefd'
ABUSE_IPDB_URL = 'https://api.abuseipdb.com/api/v2/check'
 
def abuseIPDBCheck(check_url):
    querystring = {
    'ipAddress': socket.gethostbyname(urllib3.get_host(check_url)[1]),
    'maxAgeInDays': '90'
    }
    headers = {
    'Accept': 'application/json',
    'Key': ABUSE_IPDB_KEY
    }
    response = requests.request(method='GET', url=ABUSE_IPDB_URL, headers=headers, params=querystring)
    decodedResponse = json.loads(response.text)
    # 
    # print(json.dumps(decodedResponse, sort_keys=True, indent=4))
    return decodedResponse

def printIPDBoutput(output):
    print("IP address:          ", output["data"]["ipAddress"])
    print("ISP:                 ", output["data"]["isp"])
    print("Ip country location: ", output["data"]["countryCode"])
    print("Ip Domain:           ", output["data"]["domain"])

def checkUrl(url):
    status = "N/A"
    if 'http' not in url:
        url = "http://" + url
    try:
        r = requests.get(url, timeout=5)
        status = str(r.status_code)
    except requests.exceptions.ConnectionError:
        status = "DOWN"
    PrettyPrint.printStatus(url, status)
    if status == '200':
        return True
    return False

def run_check(chk):
    for url in chk.getUrls():
        logging.debug(f"abuseIPDB check: {url}")
        chk.pluginOutput["abuseIPDB"] = []
        print("abuseIPDB check: ", url)
        if checkUrl(url):
            #logging.debug(url," is up")
            json_output = abuseIPDBCheck(url)
            chk.pluginOutput["abuseIPDB"].append(json_output)

def describe():
    desc = """This plugin query url/ip in abuse IP DB database """
    return desc