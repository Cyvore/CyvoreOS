import requests
import socket
import urllib3
import json
import logging
import os
from CyvoreOS.checkTypes import Check, Plugin

try:
    ABUSE_IPDB_KEY = os.environ['ABUSE_IPDB_KEY']
    ABUSE_IPDB_URL = 'https://api.abuseipdb.com/api/v2/check'
except Exception as e:
    logging.info(f"'ABUSE_IPDB_KEY' wasn't found: {e}")


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
    if status == '200':
        return True
    return False


def run_check(chk: Check) -> Plugin:
    plugin_name = "AbuseIPDB"
    data = str(chk.data)
    output = "Couldn't reach url: " + data
    if checkUrl(data):
        output = abuseIPDBCheck(data)
    return Plugin(chk.id, plugin_name, data, output)


def describe():
    desc = """This plugin query url/ip in abuse IP DB database """
    return desc


def tags():
    tags_list = ["ip", "domain"]
    return tags_list
