import requests
import socket
import sys
import urllib3
import json
import logging
import os

ABUSE_IPDB_KEY = os.environ['ABUSE_IPDB_KEY']
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
    if status == '200':
        return True
    return False

def run_check(chk):
    plugin_name = "AbuseIPDB"
    output = chk.raw + " Not a valid url"
    if checkUrl(chk.raw):
        output = abuseIPDBCheck(chk.raw)
    chk.add_plugin(plugin_name,output)
    
def describe():
    desc = """This plugin query url/ip in abuse IP DB database """
    return desc

def tags():
    tags_list = ["ip", "domain"]
    return tags_list
