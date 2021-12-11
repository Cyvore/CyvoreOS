
import requests
import socket
import sys
import urllib3
import json
import time
from Output.PrettyPrint import mycolors
from colorama import init, Fore, Back, Style

# To Do:
# Tokens and keys in config.yaml file.
VIRUS_TOTAL_KEY = 'a97b1f37ebab28a9059a8c87af0b3270a25e6047b0bb239e1be1b21c4c1f6c18'
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
            final = 'Error during URL checking'
            if (bkg == 1):
                print(mycolors.foreground.lightred + final)
            else:
                print(mycolors.foreground.red + final)
            exit(1)
        if (rc == 1):
            print(mycolors.reset + "\nURL SUMMARY REPORT")
            print("-"*20,"\n")

        if (bkg == 0):
            print(mycolors.foreground.blue + "Status: ".ljust(17),vttext['verbose_msg'])
            print(mycolors.foreground.blue + "Scan date: ".ljust(17),vttext['scan_date'])
            print(mycolors.foreground.blue + "Scan ID: ".ljust(17),vttext['scan_id'])
            print(mycolors.foreground.purple + "URL: ".ljust(17),vttext['url'])
            print(mycolors.foreground.cyan + "Permanent Link: ".ljust(17),vttext['permalink'])
            print(mycolors.foreground.red + "Result VT: ".ljust(17), end=' ')

        else:
            print(mycolors.foreground.lightgreen + "Status: ".ljust(17),vttext['verbose_msg'])
            print(mycolors.foreground.lightgreen + "Scan date: ".ljust(17),vttext['scan_date'])
            print(mycolors.foreground.lightgreen + "Scan ID: ".ljust(17),vttext['scan_id'])
            print(mycolors.foreground.yellow + "URL: ".ljust(17),vttext['url'])
            print(mycolors.foreground.lightcyan + "Permanent Link: ".ljust(17),vttext['permalink'])
            print(mycolors.foreground.lightred + "Result VT: ".ljust(17), end=' ')

        time.sleep(10)

        try:

            resource=vttext['url']
            params = {'apikey': VIRUS_TOTAL_KEY , 'resource': resource}
            response = requests.get(urlvtreport, params=params)
            vttext = json.loads(response.text)
            output.append(vttext)
            rc = (vttext['response_code'])
            if (rc == 0):
                final = 'Error gathering the Report.'
                if (bkg == 1):
                    print(mycolors.foreground.lightred + final)
                else:
                    print(mycolors.foreground.red + final)
                exit(1)
            pos = str(vttext['positives'])
            total = str(vttext['total'])
            final = (pos + "/" + total)
            print(final + "\n")
            return output
            if (bkg == 1):
                print(Fore.WHITE + "URL DETAILED REPORT")
                print("-"*20,"\n")

                if('AlienVault' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "AlienVault: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['AlienVault']['result'])
                if('Avira' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Avira: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Avira']['result'])
                if('BitDefender' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "BitDefender: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['BitDefender']['result'])
                if('Certego' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Certego: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Certego']['result'])
                if('Comodo Valkyrie Verdict' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Comodo: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Comodo Valkyrie Verdict']['result'])
                if('CRDF' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "CRDF: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['CRDF']['result'])
                if('CyRadar' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "CyRadar: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['CyRadar']['result'])
                if('Emsisoft' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Emsisoft: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Emsisoft']['result'])
                if('ESET' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "ESET: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['ESET']['result'])
                if('Forcepoint ThreatSeeker' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Forcepoint: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Forcepoint ThreatSeeker']['result'])
                if('Fortinet' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Fortinet: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Fortinet']['result'])
                if('G-Data' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "G-Data: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['G-Data']['result'])
                if('Google Safebrowsing' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Google: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Google Safebrowsing']['result'])
                if('Kaspersky' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Kaspersky: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Kaspersky']['result'])
                if('malwares.com URL checker' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Malwares.com: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['malwares.com URL checker']['result'])
                if('Malc0de Database' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Malc0de: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Malc0de Database']['result'])
                if('MalwarePatrol' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "MalwarePatrol: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['MalwarePatrol']['result'])
                if('OpenPhish' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "OpenPhish: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['OpenPhish']['result'])
                if('PhishLabs' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "PhishLabs: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['PhishLabs']['result'])
                if('Phishtank' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Phishtank: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Phishtank']['result'])
                if('Spamhaus' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Spamhaus: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Spamhaus']['result'])
                if('Sophos' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Sophos: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Sophos']['result'])
                if('Trustwave' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "Trustwave: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['Trustwave']['result'])
                if('VX Vault' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "VX Vault: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['VX Vault']['result'])
                if('ZeroCERT' in vttext['scans']):
                    print(mycolors.foreground.lightcyan + "ZeroCERT: ".ljust(17),mycolors.foreground.yellow + vttext['scans']['ZeroCERT']['result'])
                print(mycolors.reset + "\n")
                return(0)

            else:
                print(Fore.BLACK + "URL DETAILED REPORT")
                print("-"*20,"\n")
                if('AlienVault' in vttext['scans']):
                    print(mycolors.foreground.cyan + "AlienVault: ".ljust(17),mycolors.foreground.red + vttext['scans']['AlienVault']['result'])
                if('Avira' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Avira: ".ljust(17),mycolors.foreground.red + vttext['scans']['Avira']['result'])
                if('BitDefender' in vttext['scans']):
                    print(mycolors.foreground.cyan + "BitDefender: ".ljust(17),mycolors.foreground.red + vttext['scans']['BitDefender']['result'])
                if('Certgo' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Certego: ".ljust(17),mycolors.foreground.red + vttext['scans']['Certego']['result'])
                if('Comodo Valkyrie Verdict' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Comodo: ".ljust(17),mycolors.foreground.red + vttext['scans']['Comodo Valkyrie Verdict']['result'])
                if('CRDF' in vttext['scans']):
                    print(mycolors.foreground.cyan + "CRDF: ".ljust(17),mycolors.foreground.red + vttext['scans']['CRDF']['result'])
                if('CyRadar' in vttext['scans']):
                    print(mycolors.foreground.cyan + "CyRadar: ".ljust(17),mycolors.foreground.red + vttext['scans']['CyRadar']['result'])
                if('Emsisoft' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Emsisoft: ".ljust(17),mycolors.foreground.red + vttext['scans']['Emsisoft']['result'])
                if('ESET' in vttext['scans']):
                    print(mycolors.foreground.cyan + "ESET: ".ljust(17),mycolors.foreground.red + vttext['scans']['ESET']['result'])
                if('Forcepoint ThreatSeeker' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Forcepoint: ".ljust(17),mycolors.foreground.red + vttext['scans']['Forcepoint ThreatSeeker']['result'])
                if('Fortinet' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Fortinet: ".ljust(17),mycolors.foreground.red + vttext['scans']['Fortinet']['result'])
                if('G-Data' in vttext['scans']):
                    print(mycolors.foreground.cyan + "G-Data: ".ljust(17),mycolors.foreground.red + vttext['scans']['G-Data']['result'])
                if('Google Safebrowsing' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Google: ".ljust(17),mycolors.foreground.red + vttext['scans']['Google Safebrowsing']['result'])
                if('Kaspersky' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Kaspersky: ".ljust(17),mycolors.foreground.red + vttext['scans']['Kaspersky']['result'])
                if('malwares.com URL checker' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Malwares.com: ".ljust(17),mycolors.foreground.red + vttext['scans']['malwares.com URL checker']['result'])
                if('Malc0de Database' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Malc0de: ".ljust(17),mycolors.foreground.red + vttext['scans']['Malc0de Database']['result'])
                if('MalwarePatrol' in vttext['scans']):
                    print(mycolors.foreground.cyan + "MalwarePatrol: ".ljust(17),mycolors.foreground.red + vttext['scans']['MalwarePatrol']['result'])
                if('OpenPhish' in vttext['scans']):
                    print(mycolors.foreground.cyan + "OpenPhish: ".ljust(17),mycolors.foreground.red + vttext['scans']['OpenPhish']['result'])
                if('PhishLabs' in vttext['scans']):
                    print(mycolors.foreground.cyan + "PhishLabs: ".ljust(17),mycolors.foreground.red + vttext['scans']['PhishLabs']['result'])
                if('Phishtank' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Phishtank: ".ljust(17),mycolors.foreground.red + vttext['scans']['Phishtank']['result'])
                if('Spamhaus' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Spamhaus: ".ljust(17),mycolors.foreground.red + vttext['scans']['Spamhaus']['result'])
                if('Sophos' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Sophos: ".ljust(17),mycolors.foreground.red + vttext['scans']['Sophos']['result'])
                if('Truswave' in vttext['scans']):
                    print(mycolors.foreground.cyan + "Trustwave: ".ljust(17),mycolors.foreground.red + vttext['scans']['Trustwave']['result'])
                if('VX Vault' in vttext['scans']):
                    print(mycolors.foreground.cyan + "VX Vault: ".ljust(17),mycolors.foreground.red + vttext['scans']['VX Vault']['result'])
                if('ZeroCERT' in vttext['scans']):
                    print(mycolors.foreground.cyan + "ZeroCERT: ".ljust(17),mycolors.foreground.red + vttext['scans']['ZeroCERT']['result'])
                print(mycolors.reset + "\n")
                exit(0)

        except ValueError:
            if (bkg == 1):
                print(mycolors.foreground.lightred + "Error while connecting to Virus Total!\n")
            else:
                print(mycolors.foreground.red + "Error while connecting to Virus Total!\n")
            print(mycolors.reset)
            return(2)

    except ValueError:
        if (bkg == 1):
            print(mycolors.foreground.lightred + "Error while connecting to Virus Total!\n")
        else:
            print(mycolors.foreground.red + "Error while connecting to Virus Total!\n")
        print(mycolors.reset)
        exit(3)

def virusTotalCheck(url):
    params = {'apikey': VIRUS_TOTAL_KEY, 'url':url}
    response = requests.post(VIRUS_TOTAL_URL, data=params)
    return response

def run_check(chk):
    plugin_name = "virusTotal"
    output = vturlcheck(chk.getUrls(), 'params')
    chk.add_plugin(plugin_name,output)
        
def describe():
    desc = """This plugin query url/ip in VirusTotal database """
    return desc
