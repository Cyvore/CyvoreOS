import Levenshtein as lev
from urllib.parse import urlparse
import requests
import re

MIRROREGEX = r"Mirrored from (\S*) "
SERVICES = ["microsoft", "paypal", "outlook", "linkedin", "facebook", "amazon", "twitter", "steam", "netflix"]
UAHEADERS = {'User-Agent':
                 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
}

def strip_scheme(url):
    parsed = urlparse(url)
    scheme = "%s://" % parsed.scheme
    return parsed.geturl().replace(scheme, '', 1)

def checkUrlImper(url):
    phishurl = strip_scheme(url)
    for service in SERVICES:
        res = []
        k = len(service) - 1
        for i in range(3):
            res += [phishurl[i: j] for i in range(len(phishurl)) for j in range(i + 1, len(phishurl) + 1) if len(phishurl[i:j]) == k]
            k += 1
        #print(res)
        for sub in res:
            d = lev.distance(service.lower(),sub.lower())
            if (d < 3):
                print("[+] matched {}!!".format(service))
                return service
    return None


def checkSourceCodeMirrorAndImper(url):
    response = requests.get(url, headers=UAHEADERS)
    source = response.text.lower()
    if "Mirrored" in source:
        mirror = re.search(MIRROREGEX, source)
        return mirror.group()
    for service in SERVICES:
        matches = re.findall(service, source)
        if matches:
            print("[+] matched {}!!".format(service))
            return service
    return None
