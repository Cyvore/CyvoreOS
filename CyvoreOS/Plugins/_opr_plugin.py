from bs4 import BeautifulSoup

import requests
import urllib.request
import urllib.parse
import shutil
import re
from checkObject import Check

HEADERS = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}
IMG_REGEX = r'/([\w_-]+[.](jpg|gif|png|jpeg|tiff|psd|al|raw|svg))$'
IMG_REGEX2 = r'(https?:\/\/.*\.(jpg|gif|png|jpeg|tiff|psd|al|raw|svg|ico|bmp))'

def getImgs(site):
    #site = "https://www.msvu.ca/campus-life/campus-services/it-services/it-security/phishing/phishing-login-form-examples/"
    #https://telstra.paypai-login.com/ - telstra phish site
    img_urls = []
    try:
        print("Check for site:", site)
        response = requests.get(site)
        if response.status_code >= 400 or response.status_code < 500:
            response = requests.get(site, headers=HEADERS) 
        
        print("response:",response)
        #print("\t", response.text)
        
        chk = Check()
        chk.raw = response.text
        for url in chk.getUrls():
            filename = re.search(IMG_REGEX2, url)
            if not filename:
                #print("Regex didn't match with the url: {}".format(url))
                continue
            img_urls.append(filename.group(1))
        img_urls.append("https://static.xx.fbcdn.net/rsrc.php/y8/r/dF5SId3UHWd.svg")
        return set(img_urls)
        
    except Exception as e:
        print("[-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-]")
        print("[-]",e)
        print("[-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-]")

def downloadImgs(imgs_list):
    for url in imgs_list:    
        with open("Cases\%s"%urllib.parse.urlparse(url).path.split("/")[-1], 'wb') as f:
            response = requests.get(url)
            if response.status_code >= 400 or response.status_code < 500:
                response = requests.get(url, headers=HEADERS)
            print("Try download url: ", url)
            f.write(response.content)
 
def filterDomain(img_list, dom):
    parsed_dom = urllib.parse.urlparse(dom)
    different_dom_list = []
    print("Filter for any img urls not under %s:"%parsed_dom.netloc)
    for url in img_list:
        parsed_url = urllib.parse.urlparse(url)
        if parsed_dom.netloc != parsed_url.netloc:
            different_dom_list.append(url)
            print("\t%s"%url)
    return different_dom_list

    
def run_check(chk):
    return None
    for url in chk.getUrls():
        print("url: ", url)
        print("------- TEST -------")
        imgList = getImgs(url)
        print("Image list:")
        for i in imgList:
            print("\t",i)
        #downloadImgs(imgList)
        print("\n\n\n\n\n-----------------------------------------------------")
        print("current images from",url)
        filterDomain(imgList,url)
        

def describe():
    desc = """Check Images source"""
    return desc
