from datetime import datetime
import socket
import logging
import re
import ipaddress
import urlexpander

IPV4REGEX = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
IPV6REGEX = r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
URLREGEX = r"(?i)(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})"
EMAILREGEX = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"4e
class Plugin:
    """
    Plugin is part of check type which holds all plugins output for a check 
    """
    def __init__(self, checkID, pluginName, raw, output):
        self.checkID = checkID
        self.plugingName = pluginName
        self.raw = raw
        self.output = output
        self.timestamp = datetime.now().strftime("%m%d%Y%H%M%S")
    
    def getDict(self):
        """
        Convert plugin object into dictionary
        """
        plugin_dict = {"checkID" : self.checkID, "plugingName": self.plugingName, "raw" : self.raw,"output": self.output, "timestamp" : self.timestamp}
        return plugin_dict
      
class Check:
    """
    Check is an object to test against nrw plugins.
    When check is made as part of a Case object it will hold one value, url/file/crypto wallet.
    When check is self made it could hold all types of data in raw. 
    """
    def __init__(self, caseID, raw, tag=[]):
        self.raw = raw
        self.reputation = 0
        self.hash = ""
        self.plugins = []
        self.checkID = self.getID()
        self.caseID = caseID
        self.tags = []
        if tag and type(tag) == list:
            self.tags = tag
        self.timestemp = datetime.now().strftime("%m%d%Y%H%M%S")
    
    def getDict(self):
        """
        Convert check object into dictionary
        """
        check_dict = {"rawData" : self.raw, "reputation": self.reputation, "checkID" : self.checkID, "plugins" : [], "hash" : self.hash}
        for plg in self.plugins:
            check_dict["plugins"].append(plg.getDict())
        return check_dict
        
    def getID(self):
        """
        Create ID from the checked value: 
         - hash   (if not exist)
         - url    (if not exist)
         - wallet (if not exist)
         - empty string.
        """
        # logic TBD
        if self.hash != "":
            id = self.hash
        elif self.raw != "":
            id = self.raw
        else:
            id = ""
        return id
    
    def isEmpty(self):
        """
        Boolean funtion: return false if any of the fields is set. 
         - hash    
         - url     
         - wallet  
         - checkID 
         """
        if self.raw == "" and self.hash == "" and self.checkID == "":
            return True
        return False
    
    def add_plugin(self,pluginName, output):
        """
        Boolean function: returns true if plugin successfully added
        """
        if output == "":
            return False
        current_plugin = Plugin(self.checkID, pluginName, self.raw, output)
        self.plugins.append(current_plugin)
        return True

 
class Case:
    """
    Case is an object to investigate multiple leads from the same source. 
    checkArray will hold every lead and will only repersent one value - url/file/crypto wallet.
    """  
    def __init__(self, raw):
        logging.info("Initializing Case")
        self.caseID = self.getCaseID()
        self.checkArray = []
        self.raw = raw
        self.createChecks()
        self.timestemp = datetime.now().strftime("%m%d%Y%H%M%S")
        logging.debug(f"Created case {self.caseID} with {self.size()} checks")
        
    def getCaseID(self):
        """
        Create case ID from current time and host name, may changed TBD
        """
        # logic TBD
        timeStamp = datetime.now().strftime("%m%d%Y%H%M%S")
        hostPart = socket.gethostname()
        id = "%s-%s"%(timeStamp, hostPart)
        return id
    
    def urlchecks(self):
        """
        Create check for every unique urls in raw data
        """
        try:
            logging.info("Querying for URLs")
            urls = re.findall(URLREGEX, self.raw)
            if len(urls) > 0:        
                logging.debug("Create checks for URLs:")

                # Casting for getUniques.
                if type(urls) != list or type(urls) != tuple:
                    urls = list(urls)
                for url in self.getUniques(urls):
                    try:
                        if urlexpander.is_short(url):
                            url = urlexpander.expand(url)
                    except Exception as e:
                        logging.info(e)
                    tmpChk = Check(self.caseID, url,["url"])
                    self.checkArray.append(tmpChk)   
                    logging.debug(f"\t{url}") 
            else:
                logging.warning(f"No URLs found in case.")
        except Exception as e:
            logging.info(e)
            return ""
    
    def ipchecks(self):
        """
        Create check for every unique ip in raw data
        """
        logging.info("Querying for IPs")
        ips =  re.findall(IPV4REGEX, self.raw) + re.findall(IPV6REGEX, self.raw)
        if len(ips) > 0:
            logging.debug("Create checks for URLs:")
            for cur_ip in ips:
                try:
                    ip = ipaddress.ip_address(cur_ip)
                    tmpChk = Check(self.caseID, ip.exploded, ["ip"])
                    self.checkArray.append(tmpChk)   
                    logging.debug(f"\t{ip.exploded}") 
                except ValueError:
                    logging.debug(f'address/netmask is invalid: {cur_ip}')
    
    def emailChecks(self):
        """
        Create check for every unique email addresses in raw data
        """
        try:
            logging.info("Querying for Email addresses")
            emails_ad =  re.findall(EMAILREGEX, self.raw)
            if len(emails_ad) > 0:        
                logging.debug("Create checks for Email addresses:")

                # Casting for getUniques.
                if type(emails_ad) != list or type(emails_ad) != tuple:
                    email_ad = list(emails_ad)
                for email_ad in self.getUniques(emails_ad):
                    tmpChk = Check(self.caseID, email_ad, ["email"])
                    self.checkArray.append(tmpChk)   
                    logging.debug(f"\t{email_ad}") 
            else:
                logging.warning(f"No Email addresses found in case.")
        except Exception as e:
            logging.info(e)
            return ""

    def getUniques(self, data):
        unique_data = []
        for i in data: 
            # check if exists in unique_list or not 
            if i not in unique_data: 
                unique_data.append(i) 
        return unique_data

    def size(self):
        """
        Return the amount of checks in the case
        """
        return len(self.checkArray)
    
    def createChecks(self):
        """
        Create checks array from raw data, check could be either one url/file/crypto wallet.
        Changing self.checkArray. 
        """
        logging.info("Creating Checks...")
        try:
            self.urlchecks()
        except Exception as e:
            logging.warning(e)
        try:
            self.ipchecks()
        except Exception as e:
            logging.warning(e)
        try:
            self.emailChecks()
        except Exception as e:
            logging.warning(e)
        for chk in self.checkArray:
            logging.debug(f"\t {chk.raw}")
    
    def getDict(self):
        """
        Convert case object into dictionary
        """
        case_dict = {"caseID" : self.caseID, "raw" : self.raw, "checks": [] ,"timestamp" : self.timestemp}
        for chk in self.checkArray:
            case_dict["checks"].append(chk.getDict())
        return case_dict
