from urlextract import URLExtract
from datetime import datetime
import socket
import logging

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
    def __init__(self, caseID, raw):
        self.raw = raw
        self.reputation = 0
        self.hash = ""
        self.plugins = []
        self.checkID = self.getID()
        self.caseID = caseID
        self.timestemp = datetime.now().strftime("%m%d%Y%H%M%S")
        
    def getUrls(self):
        """
        Get urls from raw data
        """
        return URLExtract().find_urls(self.raw)
    
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
        elif self.getUrls() != "":
            id = self.getUrls()[0]
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
    
    def getUrls(self):
        """
        Get urls from raw data
        """
        print("self.raw =",self.raw)
        print("URLExtract().find_urls(self.raw) =",URLExtract().find_urls(self.raw))
        return URLExtract().find_urls(self.raw)
    
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
        unique_urls = []
        urls = self.getUrls()
        if len(urls) > 0:        
                
            for i in urls: 
                # check if exists in unique_list or not 
                if i not in unique_urls: 
                    unique_urls.append(i) 
            logging.debug("Create checks for URLs:")
            
            print("Create checks for URLs:")
            for url in unique_urls:
                tmpChk = Check(self.caseID, url)
                self.checkArray.append(tmpChk)    
            logging.debug(f"Checks in case: {self.caseID}:")
            
            print(f"Checks in case: {self.caseID}:") 
            for chk in self.checkArray:
                logging.debug(f"\t {chk.raw}")
                print("\t" + chk.raw)
        else:
            logging.warning(f"No URLs found in case.")
            print("No URLs found")
        
    
    def getDict(self):
        """
        Convert case object into dictionary
        """
        case_dict = {"caseID" : self.caseID, "raw" : self.raw, "checks": [] ,"timestamp" : self.timestemp}
        for chk in self.checkArray:
            case_dict["checks"].append(chk.getDict())
        return case_dict
