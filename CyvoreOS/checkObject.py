from urlextract import URLExtract
import argparse
from datetime import datetime
import socket
import logging

class Check:
    """
    Check is an object to test against nrw plugins.
    When check is made as part of a Case object it will hold one value, url/file/crypto wallet.
    When check is self made it could hold all types of data in raw. 
    """
    def __init__(self):
        self.raw = ""
        self.reputation = 0
        self.hash = ""
        self.pluginOutput = {}
        self.checkID = self.getID()
        
    def getUrls(self):
        """
        Get urls from raw data
        """
        return URLExtract().find_urls(self.raw)
    
    def getDict(self):
        """
        Convert check object into dictionary
        """
        check_dict = {"rawData" : self.raw, "reputation": self.reputation, "checkID" : self.checkID, "plugins" : self.pluginOutput, "hash" : self.hash}
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
            id = self.getUrls()
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

 
class Case:
    """
    Case is an object to investigate multiple leads from the same source. 
    checkArray will hold every lead and will only repersent one value - url/file/crypto wallet.
    """  
    def __init__(self):
        self.caseID = self.getCaseID()
        self.checkArray = []
        self.raw = ""
        
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
        return URLExtract().find_urls(self.raw)
    
    def size(self):
        """
        Return the amount od checks in the case
        """
        return len(self.checkArray)
        
    def createChecks(self):
        """
        Create checks array from raw data, check could be either one url/file/crypto wallet.
        Not changing self.checkArray but returning new checks array. 
        """
        testCase = self
        tmp = []
        if len(testCase.getUrls()) > 0:            
            for i in testCase.getUrls(): 
                # check if exists in unique_list or not 
                if i not in tmp: 
                    tmp.append(i) 
            testCase.raw = str(tmp)
            logging.debug("Create checks for URLs:")
            print("Create checks for URLs:")
            for i in testCase.getUrls():
                tmpChk = Check()
                tmpChk.raw = i
                testCase.checkArray.append(tmpChk)
            logging.debug(f"Checks in case: {testCase.caseID}:")
            print(f"Checks in case: {testCase.caseID}:") 
            for chk in testCase.checkArray:
                logging.debug(f"\t {chk.raw}")
                print("\t" + chk.raw)
        else:
            logging.warning(f"No URLs found in case.")
            print("No URLs found")
        return testCase.checkArray
    
    def getDict(self):
        """
        Convert case object into dictionary
        """
        case_dict = {"caseID" : self.caseID, "raw" : self.raw, "Checks": [] }
        for chk in self.checkArray:
            case_dict["Checks"].append(chk.getDict())
        return case_dict