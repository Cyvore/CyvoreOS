from CyvoreOS.checkObject import Check
from CyvoreOS.checkObject import Case
import importlib
from CyvoreOS import Plugins
#from CyvoreOS import interfaces
import pkgutil
import string
import logging
#import CyvoreOS.interfaces
import urlexpander
from urllib.parse import urlparse
import re
import ipaddress

IPV4REGEX  = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
IPV6REGEX  = r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
URLREGEX = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
EMAILREGEX = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"

BTCREG     = r"(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}"
DASHREG    = r"X[1-9A-HJ-NP-Za-km-z]{33}"
LTCREG     = r"[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}"
DOGEREG    = r"D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}"
COINS      = [BTCREG, DASHREG, LTCREG, DOGEREG]

logging.basicConfig(filename='cyvore_main.log',
                    level=logging.DEBUG,
                    format='%(asctime)s | %(name)s | %(levelname)s | %(message)s')
printable = set(string.printable)

# Get absolute path for plugins
def iter_namespace(ns_pkg):
    # Specifying the second argument (prefix) to iter_modules makes the
    # returned name an absolute name instead of a relative one. This allows
    # import_module to work without having to do additional modification to
    # the name.
    return pkgutil.iter_modules(ns_pkg.__path__, ns_pkg.__name__ + ".")

# Make all Plugins dictionary 
discovered_plugins = {
    name: importlib.import_module(name)
    for finder, name, ispkg
    in iter_namespace(Plugins)
}

def exitWithLog(msg):
    if msg:
        logging.warning(msg)
    else:
        logging.info("Program finished successfully")
    logging.info("-----------------------------------------------------\n\n\n")
    exit()


def strings(filename, min=4):
    with open(filename, errors="ignore") as f:  # Python 3.x
        result = ""
        for c in f.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= min:
                yield result
            result = ""
        if len(result) >= min:  # catch result at EOF
            yield result


def listplugins():
    logging.info("Running ls option")
    for plugin in discovered_plugins:
        current_plugin = importlib.import_module(plugin)
        output = current_plugin.describe()
        logging.info("\t" + plugin, "-", output)
    exitWithLog("")


"""
# Only for windows developers 
def install():
    logging.info("Running install option")
    path = "\"C:\\Python39\\python.exe\" \"" + __file__ + "\" -uf \"%1\""
    logging.debug(f"Path in registry:\t{path}")
    # interfaces.right_click_install.define_action_on("*", "CheckForPhish", path, title="Run Phish Check")
    logging.info("Installed right click addon")
    exitWithLog("")
"""


def urlFromFileCommand(args):
    testCase = Case(str(list(strings(args.urlFromFIle)))) 
    logging.info(f"Check file:\n\t{args.urlFromFIle}")
    logging.info(f"Create case:\n\t{testCase.caseID}")
    return testCase


def scanstring(testdata, tags=False):
    testCase = Case(testdata)
    logging.info(f"Check string:\n\t{testdata}")
    logging.info(f"Create case:\n\t{testCase.caseID}")
    for plugin in discovered_plugins:
        for chk in testCase.checkArray:
            current_plugin = importlib.import_module(plugin)
            if tags:
                if any(tag in chk.tags for tag in current_plugin.tags()):
                    current_plugin.run_check(chk)
                else:
                    plugin_name = str(plugin).split(".")[-1].strip("_plugin")
                    logging.info(f"Skip plugin {plugin_name} because of tags mismatch: {current_plugin.tags()}")
            else:
                current_plugin.run_check(chk)
    return testCase


def runPlugins(testdata, plugins_list):
    testCase = Case(testdata)
    for plugin in discovered_plugins:
        if plugins_list:
            plugin_name = str(plugin).split(".")[1].strip("_plugin")
            if plugin_name not in plugins_list:
                logging.info(f"Skipping {plugin_name} - plugin flag is on.")
                continue
        elif "debug" in str(plugin).split(".")[1].strip("_plugin"):
            continue
        logging.debug(f"Running plugin: {str(plugin)}")
        for chk in testCase.checkArray:
            
            current_plugin = importlib.import_module(plugin)
            current_plugin.run_check(chk)


def urlAndDomainChecks(case):
    """
    Create check for every unique urls and domain in raw data
    """
    logging.info(f"Checking Url: {case.raw}")
    if re.match(URLREGEX, case.raw):
        try:
            logging.info(f"Check if {case.raw} is shortend")
            if urlexpander.is_short(case.raw):
                url = urlexpander.expand(case.raw)
                logging.info(f"{case.raw} is shortend, got - {url}")

                # Add destination url check to case
                case.checkArray.append(Check(case.caseID, url, ["url"]))
            else:

                # Add url check to case
                case.checkArray.append(Check(case.caseID, case.raw, ["url"]))
        except Exception as e:
            logging.info(e)

        try:
            logging.info(f"Check for {case.raw} domain")
            domain = urlparse(case.raw).netloc
            if domain.startswith("www."):
                domain = domain[4::]
            logging.info(f"in {case.raw} found domain {domain}")

            # Add domain check to case
            case.checkArray.append(Check(case.caseID, domain, ["domain"]))
        except Exception as e:
            logging.info(e)
        return True
    else:
        logging.warning(f"No URLs found in case.")
        return False


def ipChecks(case):
    """
    Create check for every unique ip in raw data
    """
    logging.info("Querying for IPs")
    ips = re.findall(IPV4REGEX, case.raw) + re.findall(IPV6REGEX, case.raw)
    if len(ips) > 0:
        logging.debug("Create checks for IPs:")
        for cur_ip in case.getUniques(ips):
            try:
                ip = ipaddress.ip_address(cur_ip)
                case.checkArray.append(Check(case.caseID, ip.exploded, ["ip"]))
                logging.debug(f"\t{ip.exploded}")
                return True
            except ValueError:
                logging.debug(f'address/netmask is invalid: {cur_ip}')
    else:
        logging.warning(f"No IPs found in case.")
        return False


def scanUrl(url, tags=False):
    testCase = Case(url.strip(), empty=True)
    logging.info(f"Check Url:\n\t{url}")
    logging.info(f"Create case:\n\t{testCase.caseID}")
    if not urlAndDomainChecks(testCase) or not ipChecks(testCase):
        return ""
    for plugin in discovered_plugins:
        for chk in testCase.checkArray:
            current_plugin = importlib.import_module(plugin)
            if tags:
                if any(tag in chk.tags for tag in current_plugin.tags()):
                    current_plugin.run_check(chk)
                else:
                    plugin_name = str(plugin).split(".")[-1].strip("_plugin")
                    logging.info(f"Skip plugin {plugin_name} because of tags mismatch: {current_plugin.tags()}")
            else:
                current_plugin.run_check(chk)
    return testCase


def walletsCheck(case):
    """
    Create check for every unique crypto addresses in raw data
    """
    try:
        logging.info("Querying for crypto addresses")
        for coin in COINS:
            wallet_ad = re.findall(coin, case.raw)
            if len(wallet_ad) > 0:
                logging.debug("Create checks for crypto addresses:")
                for cur_wallet in case.getUniques(wallet_ad):
                    case.checkArray.append(Check(case.caseID, cur_wallet, ["crypto"]))
                    logging.debug(f"\t{cur_wallet}")
                    return True
            else:
                logging.warning(f"No Crypto addresses found in case.")
                return False
    except Exception as e:
        logging.info(e)
        return False


def scan_one_string(data, tags=False):
    testCase = Case(data.strip(), empty=True)
    logging.info(f"Check :\n\t{data}")
    logging.info(f"Create case:\n\t{testCase.caseID}")
    if not urlAndDomainChecks(testCase) or not ipChecks(testCase) or not walletsCheck(testCase):
        return ""
    for plugin in discovered_plugins:
        for chk in testCase.checkArray:
            current_plugin = importlib.import_module(plugin)
            if tags:
                if any(tag in chk.tags for tag in current_plugin.tags()):
                    current_plugin.run_check(chk)
                else:
                    plugin_name = str(plugin).split(".")[-1].strip("_plugin")
                    logging.info(f"Skip plugin {plugin_name} because of tags mismatch: {current_plugin.tags()}")
            else:
                current_plugin.run_check(chk)
    return testCase


def process(stream):
    found_str = ""
    while True:
        data = stream.read(1024*4)
        if not data:
            print("Not data")
            break
        for char in data:
            if char in printable:
                found_str += char
            elif len(found_str) >= 4:
                yield found_str
                found_str = ""
            else:
                found_str = ""
