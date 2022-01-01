from CyvoreOS.checkObject import Check
from CyvoreOS.checkObject import Case
from CyvoreOS.Output.Reporter import MakeCaseReportJson
import importlib
from CyvoreOS import Plugins
#from CyvoreOS import interfaces
import pkgutil
import string
import logging
#import CyvoreOS.interfaces

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


def scanstring(testdata):
    testCase = Case(testdata)
    logging.info(f"Check string:\n\t{testdata}")
    logging.info(f"Create case:\n\t{testCase.caseID}")
    for plugin in discovered_plugins:
        for chk in testCase.checkArray:
            current_plugin = importlib.import_module(plugin)
            current_plugin.run_check(chk)
    return testCase

def runPlugins(plugins_list, testCase):
    for plugin in discovered_plugins:
        if plugins_list:
            plugin_name = str(plugin).split(".")[1].removesuffix("_plugin")
            if plugin_name not in plugins_list:
                logging.info(f"Skipping {plugin_name} - plugin flag is on.")
                continue
        elif "debug" in str(plugin).split(".")[1].removesuffix("_plugin") :
            continue
        logging.debug(f"Running plugin: {str(plugin)}")
        for chk in testCase.checkArray:
            
            current_plugin = importlib.import_module(plugin)
            current_plugin.run_check(chk)
        
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
