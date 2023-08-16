from typing import List
from CyvoreOS.checkTypes import Check, Plugin
from CyvoreOS.checkUtils import createChecks
import importlib
from CyvoreOS import Plugins
import pkgutil
import string
import logging


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
    logging.debug("Running ls option")
    for plugin in discovered_plugins:
        current_plugin = importlib.import_module(plugin)
        output = current_plugin.describe()
        logging.info("\t" + plugin, "-", output)
    exitWithLog("Finish running ls option")


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
    logging.info(f"Check file:\n\t{args.urlFromFIle}")
    checks = createChecks(strings(args.urlFromFIle))
    return checks


def scanstring(testdata: str) -> List[Check]:
    """ scanstring - main function for scanning string with all plugins """
    checks = createChecks(testdata)
    logging.info(f"Checking string:\n\t{testdata}")
    for plugin in discovered_plugins:
        for chk in checks:
            current_plugin = importlib.import_module(plugin)
            if chk.tag:
                if chk.tag in current_plugin.tags():
                    current_plugin.run_check(chk)
                else:
                    plugin_name = str(plugin).split(".")[-1].strip("_plugin")
                    logging.info(f"Skip plugin {plugin_name} because of tags mismatch: {current_plugin.tags()}")
            else:
                current_plugin.run_check(chk)  
    return checks


def runPlugins(testdata: str, plugins_list: List[str], force=True):
    """ runPlugins - main function for running specific plugins on string"""
    checks = createChecks(testdata)
    for plugin in discovered_plugins:
        if plugins_list:
            plugin_name = str(plugin).split(".")[-1].strip("_plugin")
            if plugin_name not in plugins_list:
                logging.info(f"Skipping {plugin_name} - plugin flag is on.")
                continue
        logging.debug(f"Running plugin: {str(plugin)}")
        if force:
            for chk in checks:
                current_plugin = importlib.import_module(plugin)
                current_plugin.run_check(chk)
        else:
            for chk in checks: 
                current_plugin = importlib.import_module(plugin)
                if chk.tag in current_plugin.tags():
                    current_plugin.run_check(chk)
    return checks


def runPluginForCheck(chk: Check, plugins_list: List[str], force=True) -> List[Plugin]:
    """ runPluginForCheck - main function for running specific plugins on check
    chk: Check - check to run plugins on
    plugins_list: List[str] - list of plugins to run
    force: bool - run plugins even if tags mismatch
    returns list of plugins that ran on check"""
    plugins_output = []
    if force:
        for plugin in discovered_plugins:
            logging.info(f"plugin is {plugin}")
            if plugins_list:
                # Weird bug with virusTotal_plugin where .strip("_plugin") remove the l_plugin
                # plugin_name = str(plugin).split(".")[-1].strip("_plugin")
                plugin_name = str(plugin).split(".")[-1][:-7]
                if plugin_name not in plugins_list:
                    logging.info(f"Skipping {plugin_name} - plugin flag is on.")
                    continue
            logging.debug(f"Running plugin: {str(plugin)}")
            current_plugin = importlib.import_module(plugin)
            new_plugin = current_plugin.run_check(chk)
            plugins_output.append(new_plugin)
    else:
        for plugin in discovered_plugins:
            logging.info(f"plugin is {plugin}")
            if plugins_list:
                # Weird bug with virusTotal_plugin where .strip("_plugin") remove the l_plugin
                # plugin_name = str(plugin).split(".")[-1].strip("_plugin")
                plugin_name = str(plugin).split(".")[-1][:-7]
                if plugin_name not in plugins_list:
                    logging.info(f"Skipping {plugin_name} - plugin flag is on.")
                    continue
            current_plugin = importlib.import_module(plugin)
            if chk.tag in current_plugin.tags():
                new_plugin = current_plugin.run_check(chk)
                plugins_output.append(new_plugin)
            else:
                logging.info(f"Skip plugin {plugin_name} with tag {chk.tag} because of tags mismatch: {current_plugin.tags()}")
    return plugins_output


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
