
import importlib
import inspect
import pkgutil
import string
import logging
from typing import List, Union, Dict    
from types import ModuleType
from cyvoreos import plugins
from cyvoreos.plugins.base_plugin import BasePlugin
from cyvoreos.check_types import Check, Plugin
from cyvoreos.check_utils import create_checks

logging.basicConfig(
    filename='cyvore_main.log',
    level=logging.DEBUG,
    format='%(asctime)s | %(name)s | %(levelname)s | %(message)s'
)

printable = set(string.printable)

# Initialize plugins dictionary
discovered_plugins: Dict[str, BasePlugin] = {}

# Get absolute path for plugins
def _iter_namespace(ns_pkg):
    """
    Generate an iterator over the namespace package
    Specifying the second argument (prefix) to iter_modules makes the
    returned name an absolute name instead of a relative one. This allows
    import_module to work without having to do additional modification to
    the name.
    """

    return pkgutil.iter_modules(ns_pkg.__path__, ns_pkg.__name__ + ".")

def _find_plugin_class(module: ModuleType) -> Union[BasePlugin, None]:
    """
    Find the plugin class in the module

    Parameters:
        module (ModuleType): module to search for the plugin class

    Returns:
        class: plugin class
    """
    
    memebers = inspect.getmembers(module, inspect.isclass)

    for _, obj in memebers:
        if issubclass(obj, BasePlugin) and obj != BasePlugin:
            return obj
        
    return None

# Discover all plugins
for _, name, _ in _iter_namespace(plugins):
    # Find the plugin class in the module
    plugin = _find_plugin_class(importlib.import_module(name))

    # Add the plugin to the dictionary
    if plugin:
        discovered_plugins[plugin.name] = plugin

def exit_with_log(msg, logger: logging.Logger = logging):
    """
    Exit the program with a log message

    Parameters:
        msg (str): message to log
        logger (Logger): logger to use (optional)
    """

    # Log the warning message if there is one
    if msg:
        logger.warning(msg)

    # Log the end of the program
    else:
        logger.info("Program finished successfully")

    # Log the end of the program
    logger.info("-" * 50)
    logger.info("\n\n\n")

    # Exit the program
    exit()

def strings(filename, minimum = 4):
    """
    Get strings from file
    """
    
    with open(filename, errors="ignore", encoding="utf-8") as f:  # Python 3.x
        result = ""
        for c in f.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= minimum:
                yield result
            result = ""
        if len(result) >= minimum:  # catch result at EOF
            yield result


def list_plugins(logger: logging.Logger = logging):
    """
    Log all plugins

    Parameters:
        logger (Logger): logger to use (optional)
    """

    logger.debug("Listing all plugins")

    for plugin_name, plugin_class in discovered_plugins.items():
        logger.info("\t" + plugin_name + " - " + plugin_class.description)

    exit_with_log("Finish running ls option")

def url_from_file_command(args: dict, logger: logging.Logger = logging) -> List[Check]:
    """
    Main function for running all plugins on file
    
    Parameters:
        args: argparse arguments
        logger: logger to use (optional)
        
    Returns:
        List[Check]: list of checks
    """

    logger.info(f"Check file: \t{args.urlFromFile}")
    checks = create_checks(strings(args.urlFromFile), logger)
    return checks


def scanstring(data: str, logger: logging.Logger = logging) -> List[Check]:
    """
    main function for running all plugins on string

    Parameters:
        data (str): string to run plugins on
        logger (Logger): logger to use (optional)

    Returns:
        List[Check]: list of checks
    """
    checks = create_checks(data)
    logger.info(f"Checking string:\n\t{data}")

    for plugin_name, plugin_class in discovered_plugins.items():
        for check in checks:
            if check.tag:
                if check.tag in plugin_class.tags:
                    check.plugins.append(plugin_class.run(check, logger))

                else:
                    logger.info(f"Skip plugin {plugin_name} because of tags mismatch: {plugin_class.tags}")

            else:
                check.plugins.append(plugin_class.run(check, logger) )

    return checks


def run_plugins(data: str, plugins_list: List[str], force=True, logger: logging.Logger = logging) -> List[Check]:
    """
    Main function for running specific plugins on string

    Parameters:
        data (str): string to run plugins on
        plugins_list (List[str]): list of plugins to run
        force (bool): run plugins even if tags mismatch
        logger (Logger): logger to use (optional)

    Returns:
        List[Check]: list of checks
    """

    checks = create_checks(data)
    lower_plugins_list = [plugin.lower() for plugin in plugins_list]

    for plugin_name, plugin_class in discovered_plugins.items():
        if plugins_list:
            if plugin_name.lower() not in lower_plugins_list:
                logger.info(f"Skipping {plugin_name} - plugin flag is on.")
                continue

        logger.debug(f"Running plugin: {str(plugin_class)}")

        if force:
            for check in checks:
                check.plugins.append(plugin_class.run(check, logger))

        else:
            for check in checks: 
                if check.tag in plugin_class.tags:
                    check.plugins.append(plugin_class.run(check, logger))

    return checks


def run_plugin_for_check(check: Check, plugins_list: List[str], force: bool = True, logger: logging.Logger = logging) -> List[Plugin]:
    """
    Main function for running specific plugins on check
    
    Parameters:
        check (Check): Check - check to run plugins on
        plugins_list: List[str] - list of plugins to run
        force: bool - run plugins even if tags mismatch
        logger: Logger - logger to use (optional)

    Returns:
        List[Plugin]: list of plugins that ran on check
    """

    plugins_output = []
    lower_plugins_list = [plugin.lower() for plugin in plugins_list]

    if force:
        for plugin_name, plugin_class in discovered_plugins.items():
            logger.info(f"Plugin is {plugin_name}")

            if lower_plugins_list:
                if plugin_name.lower() not in lower_plugins_list:
                    logger.info(f"Skipping {plugin_name} - plugin flag is on.")
                    continue

            logger.debug(f"Running plugin: {plugin_name}")
            plugins_output.append(plugin_class.run(check, logger))

    else:
        for plugin_name, plugin_class in discovered_plugins.items():
            logger.info(f"Plugin is {plugin_name}")

            if lower_plugins_list:
                if plugin_name.lower() not in lower_plugins_list:
                    logger.info(f"Skipping {plugin_name} - plugin flag is on.")
                    continue

            if check.tag in plugin_class.tags:
                plugins_output.append(plugin_class.run(check, logger))

            else:
                logger.info(f"Skip plugin {plugin_name} with tag {check.tag} because of tags mismatch: {plugin_class.tags}")

    return plugins_output

def process_stream(stream):
    """
    Process the stream
    """

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
