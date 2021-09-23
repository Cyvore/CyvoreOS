from CyvoreOS.checkObject import Check
from CyvoreOS.checkObject import Case
from CyvoreOS.Output.Reporter import MakeCaseReportJson
import importlib
import CyvoreOS.Plugins
import pkgutil
import string
import logging
import CyvoreOS.interfaces

logging.basicConfig(filename='cyvore_main.log',
                    level=logging.DEBUG,
                    format='%(asctime)s | %(name)s | %(levelname)s | %(message)s')
printable = set(string.printable)

def iter_namespace(ns_pkg):
    # Specifying the second argument (prefix) to iter_modules makes the
    # returned name an absolute name instead of a relative one. This allows
    # import_module to work without having to do additional modification to
    # the name.
    return pkgutil.iter_modules(ns_pkg.__path__, ns_pkg.__name__ + ".")

discovered_plugins = {
    name: importlib.import_module(name)
    for finder, name, ispkg
    in iter_namespace(CyvoreOS.Plugins)
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
    # with open(filename, "rb") as f:           # Python 2.x
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


def lsCommand(args):
    logging.info("Running ls option")
    for plugin in discovered_plugins:
        current_plugin = importlib.import_module(plugin)
        output = current_plugin.describe()
        print("\t" + plugin, "-", output)
    exitWithLog("")


def installCommand(args):
    logging.info("Running install option")
    path = "\"C:\\Python39\\python.exe\" \"" + __file__ + "\" -uf \"%1\""
    logging.debug(f"Path in registry:\t{path}")
    interfaces.right_click_install.define_action_on("*", "CheckForPhish", path, title="Run Phish Check")
    print("Installed right click addon")
    exitWithLog("")


def urlFromFileCommand(args):
    testCase = Case()
    logging.info(f"Check file:\n\t{args.urlFromFIle}")
    logging.info(f"Create case:\n\t{testCase.caseID}")
    print("Check file:\n\t", args.urlFromFIle)
    print(f"Create case:\n\t{testCase.caseID}")
    testCase.raw = str(list(strings(args.urlFromFIle)))
    return testCase.createChecks()


def queryStringCommand(args):
    testCase = Case()
    logging.info(f"Check string:\n\t{args.queryString}")
    logging.info(f"Create case:\n\t{testCase.caseID}")
    print("Check file:\n\t", args.queryString)
    print(f"Create case:\n\t{testCase.caseID}")
    testCase.raw = args.queryString
    return testCase.createChecks()


def initmodule(command, arg):
    testCase = Case()
    if command != "qs":
        return 500
    else:
        testCase.raw = arg
        testCase.checkArray = testCase.createChecks()
    for plugin in discovered_plugins:
        for chk in testCase.checkArray:
            current_plugin = importlib.import_module(plugin)
            current_plugin.run_check(chk)