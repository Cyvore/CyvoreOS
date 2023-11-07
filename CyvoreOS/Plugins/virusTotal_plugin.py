import vt
import time
import os
import logging
from CyvoreOS.checkTypes import Check, Plugin

try:
    VIRUS_TOTAL_KEY = os.environ['VIRUS_TOTAL_KEY']
except Exception as e:
    logging.info(f"'VIRUS_TOTAL_KEY' wasn't found:{e}")

WAIT = 4.5
MAX_TRIES = 4


def virusTotalCheck(url):
    try:
        client = vt.Client(VIRUS_TOTAL_KEY)
        analysis = client.scan_url(url)
        cur = 0
        while cur < MAX_TRIES:
            analysis = client.get_object("/analyses/{}", analysis.id)
            if analysis.status == "completed":
                return analysis.to_dict()
            cur += 1
            time.sleep(WAIT)
    except Exception as e:
        logging.info(e)
    return ""


def run_check(chk: Check) -> Plugin:
    plugin_name = "VirusTotal"
    data = str(chk.data)
    output = virusTotalCheck(data)
    return Plugin(chk.id, plugin_name, data, output)


def describe():
    desc = """This plugin query url/ip in VirusTotal v3 database """
    return desc


def tags():
    tags_list = ["url", "domain"]
    return tags_list
