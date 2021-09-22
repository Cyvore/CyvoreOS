from checkObject import Check

def run_check(chk):
    chk.pluginOutput["PluginName"] = []
    for url in chk.getUrls():
        print("PluginName check: ", url)
        chk.pluginOutput["PluginName"].append(output)

        
def describe():
    desc = """Description of PluginName in a sentence """
    return desc