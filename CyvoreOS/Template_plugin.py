from CyvoreOS.checkTypes import Check, Plugin
def run_check(chk: Check):
    plugin_name = "Template-Plugin"
    output = "example for output"
    return Plugin(chk.id, plugin_name, chk.data, output)


def describe():
    desc = """Description of PluginName in a sentence """
    return desc


def tags():
    tags_list = ["url", "file", "ip", "hash", "email", "domain", "crypto", "username"]
    return tags_list
