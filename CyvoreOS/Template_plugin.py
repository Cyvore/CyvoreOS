def run_check(chk):
    plugin_name = "Template-Plugin"
    output = "example for output"
    chk.add_plugin(plugin_name,output)
        
def describe():
    desc = """Description of PluginName in a sentence """
    return desc
