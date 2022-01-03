<p align="left">
  <img src="https://github.com/Cyvore/CyvoreOS/blob/master/cyvoreLogo.png" width="250" alt="cyvoreLogo" align="left">
  <br/><br/>
  <br/><br/>
  <br/><br/>
</p>

## CyvoreOS 
Cyvore os is an open source tool for auto phishing detection.  
You are welcome to visit our site [cyvore.com](https://cyvore.com)

### Install:
There are 2 simple ways to install this tool:

**1. Installing from sources:**

preinstalls requirements:  
  - python 3.7 + 
  ```
    git clone https://github.com/Cyvore/CyvoreOS.git
    cd cyvoreos\cyvoreos
    pip3 install -r requirements.txt 
  ```
  
**2. Install packege:**

run the following command:  
`pip install CyvoreOS`  
Then use:  
```
    import CyvoreOS
    testCase = CyvoreOS.scanstring(<url>)
    print(testCase.getDict())
```

## Note:
**make sure to have in your environment variables tokens for the extranls tools:**  
- ABUSE_IPDB_KEY = < key >  
- VIRUS_TOTAL_KEY = < key >  

**Windows:**   
`set ABUSE_IPDB_KEY=<replace with api key>`  
`set VIRUS_TOTAL_KEY=<replace with api key>`  

**Linux:**   
`export ABUSE_IPDB_KEY=<replace with api key>`  
`export VIRUS_TOTAL_KEY=<replace with api key>`  

### Running

**Run from API:**
TBD, currently available to use on cyvore.com/API   

**Run with CLI**
TBD if we are going to support this and add run.py  

## Architecture: 

Cyvore tool is working on plugin formation, each plugin will preform one concise objective.  
For example plugin could be check url in virusTotal, this is a rather big objective.  
A small one could be test how much a url is similear to known domain.  
As a guiding line we would prefer each plugin to as concise as possible.  

### Plugins:
Every functionality will be called a plugin, and will follow a set of rules:   
* Contains run_check(chk) function.  
  - run_check is the plugin entry point that will always recive [check object](#Check-object)  
  - plugin_name is the plugin present name in output.   
  - and output could be string or dict object.  
```
def run_check(chk):
    plugin_name = "Template-Plugin"
    output = "example for output"
    chk.add_plugin(plugin_name,output)
```  
* Contains describe() function.   

This data will help humans to understand the plugin objective.   
```
def describe():
    desc = """Description of PluginName in a sentence """
    return desc
```

* Contains tags() function.  
tags will help sort what data this plugin is expecting.  
```
def tags():
    tags_list = ["url", "file", "ip", "hash", "email", "domain", "crypto", "username"]
    return tags_list
```


### Case object:
Case is the object our tool create for each investigation.  
Case will have a check array.  

### Check object:
Check is the smallest object to test against plugins.  
When check is made as part of a Case object it will hold one value in raw_data, url/file/crypto/ and etc.  
Check will have a plugins array, which will run plugins against this raw_data.

### Plugin object:
Plugin object holds all plugins output for a check as a dictionary, with the plugin name as key, and output as value.  

## Contribute
We encourage open discussion and collaboration using GitHub Issues.  
If you have a suggestion, question, or a general comment - please use Issues, and let us know what is on your mind.   
We are also accepting new plugins if you have ideas, open issue or even a PR in the subject.  
Lets work together on making the internet safer :smile:  
