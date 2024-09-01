<p align="left">
  <img src="https://github.com/Cyvore/CyvoreOS/blob/master/cyvore-logo.png" width="250" alt="cyvore_logo" align="left">
  <br/><br/>
  <br/><br/>
  <br/><br/>
</p>

## CyvoreOS 
Welcome to CyvoreOS, an open source tool for automated phishing detection! :fishing_pole_and_fish:

CyvoreOS works by running a suite of external tools and internal plugins to scan data for phishing indicators. It can be used to scan URLs, IP addresses, domain names, cryptocurrency wallets and more!

### Install:
There are two ways to install CyvoreOS:


**1. Install from sources:**

preinstalls requirements:  
  - python 3.7 + 
  ```
    git clone https://github.com/Cyvore/CyvoreOS.git
    cd cyvoreos\cyvoreos
    pip3 install -r requirements.txt 
  ```
  
**2. Install packege:**

run the following command:  
`pip install cyvoreos`  
**Usage:**

Once installed, you can use CyvoreOS to scan data by importing the `CyvoreOS` module and calling the `scanstring()` function. The `scanstring()` function takes a string as input and returns a list of checks. Each check contains information about the data unit that was scanned, the plugins that were run, and the results of those plugins.

For example, to scan the URL `https://example.com/evil` for phishing indicators, you would use the following code:

```
    import cyvoreos
    checks = cyvoreos.scanstring(<string data>)
    for check in checks:
        print(check)
```
This would print a list of checks similar to the following:
```
[
    {
        "plugins": ["virusTotal_plugin_object"],
        "id": "uuid4",
        "tag": "url",
        "data": "https://example.com/evil"
    },
    {
        "plugins": ["abuseIPDB_plugin_object", "whois_plugin_object"],
        "id": "uuid4",
        "tag": "domain",
        "data": "https://example.com"
    },
]
```

CyvoreOS is powered by a suite of plugins, each of which performs a specific task. 
For example, the `VirusTotal` plugin checks URLs and files against the VirusTotal database. 
The `AbuseIPDB` plugin checks IP addresses against the abuseIPDB database.
The `CryptoWalletValidator` plugin checks wallet address behaviors online.

You can add your own plugins to CyvoreOS by implementing the [following interface](/cyvoreos/plugins/base_plugin.py):

## Note:
**make sure to have in your environment variables tokens for the extranls tools:**  
- ABUSE_IPDB_KEY = < key >  
- VIRUS_TOTAL_KEY = < key >  
- GOOGLE_SAFE_BROWSING_API_KEY = < key >

**Windows:**   
`set ABUSE_IPDB_KEY=<replace with api key>`  
`set VIRUS_TOTAL_KEY=<replace with api key>`  
`set GOOGLE_SAFE_BROWSING_API_KEY=<replace with api key>`  

**Linux:**   
`export ABUSE_IPDB_KEY=<replace with api key>`  
`export VIRUS_TOTAL_KEY=<replace with api key>`  
`export GOOGLE_SAFE_BROWSING_API_KEY=<replace with api key>`  


## Architecture: 
CyvoreOS is built on a plugin-based architecture, with each plugin performing a specific task. This allows CyvoreOS to be easily extensible and adaptable to new phishing detection techniques.

### Plugins:
Every functionality is called a plugin, and will be inherited from the BasePlugin class:
* Contains run(check) function.  
  - run is the plugin entry point that will always recive [check object](#Check-object)  

* Contains name string - Plugin's name
* Contains description string - Human readable description of the plugin
* Contains tags array - Relevent data tags

This data will help humans to understand the plugin objective.   

### Check object:
A check object is the smallest unit of data that is scanned by CyvoreOS. A check object can contain a URL, IP address, domain name, cryptocurrency wallet address, or any other type of data that can be used to detect phishing.
Check will have a plugins list, which are ran plugins against this check.data 


### Plugin object:
A plugin object contains the output of a plugin for a given check object. The output of a plugin can be anything from a simple boolean value to a complex JSON object.

## Contribute
We encourage open discussion and collaboration using GitHub Issues. 
If you have a suggestion, question, or a general comment, please open an issue. 
We are also accepting new plugins, so if you have ideas, please open an issue or even a pull request. 
Let's work together to make the internet a safer place!