### CyvoreOS
 ` Code design `
### API:
1. URL check: 
	- [x] check object (will use raw string var)
1. Files check:
	- [ ] check object (will use name/attribute list separated by spaces (need to check
	how files attribute works in mail)) Check for option if there is a download link
	or file, pass it to cuckoo box for quarantine download and check with no risk
	for host.
1. SlowCheck:
	- [x] check object (will use raw string var which every substring will be checked for
	URL/file/whatever)
1. Brain:
	- [ ] Brain will be the main program which will know how to automatically choose
	function to run (can be manually override like in slowcheck mode)
 
### Plugins:
*  Every functionality will be called a plugin, and will follow a set of rules the we will define. 
	* check object:
		object that will have multiple parameters per our uses TBD (stuff like, string, 
		source, Boolean flags, reputation, status, hash, and more)
	* every plugin must contain logging
*	Every plugin will have main function run_check(chk) that will receive an object type check and will return an object type check.
	Like: 
	```
	def run_check(chk):
	    for url in chk.getUrls():
		logging.debug(f"abuseIPDB check: {url}")
		print("abuseIPDB check: ", url)
		if checkUrl(url):
		    #logging.debug(url," is up")
		    json_output = abuseIPDBCheck(url)
		    printIPDBoutput(json_output)
	```

*	Every function must use describe function
	```
	def describe():
    	    desc = "This plugin query url/ip in abuse IP DB database"
    	    return desc
    ```
    
### New plungins:
 - [ ] _OPR_ - built in plugin to run first and check for images origin and compare domains
 - [ ] Redirections plugin - check for login and auto login seek for suspicious domains 
 - [ ] Bitcoin walltes check for known scam wallet addresses
 
### Interfaces:
For every interface there will be a different file and Brain will use them in order to 
interface different platforms. The Brain will be standalone.
1. Interface: 
	- [ ] Email interfacing, will communicate with mail agent, will parse the mails into check object.
	1. - [x] Check entire mail folders
	1. - [ ] Check every new mail 
1. Interface: 
	- [ ] Right-click, will add the right click menu bar option “Check for safety”. This option will be legit for two use cases:
	1. - [ ] Every selected string (online, document, emails, etc.)
	1. - [x] Every file the will be right-click with the cursor
1. Interface: 
	- [ ] Chrome extantion to check data from browser 

### Reporter:
I guess that we will want a different kinds of output, this will be reporter job, and for 
each report kind will be a different file.
1. - [ ] Report: simple output for user (json? Pop-up massage? Yaml? Xml?)
1. - [ ] Report: send output to our db (may dis-include raw string and only save bad info because of user privacy)
1. - [ ] Report: send syslog to organization siem (So our product could be monitored by soc and used in a large organizations)

### Logs:
1. - [ ] Internal log: logging the application activity 
1. - [ ] Security logs: logging security events
	1. - [ ] Think about events id in order to intigrate with siem 
	1. - [ ] Bad and Good scan should be logged
	
### DB
1. - [ ] Setup Mongo DB 

### Server:
For large organizations we should consider option to config self DB and connect to 
siem and even setup a local site to show data, statistics and anything else TBD 
