import win32com.client
#other libraries to be used in this script
import os
from datetime import datetime, timedelta
import mailparser
def Check_header():
    outlook = win32com.client.Dispatch('outlook.application')
    mapi = outlook.GetNamespace("MAPI")
    #for account in mapi.Accounts:
        #print(account.DeliveryStore.DisplayName)
    inbox = mapi.GetDefaultFolder(6)
    messages = inbox.Items

    for msg in messages:
        try:
            #print("success:", msg.PropertyAccessor.GetProperty("http://schemas.microsoft.com/mapi/proptag/0x007D001F") )
            mess = msg.PropertyAccessor.GetProperty("http://schemas.microsoft.com/mapi/proptag/0x007D001F")
            mail = mailparser.parse_from_string(mess)
            #print("mail.body:",mail.body) 
            #print("mail.from_:",mail.from_) 
            #print("mail.received",mail.received)
            #print("mail.subject",mail.subject)
            #print("mail.text_plain", mail.text_plain)
            #print("mail.text_html",mail.text_html)
            #print("mail.headers:",mail.headers)
            #print("mail.message_as_string",mail.message_as_string)
            #print("mail.attachments",mail.attachments)
            #print("mail.to_domains",mail.to_domains)
            for head in mail.headers:
                print(head)
            print("Authentication-Results =",mail.headers["Authentication-Results"])
        except Exception as err:
            print("err:",err)
        #print(msg.PrintOut())
        print("====================================================")
        exit()
    

def run_check(chk):
    chk.pluginOutput["PluginName"] = []
    for url in chk.getUrls():
        print("PluginName check: ", url)
        chk.pluginOutput["PluginName"].append(output)

        
def describe():
    desc = """This plugin checks for mails headers"""
    return desc