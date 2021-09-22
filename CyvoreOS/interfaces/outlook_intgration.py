import win32com.client
import win32com
import os
import sys
import pythoncom
from itertools import product
from checkObject import Check
import logging
f = open("emails.log","w+")

outlook = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
accounts= win32com.client.Dispatch("Outlook.Application").Session.Accounts;

# collection of accounts
accounts2 = outlook.Folders

# number of outlook accounts
accounts_count = accounts.Count

# .Item(1) not .Item(0) because counting starts at 1
account1 = accounts2.Item(1)

# collection of folders for account1
account_folders = account1.Folders
# number of folders under outlook account
account_folders_count = account_folders.Count

# print account1 folder names
def printAccountFolders():
    logging.debug("List of folders to check:")
    for folder in range(account_folders_count):
        # must be +1 because .Folder(0) and .Item(0) do not work
        logging.debug(f"{str(folder+1)}:{account_folders.Item(folder+1)}")
        print(str(folder+1)+":", account_folders.Item(folder+1))

            
def inspect(folder):
    messages = folder.Items
    chk_list = []
    a=len(messages)
    counter = 0
    if a>0:
        for msg in messages:
            chk_list.append(Check())
            chk_list[counter].raw = "Start\n"
            try:
                sender = msg.SenderEmailAddress
                if sender != "":
                    print("Sender: %s"%sender, file=f) 
                    chk_list[counter].raw = chk_list[counter].raw + "Sender: %s\n"%sender
            except Exception as err:
                print("Error in Sender here:",err,file=f)
                pass
            
            try:
                subject = msg.subject
                if subject != "":
                    print(u"Subject: ",subject, file=f)
                    chk_list[counter].raw = chk_list[counter].raw + "subject: %s\n"%subject
            except Exception as err:
                print("Error in Subject here:",err,file=f)
                pass
            
            try:
                creation_time = msg.CreationTime
                if creation_time != "":
                    print("Creation time: %s"%creation_time, file=f)
                    chk_list[counter].raw = chk_list[counter].raw + "Creation time: %s\n"%creation_time
            except Exception as err:
                print("Error in Creation time here:",err,file=f)
                pass
            
            try:
                body = msg.body
                if body != "":
                    print("body: {%.100s}"%body.rstrip(), file=f)
                    chk_list[counter].raw = chk_list[counter].raw + "body: {%s}\n"%body.rstrip()
            except Exception as err:
                print("Error in body here:",err,file=f)
                pass
            
            try:
                attach = []
                if msg.attachments:
                    for i in msg.attachments:
                        attach.append("Item")
                if attach:
                    print("--------------------", file=f)
                    print("- attachment found -", file=f)
                    print("--------------------", file=f)
                    chk_list[counter].raw = chk_list[counter].raw + "--------------------\n"
                    chk_list[counter].raw = chk_list[counter].raw + "- attachment found -\n"
                    chk_list[counter].raw = chk_list[counter].raw + "--------------------\n"
                #print("All is good")
            except Exception as err:
                print("Error in attachment here:",err,file=f)
                #print(err)
                #print("Error")
                #print(account.DeliveryStore.DisplayName)
                pass
            counter+=1
            if counter > 100: return chk_list
            #print("counter is: ",counter)
            try:
                msg.Save
                msg.Close(0)
            except:
                pass
            #if counter > 3: return chk_list
    print("\t\tChecked %d mails"%counter)
    return chk_list    
       
def createCheckArray():
    chk_list = []
    printAccountFolders()
    
    tmp = []
    for account in accounts:
        global inbox
        inbox = outlook.Folders(account.DeliveryStore.DisplayName)
        print("****Account Name**********************************",file=f)
        print(account.DisplayName,file=f)
        print(account.DisplayName)
        print("***************************************************",file=f)
        print("----------------- Account Name ------------------")
        print("\t %s"%account.DisplayName)
        folders = inbox.Folders

        for folder in folders:
            print("****Folder Name**********************************", file=f)
            print(folder, file=f)
            print("*************************************************", file=f)
            print("Folder Name:\n\t%s:"%folder)
            chk_list = chk_list + inspect(folder)
            
                
            a = len(folder.folders)
            if a>0 :
                global subFolder
                subFolder = outlook.Folders(account.DeliveryStore.DisplayName).Folders(folder.name)
                x = subFolder.Folders
                for y in x:
                    chk_list = chk_list + inspect(y)
                    print("****Folder Name**********************************", file=f)
                    print("..."+y.name,file=f)
                    print("*************************************************", file=f)
                    print("Folder Z Name:\n\t%s:"%folder)
            """if len(chk_list) > 0:
                c = 0 
                for chk in chk_list:
                    if len(chk.getUrls()) > 0:            
                        for i in chk.getUrls(): 
                            # check if exists in unique_list or not 
                            if i not in tmp: 
                                tmp.append(i) 
                        for i in chk.getUrls():
                            c += 1
                print("\t\tFound %d addresses"%c)"""
    print("Created",len(chk_list), "check objects")
    return chk_list



#print("Total different addresss %d:\n"%len(tmp),tmp)
print("Finished Succesfully")