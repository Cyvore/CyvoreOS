import time
import requests
print("Start")
def check(wallet):
    try:
        print("request for page")
        page = requests.get("https://blockchain.info/address/"+wallet)
        print(page)
        #print("[+] Wallet:" , wallet + " got " + page.text.split('No. Transactions')[1].split("</td>")[1].split('<td id="n_transactions">')[1] + " transactions")
        #btc = page.text.split("Final Balance")[1].split('<td id="final_balance">')[1].split('</span>')[0].split(">")
        #print("[+] Wallet balance: " + btc[2] + "\n")
    except Exception as e:
        print("[-] Something went wrong")
        print(e)
"""
wallets = ["16Hz84sGs3xr4vLJZfPjQJAfFso9p5MvR","16buJrpoSNkqmGsjiw5Diws8uYnxEySHSp","16NivQ5sVKJ3kHatP51b44EZFMxMe12RaS","1AdUw4i68CFF3m2zYrjmfhcH4ortjbwVzB"]
while(1):
    for wallet in wallets:
        check(wallet)
    print("[+] Sleeping for 1 hour before checking again")
    time.sleep(10)
# Check for Crypto currency wallets, if relate to scams. 
"""
def run_check(chk):
    print("CryptoCurrncy running (Empty currently)")
        
def describe():
    desc = """This plugin query for known virtual currency wallet"""
    return desc