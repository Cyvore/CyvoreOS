import json
import requests
from datetime import datetime
from datetime import timedelta
from blockcypher import get_address_overview
from blockcypher import get_address_details
from requests.exceptions import ReadTimeout
from CyvoreOS.checkTypes import Check, Plugin

# Coin options: bitcoin, litecoin, dogecoin, dashcoin
coins = ['btc', 'ltc', 'doge', 'dash']  

# Consts
amountToCheck = 30
suspiciousAmount = amountToCheck / 2
suspiciousRange = 0 
# Needs to be tuned, If increased, more wallets would fall under the definition of suspicious transaction error


class BlackListError(Exception):
    """Raised when the address appears on a blacklist"""
    pass


class transactionError(Exception):
    """Raised when the address appears to have made suspicious transactions"""
    pass


class Verified(Exception):
    """Raised when all the validators verified the address"""
    pass


class transaction:
    """
    representation of a single transaction by date and balance in the account
    """

    def __init__(self, TranDate:datetime, balance:int):
        self.balance = balance
        self.TranDate = TranDate
    
    @property
    def date(self):
        return self.TranDate
    
    def balance(self):
        return self.balance
    
    def __lt__(self, other):
        return self.date < other.date
    
    def __ge__(self, other):
        return not self < other


class transactionArray:
    """
    Class that holds all the transactions and balance in a crypto account
    Available manipulations on the data structure: sorting, average(with a range) and two validations
    """
    
    def __init__(self) -> None:
        self.arr = []

    def add(self, newT:transaction):
        self.arr.append(newT)
    
    def sort(self):
        self.arr.sort()
    
    def setSuspiciousRange(self):
        """ tune the suspicious range to be appopriate to the wallet owner"""
        """ calculating the median, if checks that length is odd"""
        global suspiciousRange
        n = len(self.arr) - 1
        suspiciousRange = abs(self.arr[n//2].balance - self.arr[n//2 + 1].balance) // 10 if n > 1 else 0
    
    def transfer(self, index):
        """ a transfer amount is defined as difference of balance before transfer and balance after transfer"""
        return abs(self.arr[index].balance - self.arr[index + 1].balance)

    def average(self, start, amountToCheck):
        """
        average of transfers
        """
        balance = 0
        amountChecked = 0 
        
        try:
            while amountChecked is not amountToCheck:
                balance += self.transfer(start + amountChecked)
                amountChecked += 1
        except IndexError:
            pass

        return balance / amountChecked

    def suspiciousActivityByAmount(self):
        """
        check consecutive amount of transactions for suspicious behavior.
        Note that this validation is different than the validation by date because it doesn't mind dates of transactions,
        meaning, the transactions could had been done throught a decade and this validation would've noticed it.
        """

        for i in range(0, len(self.arr) - 1):
            avg = self.average(i, amountToCheck)
            amountChecked = 0
            counter = 0
            try:
                while amountChecked is not amountToCheck:
                    if abs(avg - self.transfer(i + amountChecked)) < suspiciousRange:
                        counter += 1
                    amountChecked += 1
            except IndexError:
                pass
            if counter > suspiciousAmount:
                raise transactionError
        return False

    def checkForScam(self, r, l):
        """
        called by suspiciousActivityByDate, checks for suspicious transfer routine
        """
        avg = self.average(r, l-r)
        counter = 0

        for i in range(r, l):
            if abs(self.transfer(i) - avg) < suspiciousRange:
                counter += 1
        
        # l - r - 3 is the suspicious amount of transactions, TBD about the number 3.
        if counter >= l - r - 3:
            raise transactionError

    def suspiciousActivityByDate(self):
        """
        Checking suspicious routine in transactions.
        The function sets a time limit on a routine of transactions and checks whether they were suspiciously monotonic
        which indicates a phishing scam.
        Algorithm used: window algorithm on a sorted list for achieving correct ranges in O(n) run-time
        """
        
        timeLimit = timedelta(days=amountToCheck)
        r, l = 0, 0

        while l < (len(self.arr) - 2):
            l += 1
            
            # l-r > 15 because we need at least 15 suspicious transactions to suspect a scam
            if timeLimit < self.arr[l].date - self.arr[r].date and l-r > suspiciousAmount:
                self.checkForScam(r, l - 1)

                # Resize the window to avoid repeating checks
                while timeLimit < self.arr[l].date - self.arr[r].date and r < l:   
                    r += 1
        raise Verified


def blacklistValid(wallet) -> bool:
    """
    Second validation: Appearance on a blacklist
    """

    URLBLACKLIST = f'https://api.cryptoscamdb.org/v1/check/{wallet}'

    payload={}
    headers = {}

    try:
        response = requests.get(URLBLACKLIST, headers=headers, data=payload, timeout=30) # stuck if VPN is active
    except Exception as e:
        if isinstance(e, ReadTimeout):
            return True

    info = json.loads(response.content.decode("utf-8"))
    
    if info['success'] is False:
        return True

    info = info['result']['entries'][0]['type']

    if info == 'scam':
        raise BlackListError
    return True


def transactionsValid(wallet):
    """
    Third validation: transactions 
    """

    transac = get_address_details(wallet)["txrefs"]
    db = transactionArray()

    [db.add(transaction(tx['confirmed'], tx['ref_balance'])) for tx in transac]
    db.sort()
    db.setSuspiciousRange()
    db.suspiciousActivityByAmount()
    db.suspiciousActivityByDate()


def walletVerification(wallet):
    """
    Verification of a cryptocurrency wallet using three stages:
    1. Check if the given address belongs to an existing wallet (using coinaddr)
    2. Ensure that the wallet doesn't have a history of reports and belongs to a black list (using the cryptoscamdb api)
    3. Ensure that the wallet hasn't initiated in any suspicious activity lately 
       by importing the latest transactions and ispecting their behavior (using blockcypher)
       validate(coin, wallet).valid and 
    """

    for coin in coins:
        try:
            assert get_address_overview(wallet, coin)
            assert blacklistValid(wallet)
            assert transactionsValid(wallet)

        except BlackListError:
            return 'Address is On the BlackList'
        except transactionError:
            return 'Transactions in the address are suspicious'
        except Verified:
            return 'Wallet is legitimate'
        except:
            continue
    return 'Wallet address has an issue (corrupt / non-existent)'


def run_check(chk: Check) -> Plugin:
    data = str(chk,data)
    output = walletVerification(data)
    plugin_name = "cryptoWalletValidator-Plugin"
    output = "cryptoWalletValidator-Plugin check: " + data
    return Plugin(chk.id, plugin_name, data, output)


def describe():
    desc = """Verification of a cryptocurrency wallet"""
    return desc


def tags():
    tags_list = ["crypto"]
    return tags_list
