"""CryptoWalletValidator plugin for CyvoreOS"""

from datetime import datetime
from datetime import timedelta
import json
import logging
import requests
from requests.exceptions import ReadTimeout

from blockcypher import get_address_details
from blockcypher import get_address_overview
from cyvoreos.check_types import Check, Plugin
from cyvoreos.plugins.base_plugin import BasePlugin

# Coin options: bitcoin, litecoin, dogecoin, dashcoin
coins = ['btc', 'ltc', 'doge', 'dash']  

# Consts
amount_to_check = 30
suspicious_amount = amount_to_check / 2
suspicious_range = 0 
# Needs to be tuned, If increased, more wallets would fall under the definition of suspicious transaction error


class BlackListError(Exception):
    """Raised when the address appears on a blacklist"""


class TransactionError(Exception):
    """Raised when the address appears to have made suspicious transactions"""


class Verified(Exception):
    """Raised when all the validators verified the address"""


class Transaction:
    """
    representation of a single transaction by date and balance in the account
    """

    def __init__(self, TranDate:datetime, balance:int):
        self.balance = balance
        self.TranDate = TranDate
    
    @property
    def date(self):
        return self.TranDate
    
    @property
    def balance(self):
        return self.balance
    
    def __lt__(self, other):
        return self.date < other.date
    
    def __ge__(self, other):
        return not self < other


class TransactionArray:
    """
    Class that holds all the transactions and balance in a crypto account
    Available manipulations on the data structure: sorting, average(with a range) and two validations
    """
    
    def __init__(self) -> None:
        self.arr = []

    def add(self, newT:Transaction):
        self.arr.append(newT)
    
    def sort(self):
        self.arr.sort()
    
    def set_suspicious_range(self):
        """ 
        Tune the suspicious range to be appopriate to the wallet owner
        calculating the median, if checks that length is odd
        """

        global suspicious_range # pylint: disable=global-statement
        n = len(self.arr) - 1
        suspicious_range = abs(self.arr[n//2].balance - self.arr[n//2 + 1].balance) // 10 if n > 1 else 0
    
    def transfer(self, index):
        """ 
        A transfer amount is defined as difference of balance before transfer and balance after transfer
        """

        return abs(self.arr[index].balance - self.arr[index + 1].balance)

    def average(self, start, amountToCheck):
        """
        Average of transfers
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

    def suspicious_activity_by_amount(self):
        """
        check consecutive amount of transactions for suspicious behavior.
        Note that this validation is different than the validation by date because it doesn't mind dates of transactions,
        meaning, the transactions could had been done throught a decade and this validation would've noticed it.
        """

        for i in range(0, len(self.arr) - 1):
            avg = self.average(i, amount_to_check)
            amountChecked = 0
            counter = 0
            try:
                while amountChecked is not amount_to_check:
                    if abs(avg - self.transfer(i + amountChecked)) < suspicious_range:
                        counter += 1
                    amountChecked += 1
            except IndexError:
                pass
            if counter > suspicious_amount:
                raise TransactionError
        return False

    def check_for_scam(self, r, l):
        """
        called by suspiciousActivityByDate, checks for suspicious transfer routine
        """
        avg = self.average(r, l-r)
        counter = 0

        for i in range(r, l):
            if abs(self.transfer(i) - avg) < suspicious_range:
                counter += 1
        
        # l - r - 3 is the suspicious amount of transactions, TBD about the number 3.
        if counter >= l - r - 3:
            raise TransactionError

    def suspicious_activity_by_date(self):
        """
        Checking suspicious routine in transactions.
        The function sets a time limit on a routine of transactions and checks whether they were suspiciously monotonic
        which indicates a phishing scam.
        Algorithm used: window algorithm on a sorted list for achieving correct ranges in O(n) run-time
        """
        
        timeLimit = timedelta(days=amount_to_check)
        r, l = 0, 0

        while l < (len(self.arr) - 2):
            l += 1
            
            # l-r > 15 because we need at least 15 suspicious transactions to suspect a scam
            if timeLimit < self.arr[l].date - self.arr[r].date and l-r > suspicious_amount:
                self.check_for_scam(r, l - 1)

                # Resize the window to avoid repeating checks
                while timeLimit < self.arr[l].date - self.arr[r].date and r < l:   
                    r += 1
        raise Verified

class CryptoWalletValidatorPlugin(BasePlugin):
    """
    CryptoWalletValidator plugin for CyvoreOS
    """

    name = "CryptoWalletValidator"
    description = "Verification of a cryptocurrency wallet"
    tags = ["crypto"]

    @staticmethod
    def run(check: Check, logger: logging.Logger = logging) -> Plugin:
        # Stringify the data
        data = str(check.data)

        # Run the plugin
        output = CryptoWalletValidatorPlugin._execute_plugin(data)

        output = "CryptoWalletValidator-Plugin check: " + data
        return Plugin(check.id, CryptoWalletValidatorPlugin.name, data, output)

    @staticmethod
    def print(output: str, logger: logging.Logger = logging):
        logger.info(output)

    @staticmethod
    def __blacklist_valid(wallet) -> bool:
        """
        Second validation: Appearance on a blacklist
        """

        URLBLACKLIST = f'https://api.cryptoscamdb.org/v1/check/{wallet}'

        payload = {}
        headers = {}

        try:
            response = requests.get(URLBLACKLIST, headers=headers, data=payload, timeout=30)  # stuck if VPN is active
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
    
    @staticmethod
    def __transactions_valid(wallet):
        """
        Third validation: transactions 
        """

        transac = get_address_details(wallet)["txrefs"]
        db = TransactionArray()

        for tx in transac:
            db.add(Transaction(datetime.fromtimestamp(tx['confirmed']), tx['ref_balance']))

        db.sort()
        db.set_suspicious_range()
        db.suspicious_activity_by_amount()
        db.suspicious_activity_by_date()

    @staticmethod
    def _execute_plugin(wallet):
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
                assert CryptoWalletValidatorPlugin.__blacklist_valid(wallet)
                assert CryptoWalletValidatorPlugin.__transactions_valid(wallet)

            except BlackListError:
                return 'Address is On the BlackList'
            except TransactionError:
                return 'Transactions in the address are suspicious'
            except Verified:
                return 'Wallet is legitimate'
            except Exception as _:
                continue
            
        return 'Wallet address has an issue (corrupt / non-existent)'
