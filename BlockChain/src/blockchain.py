from ast import Not
import hashlib
from datetime import datetime
import json
from re import ASCII
from tkinter import N
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os
import base58
import pprint
import requests
from Crypto.Util.number import ceil_div, bytes_to_long, long_to_bytes
pp = pprint.PrettyPrinter(indent=4)


class Blockchain(object):
    def __init__(self):
        self.chain = [self.firstBlock()]
        self.usernames = []
        self.pendingTransactions = []
        self.blockSize = 5
        self.difficulty = 4
        self.minerRewards = 50
        self.length = 1
        self.nodes = []

    def registerNode(self,adress):
        if adress not in self.nodes:
            self.nodes.append(adress)
    def registerInMainNode(self,adress,myAdress):
        try:
            resp = requests.put("http://"+adress+"/registerNode", data=myAdress)
        except:
            print("An exception occurred")
        resp = requests.get("http://"+adress+"/allNodes", data=myAdress)
        objetoJson = json.loads(resp.text)
        for adressR in objetoJson["adresses"]:
            if adressR != myAdress:
                self.nodes.append(adressR)
                try:
                    resp = requests.put("http://"+adressR+"/registerNode", data=myAdress)
                except:
                    print("An exception occurred")
    def consensus(self):
        neighbors = self.nodes
        newChain = self.chain

        maxLength = self.length
        if len(neighbors) == 0:
            return True
        for node in neighbors:
            response = requests.get('http://'+node+'/blockchain')

            if response.status_code == 200:
                objetoJson = json.loads(response.text)
                length = objetoJson['length']
                chainReceived = self.jsonDecodeBC(objetoJson['chain'])
                if length > maxLength and self.isValidChain(chainReceived):
                    maxLength = length
                    newChain = chainReceived

        if newChain:
            self.chain = newChain
            return True

        return False


    def isValidChain(self,chain):
        for i in range(1, len(chain)):
            b1 = chain[i-1]
            b2 = chain[i]

            if not b2.hasValidTransactions():
                print("error 3")
                return False

            if b2.hash != b2.calculateHash():
                print("error 4")
                return False
            if b2.prev != b1.hash:
                print("error 5")
                return False
        return True

    def addBlock(self, block):
        self.chain.append(block)
        self.length +=1
        for node in self.nodes:
            response = requests.get('http://'+node+'/blockchain')
            if response.status_code == 200:
                newBlockChain = json.loads(response.text)
                length = newBlockChain[length]

    def jsonDecodeBC(self, chainJSON):
        chain = []
        for blockJSON in chainJSON:

            tArr = []
            for tJSON in blockJSON['transactions']:
                transaction = Transaction(
                    tJSON['sender'], tJSON['receiver'], tJSON['amount'])
                transaction.time = tJSON['time']
                transaction.hash = tJSON['hash']
                if tJSON['signature'] != "NOTSIGNED":
                    transaction.signature = long_to_bytes(int(tJSON['signature']))
                else:
                    transaction.signature = tJSON['signature']
                tArr.append(transaction)

            block = Block(blockJSON['index'], tArr, blockJSON['time'])
            block.hash = blockJSON['hash']
            block.prev = blockJSON['prev']
            block.nonce = blockJSON['nonce']
            block.miner = blockJSON['miner']
            chain.append(block)
        return chain

    def jsonEncodeBC(self):
        blockArrJSON = []
        for block in self.chain:
            blockJSON = {}
            blockJSON['hash'] = block.hash
            blockJSON['index'] = block.index
            blockJSON['prev'] = block.prev
            blockJSON['time'] = block.time
            blockJSON['nonce'] = block.nonce
            blockJSON['miner'] = block.miner
            transactionsJSON = []
            for transaction in block.transactions:
                tJSON = {}
                tJSON['time'] = transaction.time
                tJSON['sender'] = transaction.sender
                tJSON['receiver'] = transaction.receiver
                tJSON['amount'] = transaction.amount
                tJSON['hash'] = transaction.hash
                if transaction.signature != "NOTSIGNED":
                    tJSON['signature'] = bytes_to_long(transaction.signature)
                else:
                     tJSON['signature'] = transaction.signature
                transactionsJSON.append(tJSON)

            blockJSON['transactions'] = transactionsJSON

            blockArrJSON.append(blockJSON)
        return blockArrJSON

    def firstBlock(self):
        firstB = Block(0, [])
        firstB.prev = None
        return firstB

    def mineTransactions(self, miner):
        lenT = len(self.pendingTransactions)
        if(lenT < 1):
            print("Need at least 1  transaction to mine")
            return False
        transacSlice = []
        for i in range(0, self.blockSize):
            if not self.pendingTransactions:
                break
            transacSlice.append(self.pendingTransactions.pop(0))
        hashVal = self.chain[-1].hash
        newBlock = Block(len(self.chain), transacSlice, prev=hashVal)
        payMiner = Transaction("Miner Rewards", miner, self.minerRewards)
        newBlock.transactions.append(payMiner)
        newBlock.miner = miner
        newBlock.mineBlock(self.difficulty)
        self.chain.append(newBlock)
        self.length +=1
        print("Mining Transactions Success!,Miner Paid")
        return True

    def addTransaction(self, sender, receiver, amount, signature, publicKey):
        if generateWalletAdressFromPublicKey(publicKey) != sender:
            return False
        t = Transaction(sender, receiver, amount, signature)
        if receiver == "MINER REWARDS":
            self.pendingTransactions.append(t)
        if sender == receiver or not t.validateSignature(publicKey, signature) or not sender or not receiver or not amount:
            return False

        self.pendingTransactions.append(t)
        print("Transaction Added")
        
        return True

    def balance(self, walletAdress):
        balance = 0
        for block in self.chain:
            for transaction in block.transactions:
                if(walletAdress == transaction.sender):
                    balance -= transaction.amount
                elif(walletAdress == transaction.receiver):
                    balance += transaction.amount
        return balance+100  # 100 tokens iniciais


class Block(object):
    def __init__(self, index, transactions=[], time=datetime.now().strftime("%m/%d/%Y, %H:%M:%S,%f"), prev=''):
        self.index = index
        self.nonce = 0
        self.transactions = transactions
        self.time = time
        self.prev = prev
        self.hash = self.calculateHash()
        self.miner = "None"

    def calculateHash(self):
        hashedTrans = ""
        for transaction in self.transactions:
            hashedTrans += transaction.hash
        stringToHash = str(self.time) + hashedTrans + \
            self.prev + str(self.nonce)
        hashEncoded = json.dumps(stringToHash, sort_keys=True).encode()
        return hashlib.sha256(hashEncoded).hexdigest()

    def mineBlock(self, difficulty):
        objective = difficulty*"0"
        while(self.hash[0:difficulty] != objective):
            self.nonce += 1
            self.hash = self.calculateHash()
        print("Block Mined")
        return True
    def hasValidTransactions(self):
        for i in range(0, len(self.transactions)):
            transaction = self.transactions[i]
            if not transaction.isValidTransaction():
                return False
        return True

class Transaction(object):
    def __init__(self, sender, receiver, amount, signature="NOTSIGNED"):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.time = datetime.now().strftime("%m/%d/%Y, %H:%M:%S,%f")
        self.hash = self.calculateHash()
        self.signature = signature

    def calculateHash(self):
        stringToHash = self.sender + self.receiver + \
            str(self.amount) + str(self.time)
        hashEncoded = json.dumps(stringToHash, sort_keys=True).encode()
        # retorna os dados encoded em formato hexadecimal
        return hashlib.sha256(hashEncoded).hexdigest()

    @staticmethod
    # parametros das chaves no tipo da biblioteca signTransaction(t,RSA.import_key(open('public.pem').read()),RSA.import_key(open('private.pem').read()))
    def getTransactionSignature(publicKEY, privateKEY):
        decodedPublicKey = publicKEY.publickey().export_key().decode('ASCII')
        msgHashed = SHA256.new(json.dumps(
            generateWalletAdressFromPublicKey(decodedPublicKey), sort_keys=True).encode())
        signature = pkcs1_15.new(privateKEY).sign(msgHashed)
        try:
            pkcs1_15.new(publicKEY).verify(msgHashed, signature)
            print("Signed Transaction")
        except (ValueError, TypeError):
            print("Transaction Signing Error")
            return False
        return signature

    # parametro é a key decoded de ascii
    def validateSignature(self, publicKey, signature):
        if signature == None:
            signature = self.signature
        key = RSA.import_key(publicKey)
        msgHashed = SHA256.new(json.dumps(generateWalletAdressFromPublicKey(publicKey), sort_keys=True).encode())
        try:
            pkcs1_15.new(key).verify(msgHashed, signature)
            print("Signature valid")
            self.signature = signature
            return True
        except (ValueError, TypeError):
            print("Signature not valid")
            return False


    def isValidTransaction(self):
        if(self.hash != self.calculateHash()):
            return False
        if(self.sender == self.receiver):
            return False
        if(self.sender == "Miner Rewards"):
            return True
        if not self.signature or len(self.signature) == 0:
            print("No Signature!")
            return False 
        return True


def generateRSAKeys():
    id = os.getpid()
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open("private{}.pem".format(os.getpid()), "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open("public{}.pem".format(os.getpid()), "wb")
    file_out.write(public_key)
    file_out.close()
    return key.publickey().export_key().decode('ASCII')


def generateWalletAdressFromPublicKey(publicKey):
    pubkey = hashlib.sha256(json.dumps(
        publicKey, sort_keys=True).encode()).hexdigest()
    compress_pubkey = False

    def hash160(hex_str):
        sha = hashlib.sha256()
        rip = hashlib.new('ripemd160')
        sha.update(hex_str)
        rip.update(sha.digest())
        return rip.hexdigest()  # .hexdigest() is hex ASCII

    if (compress_pubkey):
        if (ord(bytearray.fromhex(pubkey[-2:])) % 2 == 0):
            pubkey_compressed = '02'
        else:
            pubkey_compressed = '03'
        pubkey_compressed += pubkey[2:66]
        hex_str = bytearray.fromhex(pubkey_compressed)
    else:
        hex_str = bytearray.fromhex(pubkey)

    # Obtain key:

    key_hash = '00' + hash160(hex_str)

    # Obtain signature:

    sha = hashlib.sha256()
    sha.update(bytearray.fromhex(key_hash))
    checksum = sha.digest()
    sha = hashlib.sha256()
    sha.update(checksum)
    checksum = sha.hexdigest()[0:8]
    return base58.b58encode(bytes(bytearray.fromhex(key_hash + checksum))).decode('ASCII')


if __name__ == "__main__":
    generateRSAKeys()

    publicKeyCoded = RSA.import_key(
        open('public{}.pem'.format(os.getpid())).read())
    privateKeyCoded = RSA.import_key(
        open('private{}.pem'.format(os.getpid())).read())

    publicKeyDecoded = publicKeyCoded.export_key().decode('ASCII')
    privateKeyDecoded = privateKeyCoded.export_key().decode('ASCII')
    wallet = generateWalletAdressFromPublicKey(publicKeyDecoded)

    signature = Transaction.getTransactionSignature(
        publicKeyCoded, privateKeyCoded)
    b = Blockchain()
    t = Transaction(wallet, "lll", 5)
    print(wallet)
    print(b.addTransaction(wallet, "lll", 5, signature, publicKeyDecoded))
    print(b.addTransaction(wallet, "lll", 5, signature, publicKeyDecoded))
    print(b.mineTransactions(wallet))
    print(b.addTransaction(wallet, "lll", 5, signature, publicKeyDecoded))
    print(b.addTransaction(wallet, "lll", 5, signature, publicKeyDecoded))
    print(b.mineTransactions(wallet))
    print()
    t.validateSignature(publicKeyDecoded, signature)
    pp.pprint(b.jsonEncodeBC())
    print(b.balance(wallet))
    b.consensus()
    os.remove("public{}.pem".format(os.getpid()))
    os.remove("private{}.pem".format(os.getpid()))
