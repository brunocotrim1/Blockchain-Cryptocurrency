from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from urllib import response
from numpy import block
from blockchain import *
import atexit
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
def exit_handler():
    os.remove("public{}.pem".format(os.getpid()))
    os.remove("private{}.pem".format(os.getpid()))
    os.remove("wallet{}.pem".format(os.getpid()))

atexit.register(exit_handler)      
print("Client Number {}".format(os.getpid()))
mainAdress = "0.0.0.0:"+input("Node to Connect")
generateRSAKeys()

publicKeyCoded = RSA.import_key(
    open('public{}.pem'.format(os.getpid())).read())
privateKeyCoded = RSA.import_key(
    open('private{}.pem'.format(os.getpid())).read())

publicKeyDecoded = publicKeyCoded.export_key().decode('ASCII')
privateKeyDecoded = privateKeyCoded.export_key().decode('ASCII')
wallet = generateWalletAdressFromPublicKey(publicKeyDecoded)
file_out = open("wallet{}.pem".format(os.getpid()), "w")
file_out.write(wallet)
file_out.close()
signature = Transaction.getTransactionSignature(
    publicKeyCoded, privateKeyCoded)


while(True):
    i = input("ACTION:  ")
    if i == "send":
        receiver = input("Enter your receiver: ")
        amount = float(input("Enter your amount: "))
        tJSON = {}
        tJSON['sender'] = wallet
        tJSON['receiver'] = receiver
        tJSON['amount'] = amount
        tJSON['signature'] = bytes_to_long(signature)
        tJSON['public'] = publicKeyDecoded
        try:
            resp = requests.put("http://"+mainAdress+"/addTransaction", data=json.dumps(tJSON, sort_keys=True).encode())
        except:
            print("")
    elif i == "balance":    
        try:
            resp = requests.get("http://"+mainAdress+"/balance/"+wallet)
            print(json.loads(resp.text)["balance"])
        except:
            print("ERROR")