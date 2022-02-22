from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from urllib import response
from numpy import block
from blockchain import *
import atexit
from Crypto.Util.number import ceil_div, bytes_to_long, long_to_bytes


blockChain = Blockchain()
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

blockChain = Blockchain()
class handlerHTTP(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path =="/blockchain":
            self.send_response(200)
            self.send_header('content-type','application/json')
            self.end_headers()
            response = {"length":blockChain.length, "chain": blockChain.jsonEncodeBC()}
            self.wfile.write(json.dumps(response, sort_keys=True).encode())
        elif self.path =="/allNodes":
            self.send_response(200)
            self.send_header('content-type','application/json')
            self.end_headers()
            response = {"adresses":blockChain.nodes}
            self.wfile.write(json.dumps(response, sort_keys=True).encode())
        elif "/balance" in self.path:
            self.send_response(200)
            self.send_header('content-type','application/json')
            self.end_headers()
            blockChain.consensus()
            response = {"balance":blockChain.balance(self.path.split("/")[2])}
            self.wfile.write(json.dumps(response, sort_keys=True).encode())
    def do_PUT(self):
        if self.path =="/registerNode":
            blockChain.registerNode(self.rfile.read(int(self.headers.get('content-length'))).decode("ASCII"))
            self.send_response(200)
        if self.path == "/addTransaction":
            transaction = json.loads(self.rfile.read(int(self.headers.get('content-length'))).decode("ASCII"))
            con = blockChain.consensus()
            ad = blockChain.addTransaction(transaction["sender"], transaction["receiver"], float(transaction["amount"]), long_to_bytes(transaction["signature"]), transaction["public"])
            print(con)
            print(ad)
            if con and ad:
                print("Transaction Added Sucessfully")
                blockChain.mineTransactions(wallet)
            else:
                print("Transaction Not Added")
            self.send_response(200)


PORT = int(input("Choose Port:  "))
print("Server listening on "+str(PORT))
server = HTTPServer(('',PORT),handlerHTTP)
def exit_handler():
    server.server_close()
    os.remove("public{}.pem".format(os.getpid()))
    os.remove("private{}.pem".format(os.getpid()))
atexit.register(exit_handler)        
server.serve_forever()