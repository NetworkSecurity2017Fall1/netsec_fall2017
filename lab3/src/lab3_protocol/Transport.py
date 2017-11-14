"""Transport"""
from playground.network.common import StackingTransport
from . import Packets
from Crypto.Cipher import AES
from Crypto.Util import Counter


class MyProtocolTransport(StackingTransport):

    def __init__(self, lowerTransport, nonce, key):
        super().__init__(lowerTransport)
        self.counter = Counter.new(128, initial_value=nonce)
        self.aesEncrypter = AES.new(key, counter=self.counter, mode=AES.MODE_CTR)

    def reset_all(self):
        print("Hello World")

    def write(self, ptxt):
        ctxt = self.aesEncrypter.encrypt(ptxt)
        self.lowerTransport().write(ctxt)



        
