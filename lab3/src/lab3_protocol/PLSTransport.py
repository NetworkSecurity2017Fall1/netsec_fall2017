"""Transport"""
from playground.network.common import StackingTransport
from .PLSPackets import PlsData
from Crypto.Cipher import AES
from Crypto.Util import Counter


class PLSTransport(StackingTransport):

    def __init__(self, lowerTransport, IV, key):
        super().__init__(lowerTransport)
        print("IV in the transport: ", IV)
        print("Key in the transport: ", key)
        self.counter = Counter.new(128, initial_value=IV)
        self.aesEncrypter = AES.new(key, counter=self.counter, mode=AES.MODE_CTR)
        ctxt = self.aesEncrypter.encrypt(b'HelloWorld')
        pkt = PlsData.set(ctxt, b'')
        self.lowerTransport().write(pkt.__serialize__())


    def write(self, ptxt):
        ctxt = self.aesEncrypter.encrypt(ptxt)
        pkt = PlsData.set(ctxt, b'')
        self.lowerTransport().write(pkt.__serialize__())


        
