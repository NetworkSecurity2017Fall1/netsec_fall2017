"""Transport"""
from playground.network.common import StackingTransport
from .PLSPackets import PlsData
from Crypto.Cipher import AES
from Crypto.Util import Counter
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

class PLSTransport(StackingTransport):

    def __init__(self, lowerTransport, IV, k_enc, k_mac):
        super().__init__(lowerTransport)
        # print("IV in the transport: ", IV)
        # print("Key in the transport: ", k_enc)
        self.k_mac = k_mac
        self.counter = Counter.new(128, initial_value=IV)
        self.aesEncrypter = AES.new(k_enc, counter=self.counter, mode=AES.MODE_CTR)

    def write(self, ptxt):
        ctxt = self.aesEncrypter.encrypt(ptxt)
        mac = self.mac_compute(ctxt)
        pkt = PlsData.set(ctxt, mac)
        self.lowerTransport().write(pkt.__serialize__())

    def mac_compute(self, ctxt):
        h = hmac.HMAC(self.k_mac, hashes.SHA256(), backend=default_backend())
        h.update(ctxt)
        return h.finalize()