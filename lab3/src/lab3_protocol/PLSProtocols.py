"""Protocols"""

import random
# from . import Transport, CertFactory
# from .Packets import PlsHello, PlsKeyExchange, PlsHandshakeDone, PlsData, PlsClose, BasePacketType
from Packets import PlsHello, PlsKeyExchange, PlsHandshakeDone, PlsData, PlsClose, BasePacketType # Should del
from playground.network.common import StackingProtocol
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
from Crypto.Hash import SHA


class PLSProtocol(StackingProtocol):
    def __init__(self):
        super().__init__()
        random.seed()
        self.state = 0
        self.nonce = random.getrandbits(64)
        self.cert = []
        self.PreKey = b"HelloSky"  # modified after we know how to deal with cert
        self.message_digest = b"HelloSea"
        self.seed = b"PLS1.0"
        self.peerpk = 123 # modified after we know how to deal with cert
        self.mysk = 321 # modified after we know how to deal with cert
        self.EKc = 0
        self.EKs = 0
        self.IVc = 0
        self.IVs = 0
        self.MKc = 0
        self.MKs = 0
        self.deserializer = BasePacketType.Deserializer()
        self.peerRsaEncrypter = PKCS1OAEP_Cipher(self.peerpk, None, None, None)
        self.myRsaDecrypter = PKCS1OAEP_Cipher(self.mysk, None, None, None)

    def connection_lost(self, exc):
        print("PLS: Lost connection to client. Cleaning up.")
        if self.transport is not None:
            self.transport.close()
        if self.higherProtocol():
            self.higherProtocol().connection_lost(None)

    def data_received(self, data):
        self.counter = 5
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            print("PLS: Received PLS packet.", pkt.to_string())
            self.packet_processing(pkt)

    def packet_processing(self, pkt):
        if type(pkt) is PlsHello:
            if self.state == 0:
                self.state = 1
                pkt_rsps = PlsHello(self.nonce, self.cert)
            elif self.state == 1:
                self.state = 2
                encrypted_prekey = self.peerRsaEncrypter.encrypt(self.PreKey)
                pkt_rsps = PlsKeyExchange(encrypted_prekey, pkt.Nonce + 1)
            else:
                return
            pkt_rsps_bytes = pkt_rsps.__serialize__()
            self.transport.write(pkt_rsps_bytes)
        elif type(pkt) is PlsKeyExchange:
            if self.state == 1 and pkt.Nonce == self.nonce + 1:
                self.state = 2
                encrypted_prekey = self.peerRsaEncrypter.encrypt(self.PreKey)
                pkt_rsps = PlsKeyExchange(encrypted_prekey, pkt.Nonce + 1)
            elif self.state == 2 and pkt.Nonce == self.nonce + 1:
                self.state = 3
                pkt_rsps = PlsHandshakeDone(self.message_digest)
            else:
                return
            pkt_rsps_bytes = pkt_rsps.__serialize__()
            self.transport.write(pkt_rsps_bytes)
        elif type(pkt) is PlsHandshakeDone:
            if self.state == 2:
                self.state = 3
                self.ctrDecrypt = Counter.new(128, initial_value=pkt.Nonce)
                self.aesDecrypter = AES.new(0, counter=self.ctrDecrypt, mode=AES.MODE_CTR)  # key set to 0
                pkt_rsps = PlsHandshakeDone(self.message_digest)
                pkt_rsps_bytes = pkt_rsps.__serialize__()
                self.transport.write(pkt_rsps_bytes)
            elif self.state == 3:
                self.ctrDecrypt = Counter.new(128, initial_value=pkt.Nonce)
                self.aesDecrypter = AES.new(0, counter=self.ctrDecrypt, mode=AES.MODE_CTR)  # key set to 0
                self.state = 4
            else:
                return

    def key_derivation(self, seed):
        block_0 = self.sha_hash(seed)
        block_1 = self.sha_hash(block_0)
        block_2 = self.sha_hash(block_1)
        block_3 = self.sha_hash(block_2)
        block_4 = self.sha_hash(block_3)
        self.EKc = block_0[:16]
        self.EKs = block_0[16:] + block_1[:12]
        self.IVc = block_1[12:] + block_2[:8]
        self.IVs = block_2[8:] + block_3[:4]
        self.MKc = block_3[4:]
        self.MKs = block_4[:16]

    def setup_signer(self, key):
        with open("privateKey.pem") as f:
            rawKey = f.read()
        rsaKey = RSA.importKey(rawKey)
        rsaSigner = PKCS1_v1_5.new(key)

    def sha_hash(self, data):
        hasher = SHA.new()
        hasher.update(data)
        return hasher.digest()

    def rsa_enc(self, pk, data):
        peerRsaEncrypter = PKCS1OAEP_Cipher(pk, None, None, None)
        return peerRsaEncrypter.encrypt(data)


    def cert_verification(self):
        ## verify certificate ##
        return True







class PLSServerProtocol(PLSProtocol):
    def connection_made(self, transport):
        print("PLSServer: Received a connection from {}".format(transport.get_extra_info("peername")))
        self.transport = transport


class PLSClientProtocol(PLSProtocol):
    def connection_made(self, transport):
        print("PLSClient: Connection established with server")
        self.transport = transport
        self.handshake()

    def handshake(self):
        pkt = PlsHello(self.nonce, self.cert)
        pkt_bytes = pkt.__serialize__()
        print("PLS: Starting handshake")
        self.transport.write(pkt_bytes)
        self.state = 1


if __name__ == "__main__":
    myprotocol = PLSProtocol()
    peerprotocol = PLSProtocol()

    # test rsa encryption, decryption
    key = RSA.generate(2048)
    data = b"bye"
    myprotocol.peerRsaEncrypter = PKCS1OAEP_Cipher(key, None, None, None)
    peerprotocol.myRsaDecrypter = PKCS1OAEP_Cipher(key, None, None, None)
    ciphertxt = myprotocol.peerRsaEncrypter.encrypt(data)
    recoveredtxt = peerprotocol.myRsaDecrypter.decrypt(ciphertxt)
    print(ciphertxt)
    print(recoveredtxt)

    # test sha_hash
    bytes = b"hello world"
    ans = myprotocol.sha_hash(bytes)

    # test key_derivation
    myprotocol.key_derivation(myprotocol.seed)
    print(myprotocol.EKc)
    print(myprotocol.EKs)
    print(myprotocol.IVc)
    print(myprotocol.IVs)
    print(myprotocol.MKc)
    print(myprotocol.MKs)

    print(myprotocol.nonce)
