"""Protocols"""

from .PLSTransport import *
from .PLSPackets import *
# from PLSPackets import *
# from PLSTransport import *
import os, random
from playground.network.common import StackingProtocol
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
from Crypto.Hash import SHA

fixed_key = RSA.generate(2048)


class PLSProtocol(StackingProtocol):
    def __init__(self):
        super().__init__()
        random.seed()
        self.state = 0
        self.mynonce = random.getrandbits(64)
        self.peernonce = 0
        self.cert = []
        self.PreKey = os.urandom(16)  # not sure whether this should be a random number
        self.digest = b''
        self.seed = b'PLS1.0'
        self.peerpk = fixed_key  # modified after we know how to deal with cert
        self.mysk = fixed_key  # modified after we know how to deal with cert
        self.EKm = b''
        self.EKp = b''
        self.IVm = b''
        self.IVp = b''
        self.MKm = b''
        self.MKp = b''
        self.deserializer = BasePacketType.Deserializer()
        self.peerRsaEncrypter = PKCS1OAEP_Cipher(self.peerpk, None, None, None)
        self.myRsaDecrypter = PKCS1OAEP_Cipher(self.mysk, None, None, None)

    def connection_lost(self, exc):
        # print("PLS: Lost connection to client. Cleaning up.")
        if self.transport is not None:
            self.transport.close()
        if self.higherProtocol():
            self.higherProtocol().connection_lost(None)

    def data_received(self, data):
        # print("PLS: Received data")
        self.deserializer.update(data)
        # print("PLS: Deserialize data")
        for pkt in self.deserializer.nextPackets():
            # print("PLS: Packet type: ", type(pkt))
            self.packet_processing(pkt)

    def packet_processing(self, pkt):
        if type(pkt) is PlsHello:
            # print("This packet is PlsHello")
            if self.state == 0:
                self.state = 1
                self.peernonce = pkt.Nonce
                self.seed = self.seed + pkt.Nonce.to_bytes(8, byteorder='big') + self.mynonce.to_bytes(8, byteorder='big')
                pkt_rsps = PlsHello.set(self.mynonce, self.cert)
            elif self.state == 1:
                self.state = 2
                self.peernonce = pkt.Nonce
                self.seed = self.seed + pkt.Nonce.to_bytes(8, byteorder='big') + self.PreKey
                encrypted_prekey = self.peerRsaEncrypter.encrypt(self.PreKey)
                pkt_rsps = PlsKeyExchange.set(encrypted_prekey, pkt.Nonce + 1)
            else:
                return
            pkt_rsps_bytes = pkt_rsps.__serialize__()
            self.transport.write(pkt_rsps_bytes)
            self.digest = self.digest + pkt.__serialize__() + pkt_rsps_bytes
        elif type(pkt) is PlsKeyExchange:
            # print("This packet is PlsExchange")
            if self.state == 1 and pkt.NoncePlusOne == self.mynonce + 1:
                self.state = 2
                PKc = self.myRsaDecrypter.decrypt(pkt.PreKey)
                enc_PKs = self.peerRsaEncrypter.encrypt(self.PreKey)
                pkt_rsps = PlsKeyExchange.set(enc_PKs, self.peernonce + 1)
                pkt_rsps_bytes = pkt_rsps.__serialize__()
                self.transport.write(pkt_rsps_bytes)
                self.digest = self.digest + pkt.__serialize__() + pkt_rsps_bytes
                self.seed = self.seed + PKc + self.PreKey
                print("Server seed: ", self.seed)
                self.key_derivation(self.seed, False)
                self.state = 3
                # print("Server's digest: ", self.digest)
                pkt_rsps2 = PlsHandshakeDone.set(self.digest)
                pkt_rsps2_bytes = pkt_rsps2.__serialize__()
                self.transport.write(pkt_rsps2_bytes)
            elif self.state == 2 and pkt.NoncePlusOne == self.mynonce + 1:
                self.state = 3
                # print("Client's digest: ", self.digest)
                PKs = self.myRsaDecrypter.decrypt(pkt.PreKey)
                self.digest = self.digest +  pkt.__serialize__()
                self.seed = self.seed + PKs
                print("Client seed: ", self.seed)
                self.key_derivation(self.seed, True)
                pkt_rsps = PlsHandshakeDone.set(self.digest)
                pkt_rsps_bytes = pkt_rsps.__serialize__()
                self.transport.write(pkt_rsps_bytes)
            else:
                return
        elif type(pkt) is PlsHandshakeDone:
            print("This packet is PlsHandshakeDone")
            print("This packet is PlsHandshakeDone")
            print("This packet is PlsHandshakeDone")
            print("This packet is PlsHandshakeDone")
            if self.state == 3:
                self.state = 4
                self.digest_verification(pkt.ValidationHash)
                IVp = int.from_bytes(self.IVp, byteorder='big')
                IVm = int.from_bytes(self.IVm, byteorder='big')
                print("IV in the protocol: ", IVp)
                print("Key in the protocol: ", self.EKp)
                self.ctrDecrypt = Counter.new(128, initial_value=IVp)
                self.aesDecrypter = AES.new(self.EKp, counter=self.ctrDecrypt, mode=AES.MODE_CTR)
                self.higherProtocol().connection_made(PLSTransport(self.transport, IVm, self.EKm))
                print("PLS handshake complete")
                print("PLS handshake complete")
                print("PLS handshake complete")
                print("PLS handshake complete")
                print("PLS handshake complete")
                print("PLS handshake complete")
            else:
                return
        elif type(pkt) is PlsData:
            if self.state == 4:
                ptxt = self.aesDecrypter.decrypt(pkt.Ciphertext)
                # print("plain text: ", ptxt)
                self.higherProtocol().data_received(ptxt)

    def digest_verification(self, digest):
        print("PLS: Digest verification")
        print("PLS: Digest verification")
        print("PLS: Digest verification")
        print("PLS: Digest verification")
        print("PLS: Digest verification")
        print("PLS: Digest verification")

        # print(digest)
        # print(self.digest)
        if digest != self.digest:
            self.transport.close()

    def key_derivation(self, seed, role): # True is client, False is Server
        block_0 = self.sha_hash(seed)
        block_1 = self.sha_hash(block_0)
        block_2 = self.sha_hash(block_1)
        block_3 = self.sha_hash(block_2)
        block_4 = self.sha_hash(block_3)
        if(role):
            self.EKm = block_0[:16]
            self.EKp = block_0[16:] + block_1[:12]
            self.IVm = block_1[12:] + block_2[:8]
            self.IVp = block_2[8:] + block_3[:4]
            self.MKm = block_3[4:]
            self.MKp = block_4[:16]
            print("Client EKm: ", self.EKm)
            print("Client EKp: ", self.EKp)
        else:
            self.EKp = block_0[:16]
            self.EKm = block_0[16:] + block_1[:12]
            self.IVp = block_1[12:] + block_2[:8]
            self.IVm = block_2[8:] + block_3[:4]
            self.MKp = block_3[4:]
            self.MKm = block_4[:16]
            print("Server EKm: ", self.EKm)
            print("Server EKp: ", self.EKp)

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
        # print("PLSServer: Received a connection from {}".format(transport.get_extra_info("peername")))
        self.transport = transport


class PLSClientProtocol(PLSProtocol):
    def connection_made(self, transport):
        # print("PLSClient: Connection established with server")
        self.transport = transport
        self.handshake()

    def handshake(self):
        pkt = PlsHello.set(self.mynonce, self.cert)
        pkt_bytes = pkt.__serialize__()
        # print("PLS: Starting handshake")
        self.transport.write(pkt_bytes)
        self.state = 1
        self.digest = pkt_bytes
        self.seed = self.seed + self.mynonce.to_bytes(8, byteorder='big')

# if __name__ == "__main__":
#     client = PLSClientProtocol()
#     server = PLSServerProtocol()

    # test rsa encryption, decryption
    # key = RSA.generate(2048)
    # prekey = os.urandom(16)
    # print(prekey)
    # data = prekey
    # client.peerRsaEncrypter = PKCS1OAEP_Cipher(key, None, None, None)
    # server.myRsaDecrypter = PKCS1OAEP_Cipher(key, None, None, None)
    # ciphertxt = client.peerRsaEncrypter.encrypt(data)
    # recoveredtxt = server.myRsaDecrypter.decrypt(ciphertxt)
    # print(ciphertxt)
    # print(recoveredtxt)

    # test sha_hash
    # bytes = b"hello world"
    # ans = client.sha_hash(bytes)

    # test key_derivation
    # client.key_derivation(client.seed)
    # print(client.EKc)
    # print(client.EKs)
    # print(client.IVc)
    # print(client.IVs)
    # print(client.MKc)
    # print(client.MKs)

    # test desrializer
    # print("Start testing desrializer  ")
    # mynonce = 123
    # cert = []
    # pkt = PlsHello.set(mynonce, cert)
    # print(pkt.Nonce)
    # print(pkt.Certs)
    # bytes = pkt.__serialize__()
    # print(bytes)
    # _deserializer = BasePacketType.Deserializer()
    # _deserializer.update(bytes)
    # for p in _deserializer.nextPackets():
    #     print("There is a packet")
    #     print("Type: ", type(p))
    # print("End testing desrializer  ")

    # test data_received()
    # mynonce = 123
    # cert = []
    # pkt = PlsHello.set(mynonce, cert)
    # server.data_received(pkt.__serialize__())


    # print(client.mynonce)
