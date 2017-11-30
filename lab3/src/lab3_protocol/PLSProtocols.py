"""Protocols"""

from .PLSTransport import *
from .PLSPackets import *
from .CertFactory import *
import os, random
from playground.network.common import StackingProtocol
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
from Crypto.Hash import SHA
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

class PLSProtocol(StackingProtocol):
    def __init__(self):
        super().__init__()
        random.seed()
        self.deserializer = BasePacketType.Deserializer()
        self.state = 0
        self.cert = []
        self.PreKey = os.urandom(16)
        self.digest = b''
        self.seed = b'PLS1.0'
        self.NCm = random.getrandbits(64)
        self.NCp = 0
        self.PKp = RSA.generate(2048)
        self.SKm = RSA.generate(2048)
        self.EKm = b''
        self.EKp = b''
        self.IVm = b''
        self.IVp = b''
        self.MKm = b''
        self.MKp = b''


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
                self.NCp = pkt.Nonce
                self.cert_verification(pkt.Certs)
                self.seed = self.seed + pkt.Nonce.to_bytes(8, byteorder='big') + self.NCm.to_bytes(8, byteorder='big')
                self.PKp = x509.load_pem_x509_certificate(pkt.Certs[0], default_backend()).public_key()
                pkt_rsps = PlsHello.set(self.NCm, self.cert)
            elif self.state == 1:
                self.state = 2
                self.NCp = pkt.Nonce
                self.cert_verification(pkt.Certs)
                self.seed = self.seed + pkt.Nonce.to_bytes(8, byteorder='big') + self.PreKey
                self.PKp = x509.load_pem_x509_certificate(pkt.Certs[0], default_backend()).public_key()
                encrypted_prekey = self.rsa_enc(self.PKp, self.PreKey)
                pkt_rsps = PlsKeyExchange.set(encrypted_prekey, pkt.Nonce + 1)
            else:
                return
            pkt_rsps_bytes = pkt_rsps.__serialize__()
            self.transport.write(pkt_rsps_bytes)
            self.digest = self.digest + pkt.__serialize__() + pkt_rsps_bytes
        elif type(pkt) is PlsKeyExchange:
            # print("This packet is PlsExchange")
            if self.state == 1 and pkt.NoncePlusOne == self.NCm + 1:
                self.state = 2
                PKc = self.rsa_dec(self.SKm, pkt.PreKey)
                enc_PKs = self.rsa_enc(self.PKp, self.PreKey)
                pkt_rsps = PlsKeyExchange.set(enc_PKs, self.NCp + 1)
                pkt_rsps_bytes = pkt_rsps.__serialize__()
                self.transport.write(pkt_rsps_bytes)
                self.digest = self.digest + pkt.__serialize__() + pkt_rsps_bytes
                self.seed = self.seed + PKc + self.PreKey
                print("team5 Server seed: ", self.seed)
                self.key_derivation(self.seed, False)
                self.state = 3
                # print("Server's digest: ", self.digest)
                pkt_rsps2 = PlsHandshakeDone.set(self.sha_hash(self.digest))
                pkt_rsps2_bytes = pkt_rsps2.__serialize__()
                self.transport.write(pkt_rsps2_bytes)
            elif self.state == 2 and pkt.NoncePlusOne == self.NCm + 1:
                self.state = 3
                # print("Client's digest: ", self.digest)
                PKs = self.rsa_dec(self.SKm, pkt.PreKey)
                self.digest = self.digest +  pkt.__serialize__()
                self.seed = self.seed + PKs
                print("team5 Client seed: ", self.seed)
                self.key_derivation(self.seed, True)
                pkt_rsps = PlsHandshakeDone.set(self.sha_hash(self.digest))
                pkt_rsps_bytes = pkt_rsps.__serialize__()
                self.transport.write(pkt_rsps_bytes)
            else:
                return
        elif type(pkt) is PlsHandshakeDone:
            if self.state == 3:
                self.state = 4
                self.digest_verification(pkt.ValidationHash)
                IVp = int.from_bytes(self.IVp, byteorder='big')
                IVm = int.from_bytes(self.IVm, byteorder='big')
                # print("IV in the protocol: ", IVp)
                # print("Key in the protocol: ", self.EKp)
                self.ctrDecrypt = Counter.new(128, initial_value=IVp)
                self.aesDecrypter = AES.new(self.EKp, counter=self.ctrDecrypt, mode=AES.MODE_CTR)
                self.higherProtocol().connection_made(PLSTransport(self.transport, IVm, self.EKm, self.MKm))
            else:
                return
        elif type(pkt) is PlsData:
            if self.state == 4:
                self.mac_verify(pkt.Ciphertext, pkt.Mac)
                self.higherProtocol().data_received(self.aesDecrypter.decrypt(pkt.Ciphertext))

    def digest_verification(self, digest):
        if digest != self.sha_hash(self.digest):
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
            print("team5 Client EKm: ", self.EKm)
            print("team5 Client EKp: ", self.EKp)
            print("team5 Client IVm: ", self.IVm)
            print("team5 Client IVp: ", self.IVp)
            print("team5 Client MKm: ", self.MKm)
            print("team5 Client MKp: ", self.MKp)
        else:
            self.EKp = block_0[:16]
            self.EKm = block_0[16:] + block_1[:12]
            self.IVp = block_1[12:] + block_2[:8]
            self.IVm = block_2[8:] + block_3[:4]
            self.MKp = block_3[4:]
            self.MKm = block_4[:16]
            print("team5 Server EKm: ", self.EKm)
            print("team5 Server EKp: ", self.EKp)
            print("team5 Server IVm: ", self.IVm)
            print("team5 Server IVp: ", self.IVp)
            print("team5 Server MKm: ", self.MKm)
            print("team5 Server MKp: ", self.MKp)

    def sha_hash(self, data):
        hasher = SHA.new()
        hasher.update(data)
        return hasher.digest()

    def load_sk(self, address):
        key_bytes = getPrivateKeyForAddr("hello")
        self.SKm = serialization.load_pem_private_key(
            key_bytes,
            password=None,
            backend=default_backend()
        )

    def rsa_enc(self, pk, data):
        return pk.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None)
        )

    def rsa_dec(self, sk, data):
        return sk.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None)
        )

    def GetCommonName(self, cert):
        commonNameList = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(commonNameList) != 1: return None
        commonNameAttr = commonNameList[0]
        return commonNameAttr.value

    def cert_verification(self, cert_list):
        cert = x509.load_pem_x509_certificate(cert_list[0], default_backend())
        print(self.GetCommonName(cert))
        print(self.transport.get_extra_info("peername")[0])
        for i in range(1, len(cert_list)):
            # print(i)
            cert = x509.load_pem_x509_certificate(cert_list[i - 1], default_backend())
            pk = x509.load_pem_x509_certificate(cert_list[i], default_backend()).public_key()
            pk.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )

    def load_cert(self):
        address = "hello"
        self.cert = getCertsForAddr(address)

    def mac_verify(self, data, mac):
        h = hmac.HMAC(self.MKp, hashes.SHA1(), backend=default_backend())
        h.update(data)
        try:
            h.verify(mac)
            return True
        except Exception as e:
            print(e)
            return False

class PLSServerProtocol(PLSProtocol):
    def connection_made(self, transport):
        # print("PLSServer: Received a connection from {}".format(transport.get_extra_info("peername")))
        self.transport = transport
        self.load_cert()
        self.load_sk('server_certificate/local.key')


class PLSClientProtocol(PLSProtocol):
    def connection_made(self, transport):
        # print("PLSClient: Connection established with server")
        self.transport = transport
        self.load_cert()
        self.load_sk('client_certificate/local.key')
        self.handshake()

    def handshake(self):
        # print("PLS: Starting handshake")
        pkt = PlsHello.set(self.NCm, self.cert)
        self.state = 1
        self.seed = self.seed + self.NCm.to_bytes(8, byteorder='big')
        self.digest = pkt.__serialize__()
        self.transport.write(self.digest)
