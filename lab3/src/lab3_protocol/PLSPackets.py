""""Packets"""

from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT64, UINT8, BUFFER, STRING, LIST
from playground.network.packet.fieldtypes.attributes import Optional

class BasePacketType(PacketType):
    DEFINITION_IDENTIFIER = "netsecfall2017.pls.basepacket"
    DEFINITION_VERSION = "1.0"

    def __init__(self):
        super().__init__()

class PlsHello(BasePacketType):
    DEFINITION_IDENTIFIER = "netsecfall2017.pls.hello"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Nonce", UINT64),
        ("Certs", LIST(BUFFER))
    ]

    @classmethod
    def set(cls, nonce, certs):
        pkt = cls()
        pkt.Nonce = nonce
        pkt.Certs = certs
        return pkt




class PlsKeyExchange(BasePacketType):
    DEFINITION_IDENTIFIER = "netsecfall2017.pls.keyexchange"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("PreKey", BUFFER),
        ("NoncePlusOne", UINT64),
    ]
    @classmethod
    def set(cls, k, n):
        pkt = cls()
        pkt.PreKey = k
        pkt.NoncePlusOne = n
        return pkt

class PlsHandshakeDone(BasePacketType):
    DEFINITION_IDENTIFIER = "netsecfall2017.pls.handshakedone"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("ValidationHash", BUFFER)
    ]

    @classmethod
    def set(cls, valid):
        pkt = cls()
        pkt.ValidationHash = valid
        return pkt


class PlsData(BasePacketType):
    DEFINITION_IDENTIFIER = "netsecfall2017.pls.data"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Ciphertext", BUFFER),
        ("Mac", BUFFER)
    ]

    @classmethod
    def set(cls, c, m):
        pkt = cls()
        pkt.Ciphertext = c
        pkt.Mac = m
        return pkt


class PlsClose(BasePacketType):
    DEFINITION_IDENTIFIER = "netsecfall2017.pls.close"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Error", STRING({Optional: True}))
    ]

    @classmethod
    def set(cls, err):
        pkt = cls()
        pkt.Error = err
        return pkt

# if __name__ == "__main__":
    # cert = []
    # Nc = 0
    # pkt = PlsHello(Nc, cert)
    # print(type(Nc) is int)
    # print(type(pkt) is PlsHello)

    # data = b'HelloWorld'
    # pkt = PlsData.set(data, b'')
    # print(pkt.Ciphertext)
    # print(pkt.Mac)
