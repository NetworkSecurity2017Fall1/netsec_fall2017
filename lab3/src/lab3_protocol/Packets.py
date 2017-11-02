""""Packets"""

import zlib
import asyncio
import logging
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT64, UINT8, BUFFER, STRING, LIST
from playground.network.packet.fieldtypes.attributes import Optional


# Comment out this block when you don't want to be distracted by logs
# loop = asyncio.get_event_loop()
# loop.set_debug(enabled=True)
# logging.getLogger().setLevel(logging.NOTSET)  # this logs everything going on
# logging.getLogger().addHandler(logging.StreamHandler())


class PlsHello(PacketType):
    DEFINITION_IDENTIFIER = "netsecfall2017.pls.hello"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Nonce", UINT64),
        ("Certs", LIST(BUFFER))
    ]

    def __init__(self, nonce, certs):
        super().__init__()
        self.Nonce = nonce
        self.Certs = certs


class PlsKeyExchange(PacketType):
    DEFINITION_IDENTIFIER = "netsecfall2017.pls.keyexchange"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("PreKey", BUFFER),
        ("NoncePlusOne", UINT64),
    ]

    def __init__(self, k, n):
        super().__init__()
        self.PreKey = k
        self.NoncePlusOne = n

class PlsHandshakeDone(PacketType):
    DEFINITION_IDENTIFIER = "netsecfall2017.pls.handshakedone"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("ValidationHash", BUFFER)
    ]

    def __init__(self, valid):
        super().__init__()
        self.ValidationHash = valid


class PlsData(PacketType):
    DEFINITION_IDENTIFIER = "netsecfall2017.pls.data"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Ciphertext", BUFFER),
        ("Mac", BUFFER)
    ]

    def __init__(self, c, m):
        super().__init__()
        self.Ciphertext = c
        self.Mac = m


class PlsClose(PacketType):
    DEFINITION_IDENTIFIER = "netsecfall2017.pls.close"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Error", STRING({Optional: True}))
    ]

    def __init__(self, err):
        super().__init__()
        self.Error = err

if __name__ == "__main__":
    cert = []
    Nc = 0
    pkt = PlsHello(Nc, cert)
    print(type(Nc) is int)
    print(type(pkt) is PlsHello)
