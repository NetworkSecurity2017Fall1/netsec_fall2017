""""Packets"""

import zlib
import asyncio
import logging
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, UINT8, UINT16, BUFFER, STRING
from playground.network.packet.fieldtypes.attributes import Optional


# Comment out this block when you don't want to be distracted by logs
# loop = asyncio.get_event_loop()
# loop.set_debug(enabled=True)
# logging.getLogger().setLevel(logging.NOTSET)  # this logs everything going on
# logging.getLogger().addHandler(logging.StreamHandler())


class PLSPacket(PacketType):
    DEFINITION_IDENTIFIER = "SL.Packet"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Type", UINT8),
        ("Source", STRING({Optional: True})),
        ("SharedKey", UINT32({Optional: True})),
        ("Nonce", UINT32({Optional: True})),
        ("Data", BUFFER({Optional: True}))
    ]

    def __init__(self, typ=5):
        super().__init__()
        self.Type = typ

    @classmethod
    def set_clienthello(cls, nonce):
        pkt = cls(0)
        pkt.Nonce = nonce
        return pkt

    @classmethod
    def set_serverhello(cls, nonce):
        pkt = cls(1)
        pkt.Nonce = nonce
        return pkt

    @classmethod
    def set_encdata(cls, data):
        pkt = cls(2)
        pkt.Data = data
        return pkt

    def to_string(self):
        return "Type = " + self.get_type_string() + ". Source = " + str(self.Source) \
               + ". SharedKey = " + str(self.SharedKey) + ". Nonce = " + str(self.Nonce)

    def get_type_string(self):
        packet_type = ["ClientHello", "ServerHello", "EncData"]
        return packet_type[self.Type]

    # def calculateChecksum(self):
    #     oldChecksum = self.Checksum
    #     self.Checksum = 0
    #     bytes = self.__serialize__()
    #     self.Checksum = oldChecksum
    #     return zlib.adler32(bytes) & 0xffff

    # def validate_checksum(self):
    #     return self.Checksum == self.calculateChecksum()



# PLS Protocol Types
# -------------------
# SYN         TYPE 0
# SYN-ACK     TYPE 1
# ACK         TYPE 2
# RIP         TYPE 3
# RIP-ACK     TYPE 4
# DATA        TYPE 5

