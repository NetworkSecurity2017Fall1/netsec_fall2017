""""Packets"""

import zlib
import asyncio
import logging
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, UINT8, UINT16, BUFFER
from playground.network.packet.fieldtypes.attributes import Optional

# Comment out this block when you don't want to be distracted by logs
# loop = asyncio.get_event_loop()
# loop.set_debug(enabled=True)
# logging.getLogger().setLevel(logging.NOTSET)  # this logs everything going on
# logging.getLogger().addHandler(logging.StreamHandler())


class PEEPPacket(PacketType):
    DEFINITION_IDENTIFIER = "PEEP.Packet"
    DEFINITION_VERSION = "1.0"
    
    FIELDS = [
        ("Type", UINT8),
        ("SequenceNumber", UINT32({Optional: True})),
        ("Checksum", UINT16),
        ("Acknowledgement", UINT32({Optional: True})),
        ("Data", BUFFER({Optional: True}))
    ]

    def __init__(self, typ=5, seq=0, ack=0, che=0):
        super().__init__()
        self.Type = typ
        self.SequenceNumber = seq
        self.Acknowledgement = ack
        self.Checksum = che

    @classmethod
    def set_all(cls, typ, seq, ack):
        return cls(typ, seq, ack, 0)

    def to_string(self):
        return "Type = " + self.get_type_string() + ". SEQ = " + str(self.SequenceNumber) \
               + ". ACK = " + str(self.Acknowledgement) + ". Checksum = " + str(self.Checksum)

    def calculateChecksum(self):
        oldChecksum = self.Checksum
        self.Checksum = 0
        bytes = self.__serialize__()
        self.Checksum = oldChecksum
        return zlib.adler32(bytes) & 0xffff
    
    def is_checksum_legit(self):
        return self.Checksum == self.calculateChecksum()

    def get_type_string(self):
        packet_type = ["SYN", "SYN-ACK", "ACK", "RIP", "RIP-ACK", "DATA"]
        return packet_type[self.Type]

# PEEP Protocol Types
# -------------------
# SYN         TYPE 0
# SYN-ACK     TYPE 1
# ACK         TYPE 2
# RIP         TYPE 3
# RIP-ACK     TYPE 4
# DATA        TYPE 5
