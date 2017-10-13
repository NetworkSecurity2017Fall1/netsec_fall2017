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

    def __init__(self, typ=5, che=0):
        super().__init__()
        self.Type = typ
        self.Checksum = che

    @classmethod
    def set_data(cls, seq, ack, dat):
        pkt = cls(5, 0)
        pkt.SequenceNumber = seq
        pkt.Acknowledgement = ack
        pkt.Data = dat
        pkt.Checksum = pkt.calculateChecksum()
        return pkt

    @classmethod
    def set_synack(cls, seq, ack):
        pkt = cls(1, 0)
        pkt.SequenceNumber = seq
        pkt.Acknowledgement = ack
        pkt.Checksum = pkt.calculateChecksum()
        return pkt

    @classmethod
    def set_syn(cls, seq):
        pkt = cls(0, 0)
        pkt.SequenceNumber = seq
        pkt.Checksum = pkt.calculateChecksum()
        return pkt

    @classmethod
    def set_ack(cls, ack):
        pkt = cls(2, 0)
        pkt.Acknowledgement = ack
        pkt.Checksum = pkt.calculateChecksum()
        return pkt

    @classmethod
    def set_rip(cls):
        pkt = cls(3, 0)
        pkt.Checksum = pkt.calculateChecksum()
        return pkt

    @classmethod
    def set_ripack(cls, ack):
        pkt = cls(4, 0)
        pkt.Acknowledgement = ack
        pkt.Checksum = pkt.calculateChecksum()
        return pkt

    def to_string(self):
        return "Type = " + self.get_type_string() + ". SEQ = " + str(self.SequenceNumber) \
               + ". ACK = " + str(self.Acknowledgement) + ". Checksum = " + str(self.Checksum)

    def calculateChecksum(self):
        oldChecksum = self.Checksum
        self.Checksum = 0
        bytes = self.__serialize__()
        self.Checksum = oldChecksum
        return zlib.adler32(bytes) & 0xffff
    
    def validate_checksum(self):
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

if __name__ == "__main__":
    packet = PEEPPacket.set_four(5, 1, 1)
    print(packet.SequenceNumber)
    print(packet.Acknowledgement)
