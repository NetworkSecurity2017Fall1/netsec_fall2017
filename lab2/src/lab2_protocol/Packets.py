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

    def to_string(self):
        seq_num = self.SequenceNumber
        if seq_num == self.UNSET:
            seq_num = "-"

        ack_num = self.Acknowledgement
        if ack_num == self.UNSET:
            ack_num = "-"

        data_len = self.dataoffset()
        return "(): SEQ({}), ACK({}), Checksum({}), Data Length({})".format(self.packetType(), seq_num, ack_num,
                                                                            self.Checksum, data_len)
    
    def calculateChecksum(self):
        old_checksum = self.Checksum
        self.Checksum = 0
        bytes = self.__serialize__()
        self.Checksum = old_checksum
        return zlib.adler32(bytes) & 0xffff
    
    def updateChecksum(self):
        self.Checksum = self.calculateChecksum()
    
    def verifyChecksum(self):
        return self.Checksum == self.calculateChecksum()


# PEEP Protocol Types
# -------------------
# SYN -      TYPE 0
# SYN-ACK -  TYPE 1
# ACK -      TYPE 2
# RIP -      TYPE 3
# RIP-ACK -  TYPE 4
# DATA -     TYPE 5
