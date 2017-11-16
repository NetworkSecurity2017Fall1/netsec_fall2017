#!/usr/bin/env python3
# Network Security - Lab 2

from playground.network.packet import PacketType, FIELD_NOT_SET
from playground.network.packet.fieldtypes import UINT8, UINT16, UINT32, BUFFER
from playground.network.packet.fieldtypes.attributes import Optional
import random
from datetime import datetime
import zlib

TYPE_SYN = 0
TYPE_SYNACK = 1
TYPE_ACK = 2
TYPE_RIP = 3
TYPE_RIPACK = 4
TYPE_RST = 5
TYPE_DATA = 6

typeStrings = {TYPE_SYN:    "SYN",
               TYPE_SYNACK: "SYN-ACK",
               TYPE_ACK:    "ACK",
               TYPE_RIP:    "RIP",
               TYPE_RIPACK: "RIP-ACK",
               TYPE_RIP:    "RST",
               TYPE_DATA:   "DATA"}

class PEEPPacket(PacketType):
    """
    Players Enjoy Eavesdropping Protocol packet.
    """
    DEFINITION_IDENTIFIER = "PEEP.Packet"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("Type",            UINT8),
        ("SequenceNumber",  UINT32({Optional: True})),
        ("Checksum",        UINT16),
        ("Acknowledgement", UINT32({Optional: True})),
        ("Data",            BUFFER({Optional: True}))
    ]

    def calculateChecksum(self):
        oldChecksum = self.Checksum
        self.Checksum = 0
        bytes = self.__serialize__()
        self.Checksum = oldChecksum
        return zlib.adler32(bytes) & 0xffff

    def updateChecksum(self):
        self.Checksum = self.calculateChecksum()

    def verifyChecksum(self):
        return self.Checksum == self.calculateChecksum()

    def setType(self, type):
        self.Type = type

    def initSeqNum(self):
        random.seed(datetime.now())
        if self.SequenceNumber == FIELD_NOT_SET:
            # Random is seeded with datetime and random number
            # between 0 and 1,000,000 is created
            self.SequenceNumber = random.randint(0, 1000000)

    def setSeqNum(self, value):
        self.SequenceNumber = value

    def getStringType(self):
        return typeStrings[self.Type]

    def isType(self, type):
        return self.Type == type

    @classmethod
    def makeSyn(cls):
        synPacket = cls()
        synPacket.setType(TYPE_SYN)
        synPacket.initSeqNum()
        synPacket.updateChecksum()
        return synPacket

    @classmethod
    def makeSynAck(cls, synSeqNum):
        synAckPacket = cls()
        synAckPacket.setType(TYPE_SYNACK)
        synAckPacket.initSeqNum()
        synAckPacket.Acknowledgement = ((synSeqNum + 1) % (2 ** 32)) # TODO, make sure this is sound
        synAckPacket.updateChecksum()
        return synAckPacket

    @classmethod
    def makeAck(cls, ackNum):
        ackPacket = cls()
        ackPacket.setType(TYPE_ACK)
        ackPacket.Acknowledgement = ackNum
        ackPacket.updateChecksum()
        return ackPacket

    @classmethod
    def makeData(cls, seqNum, ackNum, data):
        dataPacket = cls()
        dataPacket.setType(TYPE_DATA)
        dataPacket.setSeqNum(seqNum) # TODO, Match makeSynAck's 2 ** 32 check?
        dataPacket.Acknowledgement = ackNum
        dataPacket.Data = data
        dataPacket.updateChecksum()
        return dataPacket

    @classmethod
    def makeRip(cls, seqNum):
        ripPacket = cls()
        ripPacket.setType(TYPE_RIP)
        ripPacket.setSeqNum(seqNum)
        ripPacket.updateChecksum()
        return ripPacket

    @classmethod
    def makeRipAck(cls, seqNum):
        ripAckPacket = cls()
        ripAckPacket.setType(TYPE_RIPACK)
        ripAckPacket.setSeqNum(seqNum)
        ripAckPacket.updateChecksum()
        return ripAckPacket

    """ Returns a string representation of the current packet """
    def __str__(self):
        return "(Type: {0}, SEQ: {1}, ACK: {2}, CSUM: {3})".format(
                 typeStrings[self.Type], self.SequenceNumber,
                 self.Acknowledgement, self.Checksum)
