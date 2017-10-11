"""ReliableTransmission"""

from .Packets import PEEPPacket
import random


class ReliableTransmission:
    def __init__(self, seq):
        self.pktReceived = []
        self.WindowSize = 5
        self.curr = 0
        self.next = seq

    # def slidingWindowExamine(self):
    #     if self.pktReceived[self.curr].SequenceNumber - self.pktReceived[self.curr + 5].SequenceNumber == self.WindowSize-1:
    #         return 0, self.pktReceived
    #     else:
    #         missingNumber = []
    #         seqNum = self.pktReceived[0].SequenceNumber
    #         for pkt in self.pktReceived:
    #             if seqNum != pkt.SequenceNumber:
    #                 missingNumber.append(seqNum)
    #             seqNum += 1
    #         return 2, missingNumber

    def addPackets2Queue(self, packet):
        self.pktReceived.append(packet)
        self.sortPacketBySeqNum()
        if packet.SequenceNumber == self.next:
            return True


    def sortPacketBySeqNum(self):
        self.pktReceived.sort(key=lambda pkt: pkt.SequenceNumber, reverse=False)
        return self.pktReceived


if __name__ == "__main__":
    reliableTransmission = ReliableTransmission()
    for i in range(0,5):
        pkt = PEEPPacket()
        pkt.Type = 1
        pkt.SequenceNumber = random.randint(0,10)
        #pkt.SequenceNumber = i
        pkt.Acknowledgement = 1
        pkt.Checksum = pkt.calculateChecksum()
        state, result = reliableTransmission.addPackets2Queue(pkt)
        print(state, result)
    print([pkt.SequenceNumber for pkt in reliableTransmission.sortPacketBySeqNum()])
