"""ReliableTransmission"""

from Packets import PEEPPacket
import random


class AckValidate:
    def __init__(self, seq):
        self.pktReceived = []
        self.WindowSize = 5
        self.next = seq

    def addPackets2Queue(self, packet):
        shift = 0
        if packet.SequenceNumber in range(self.next, self.next + self.WindowSize):
            self.pktReceived.append(packet)
            self.sortPacketBySeqNum()
        while self.pktReceived and self.pktReceived[0].SequenceNumber == self.next:
            self.next += 1
            shift += 1
            self.pktReceived.pop(0)

        return shift


    def sortPacketBySeqNum(self):
        self.pktReceived.sort(key=lambda pkt: pkt.SequenceNumber, reverse=False)
        # return self.pktReceived


class SendAck:

    def __init__(self, seq):
        #self.time_limit = 0.5
        self.WindowSize = 5
        self.pktReceived = []
        self.next = seq


    def addPackets2Queue(self, packet):
        if packet.SequenceNumber in range(self.next, self.next + self.WindowSize):
            self.pktReceived.append(packet)


    def sortPacketBySeqNum(self):
        self.pktReceived.sort(key=lambda pkt: pkt.SequenceNumber, reverse=False)

    def updateAck(self):
        self.sortPacketBySeqNum()
        while self.pktReceived and self.pktReceived[0].SequenceNumber == self.next:
            self.next += 1
            self.pktReceived.pop(0)

        return self.next



if __name__ == "__main__":
    #reliableTransmission = AckValidate(1)
    reliableTransmission = SendAck(1)
    test_list = [1,2,4,5,1,3]
    for i in range(0, len(test_list)):
        pkt = PEEPPacket()
        pkt.Type = 1
        # pkt.SequenceNumber = random.randint(0,10)
        pkt.SequenceNumber = test_list[i]
        pkt.Acknowledgement = 1
        pkt.Checksum = pkt.calculateChecksum()
        #result =
        reliableTransmission.addPackets2Queue(pkt)
        result = reliableTransmission.updateAck()
        print(reliableTransmission.pktReceived)
        print(result)
    #print([pkt.SequenceNumber for pkt in reliableTransmission.sortPacketBySeqNum()])
