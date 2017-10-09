"""Transport"""

from playground.network.common import StackingTransport
from . import Packets


class MyProtocolTransport(StackingTransport):
    def write(self, data):
    # this will be the data from the upper layer
        chunk_size = 1024
        counter = 0
        MyProtocolPackets = []
        while( len(data) > 0 ):
            pkt = Packets.PEEPPacket()
            pkt.Type = 6
            pkt.SequenceNumber = counter
            pkt.Acknowledgemen = 0
            if( len(data) > chunk_size ):
                pkt.Data = data[:chunk_size]
                data = data[chunk_size:]
            else:
                pkt.Data = data[:len(data)]
                data = data[len(data):]
            pkt.Checksum = pkt.calculateChecksum()
            counter = counter + 1
            MyProtocolPackets.append(pkt)

        # Create MyProtocolPackets
        for pkt in MyProtocolPackets:
            self.lowerTransport().write(pkt.__serialize__())
