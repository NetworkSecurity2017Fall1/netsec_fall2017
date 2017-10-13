"""Transport"""

from playground.network.common import StackingTransport
from . import Packets


class MyProtocolTransport(StackingTransport):

    def seq_start(self, seq):
        self.seq_start = seq

    def write(self, data):
        # this will be the data from the upper layer
        chunk_size = 1024
        my_protocol_packets = []
        while len(data) > 0:
            pkt = Packets.PEEPPacket()
            pkt.Type = 5
            pkt.SequenceNumber = self.seq_start
            if len(data) > chunk_size:
                self.seq_start += chunk_size
                pkt.Data = data[:chunk_size]
                data = data[chunk_size:]
            else:
                self.seq_start += len(data)
                pkt.Data = data[:len(data)]
                data = data[len(data):]
            pkt.Checksum = pkt.calculateChecksum()
            my_protocol_packets.append(pkt)

        # Create MyProtocolPackets
        for pkt in my_protocol_packets:
            print("Sending PEEP packet.", pkt.to_string())
            self.lowerTransport().write(pkt.__serialize__())