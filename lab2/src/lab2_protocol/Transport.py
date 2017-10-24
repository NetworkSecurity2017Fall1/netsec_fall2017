"""Transport"""

from playground.network.common import StackingTransport
from . import Packets


class MyProtocolTransport(StackingTransport):

    def reset_all(self):
        self.window_size = 5
        self.my_protocol_packets = []
        self.to_send = []
        self.expected_ack = []
        self.chunk_size = 1024

    def mvwindow(self, n):
        print("move window ", n)
        while n > 0 and len(self.my_protocol_packets.pop(0)) > 0:
            pkt = self.my_protocol_packets[0]
            self.to_send.pop(0)
            self.expected_ack.pop(0)
            self.to_send.append(pkt)
            self.expected_ack.append(pkt.SequenceNumber + len(pkt.Data))
            self.lowerTransport().write(self.my_protocol_packets[0].__serialize__())
            self.my_protocol_packets.pop(0)
            n-=1

    def close(self):
        pkt = Packets.PEEPPacket.set_rip(self.seq_sending)
        self.my_protocol_packets.append(pkt)

    def resend(self, index):
        assert(index < 5)
        self.lowerTransport().write(self.to_send[index].__serialize__())

    def seq_start(self, seq):
        self.seq_sending = seq

    def write(self, data):
        #self.my_protocol_packets = []
        #self.to_send = []
        #self.chunk_size = 1024
        # this will be the data from the upper layer
        while len(data) > 0:
            pkt = Packets.PEEPPacket()
            pkt.Type = 5
            pkt.SequenceNumber = self.seq_sending
            if len(data) > self.chunk_size:
                self.seq_sending += self.chunk_size
                pkt.Data = data[:self.chunk_size]
                data = data[self.chunk_size:]
            else:
                self.seq_sending += len(data)
                pkt.Data = data[:len(data)]
                data = data[len(data):]
            pkt.Checksum = pkt.calculateChecksum()
            self.my_protocol_packets.append(pkt)

        print("my protocol packets length: ", len(self.my_protocol_packets))
        while(len(self.to_send) < self.window_size and len(self.my_protocol_packets) != 0):
            pkt = self.my_protocol_packets[0]
            self.to_send.append(pkt)
            self.expected_ack.append(pkt.SequenceNumber + len(pkt.Data))
            self.my_protocol_packets.pop(0)

        # send all packets in to_send[]
        for pkt in self.to_send:
            print("Sending PEEP packet.", pkt.to_string())
            self.lowerTransport().write(pkt.__serialize__())
        
