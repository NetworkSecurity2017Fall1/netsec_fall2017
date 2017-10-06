from playground.network.common import StackingTransport

class MyProtocolTransport(StackingTransport):
    def write(self, data):
    # this will be the data from the upper layer
        chunk_size = 1024
        counter = 0
        while( len(data) > 1024 ):
            pkt = Packets.PEEPPacket()
            pkt.Type = 6
            pkt.SequenceNumber = counter
            pkt.Acknowledgemen = 0
            pkt.Data = data[:chunk_size]
            pkt.Checksum = pkt.calculateChecksum()
            data = data[chunk_size:]
            counter = counter + 1
            self.transport.write(pkt_bytes)
#
#    # Create MyProtocolPackets
#    for each pkt in MyProtocolPackets:
#        self.lowerTransport().write(pkt.__serialize__())
