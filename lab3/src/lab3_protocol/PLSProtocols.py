"""Protocols"""

import random, threading, time
from . import Transport
from . import ReliableTransmission
from .Packets import PLSPacket
from playground.network.packet import PacketType
from playground.network.common import StackingProtocol


class resendThread(threading.Thread):
    def __init__(self, threadID, name, func):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.func = func

    def run(self):
        print("Starting " + self.name)
        self.func()
        print("Exiting " + self.name)


class PLSProtocol(StackingProtocol):
    def __init__(self):
        self.deserializer = PLSPacket.Deserializer()
        self.state = 0
        self.counter = 5
        random.seed()
        self.nonce = random.randrange(0, 4294967295)
        self.valid_received = 0
        self.handshake_to_send = []
        self.ackReceived = []
        self.pktReceived = []
        super().__init__()

    def connection_lost(self, exc):
        print("PLS: Lost connection to client. Cleaning up.")
        if self.transport != None:
            self.transport.close()
        if self.higherProtocol():
            self.higherProtocol().connection_lost(None)

    def data_received(self, data):
        self.counter = 5
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            if isinstance(pkt, PLSPacket) and pkt.validate_checksum():
                print("PLS: Received PLS packet.", pkt.to_string())
                self.packet_processing(pkt)

    def packet_processing(self, pkt):
        if pkt.get_type_string() == "ClientHello" and self.state == 0:
            self.state = 1
            pkt_rsps = PLSPacket.set_serverhello(self.nonce)
            pkt_rsps_bytes = pkt_rsps.__serialize__()
            print("PLS: Sending PLS packet.", pkt_rsps.to_string())
            self.transport.write(pkt_rsps_bytes)
        elif pkt.get_type_string() == "ServerHello" and self.state == 1:
            self.state = 2
            pkt_rsps = PLSPacket.set_ack(pkt.SequenceNumber + 1)
            response_bytes = packet_response.__serialize__()
            self.expecting_receive = pkt.SequenceNumber + 1
            self.nonce = pkt.Acknowledgement
            print("PLS: Sending PLS packet.", packet_response.to_string())
            self.transport.write(response_bytes)
            print("PLS: Handshake is completed.")
            higher_transport = Transport.MyProtocolTransport(self.transport)
            higher_transport.seq_start(self.valid_sent)
            higher_transport.reset_all()
            self.higherProtocol().connection_made(higher_transport)




class PLSServerProtocol(PLSProtocol):

    def connection_made(self, transport):
        print("PLSServer: Received a connection from {}".format(transport.get_extra_info("peername")))
        self.transport = transport


class PLSClientProtocol(PLSProtocol):

    def connection_made(self, transport):
        print("PLSClient: Connection established with server")
        self.transport = transport
        self.handshake()

    def handshake(self):
        pkt = PLSPacket.set_clienthello(self.valid_sent)
        pkt_bytes = pkt.__serialize__()
        print("PLS: Starting handshake. Sending PLS packet.", pkt.to_string())
        self.transport.write(pkt_bytes)
        self.state = 1
