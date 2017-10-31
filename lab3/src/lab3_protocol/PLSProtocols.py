"""Protocols"""

import random, threading, time
from . import Transport
from .Packets import PLSPacket
from playground.network.common import StackingProtocol


class PLSProtocol(StackingProtocol):
    def __init__(self):
        self.deserializer = PLSPacket.Deserializer()
        self.state = 0
        self.counter = 5
        random.seed()
        self.nonce = random.randrange(0, 4294967295)
        super().__init__()

    def connection_lost(self, exc):
        print("PLS: Lost connection to client. Cleaning up.")
        if self.transport is not None:
            self.transport.close()
        if self.higherProtocol():
            self.higherProtocol().connection_lost(None)

    def data_received(self, data):
        self.counter = 5
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            if isinstance(pkt, PLSPacket):
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
            pkt_rsps = PLSPacket.set_serverhello(self.nonce)
            rsps_bytes = pkt_rsps.__serialize__()
            print("PLS: Sending PLS packet.", pkt_rsps.to_string())
            self.transport.write(rsps_bytes)


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
        pkt = PLSPacket.set_clienthello(self.nonce)
        pkt_bytes = pkt.__serialize__()
        print("PLS: Starting handshake. Sending PLS packet.", pkt.to_string())
        self.transport.write(pkt_bytes)
        self.state = 1
