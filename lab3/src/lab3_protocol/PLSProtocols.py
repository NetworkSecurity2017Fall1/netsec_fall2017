"""Protocols"""

import random, threading, time
from . import Transport
from .Packets import PlsHello, PlsKeyExchange, PlsHandshakeDone, PlsData, PlsClose, PacketType
from playground.network.common import StackingProtocol


class PLSProtocol(StackingProtocol):
    def __init__(self):
        self.deserializer = PacketType.Deserializer()
        self.state = 0
        self.counter = 5
        random.seed()
        self.nonce = random.randrange(0, 4294967295) # Now it's 2^32, and it should be 2^64
        self.cert = []
        self.PreKey = b"HelloSky"
        self.hash = b"HelloSea"
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
            print("PLS: Received PLS packet.", pkt.to_string())
            self.packet_processing(pkt)

    def packet_processing(self, pkt):
        if type(pkt) is PlsHello:
            if  self.state == 0:
                self.state = 1
                pkt_rsps = PlsHello(self.nonce, self.cert)
            elif self.state == 1:
                self.state = 2
                pkt_rsps = PlsKeyExchange(self.PreKey, pkt.Nonce + 1)
            else:
                return
            pkt_rsps_bytes = pkt_rsps.__serialize__()
            self.transport.write(pkt_rsps_bytes)
        elif type(pkt) is PlsKeyExchange:
            if  self.state == 1:
                self.state = 2
                pkt_rsps = PlsKeyExchange(self.PreKey, pkt.Nonce + 1)
            elif self.state == 2:
                self.state = 3
                pkt_rsps = PlsHandshakeDone(self.hash)
            else:
                return
            pkt_rsps_bytes = pkt_rsps.__serialize__()
            self.transport.write(pkt_rsps_bytes)
        elif type(pkt) is PlsHandshakeDone:
            if  self.state == 2:
                self.state = 3
                pkt_rsps = PlsHandshakeDone(self.hash)
                pkt_rsps_bytes = pkt_rsps.__serialize__()
                self.transport.write(pkt_rsps_bytes)
            elif self.state == 3:
                self.state = 4
            else:
                return


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
        pkt = PlsHello(self.nonce, self.cert)
        pkt_bytes = pkt.__serialize__()
        print("PLS: Starting handshake")
        self.transport.write(pkt_bytes)
        self.state = 1
