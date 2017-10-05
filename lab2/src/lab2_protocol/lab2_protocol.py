"""Client"""
import asyncio
import sys, time, os, logging
from . import Packets
from playground import getConnector
from playground.network.packet import PacketType
from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory
from playground import Connector, setConnector

class PEEPServerProtocol(StackingProtocol):
    def __init__(self):
        self.deserializer = PacketType.Deserializer()
        self.state = 0
        super().__init__()

    def connection_made(self, transport):
        print("Server: Received a connection from {}".format(transport.get_extra_info("peername")))
        self.transport = transport

    def data_received(self, data):
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            print("Server: Received PEEPPacket from client. Type = ", pkt.Type)
            if pkt.Type == 0 and self.state == 0:
                self.state = 1
                packet_response = Packets.PEEPPacket()
                packet_response.Type = 1
                packet_response.SequenceNumber = 1
                packet_response.Acknowledgement = pkt.SequenceNumber + 1
                packet_response.Checksum = packet_response.calculateChecksum()
                packet_response_bytes = packet_response.__serialize__()
                self.transport.write(packet_response_bytes)
            elif pkt.Type == 2 and self.state == 1:
                self.state = 2
                # Only when handshake is completed should we call higher protocol's connection_made
                print("Server: Handshake is completed.")
                higher_transport = StackingTransport(self.transport)
                self.higherProtocol().connection_made(higher_transport)
            elif self.state == 2:
                # Only when handshake is completed should we call higher protocol's data_received
                print("Server: Data passes up PEEPServerProtocol.")
                self.higherProtocol().data_received(data)
            else:
                self.state = 0
                self.transport = None
                break

    def connection_lost(self, exc):
        print("Server: Lost connection to client. Cleaning up.")
        self.transport = None
        self.higherProtocol().connection_lost()





class PEEPClientProtocol(StackingProtocol):
    def __init__(self):
        self.deserializer = PacketType.Deserializer()
        self.state = 0
        super().__init__()

    def connection_made(self, transport):
        print("Client: Connection Established With Server")
        self.transport = transport
        self.handshake()

    def data_received(self, data):
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            if isinstance(pkt, Packets.PEEPPacket):
                # print(pkt.to_string())
                print("Client: Received PEEPPacket From Server. Type = ", pkt.Type)
                if pkt.Type == 1 and self.state == 0:
                    response = Packets.PEEPPacket()
                    response.Type = 2
                    response.Acknowledgement = pkt.SequenceNumber + 1
                    response.SequenceNumber = pkt.Acknowledgement
                    response.Checksum = response.calculateChecksum()
                    response_bytes = response.__serialize__()
                    self.transport.write(response_bytes)
                    self.state = 2
                    # Only when handshake is completed should we call higher protocol's connection_made
                    print("Client: Handshake is completed.")
                    higher_transport = StackingTransport(self.transport)
                    self.higherProtocol().connection_made(higher_transport)
                elif self.state == 2:
                    # Only when handshake is completed should we call higher protocol's data_received
                    print("Client: Data passes up PEEPClientProtocol.")
                    self.higherProtocol().data_received(data)
                else:
                    self.transport = None
                    break
            else:
                self.transport = None
                break

    def connection_lost(self, exc):
        print("Client: Connection Lost in PEEPClientProtocol")
        self.transport = None
        self.higherProtocol().connection_lost()

    def handshake(self):
        response = Packets.PEEPPacket()
        response.Type = 0
        response.SequenceNumber = 0
        response.Checksum = response.calculateChecksum()
        print("Client: checksum =", response.Checksum)
        # print(response.to_string())
        response_bytes = response.__serialize__()
        print("Client: Starting handshake. Sending first packet. Type = 0")
        self.transport.write(response_bytes)

def lab2ClientFactory():
    return StackingProtocolFactory(lambda: PEEPClient.PassThroughLayer1(), lambda: PEEPClientProtocol())

def lab2ServerFactory():
    return StackingProtocolFactory(lambda: PEEPServer.PassThroughLayer1(), lambda: PEEPServerProtocol())



