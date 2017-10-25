"""Protocols"""

import random, threading, time
from . import Transport
from . import ReliableTransmission
from .Packets import PEEPPacket
from playground.network.packet import PacketType
from playground.network.common import StackingProtocol


# class resendThread(threading.Thread):
#     def __init__(self, threadID, name, func):
#         threading.Thread.__init__(self)
#         self.threadID = threadID
#         self.name = name
#         self.func = func
#
#     def run(self):
#         print("Starting " + self.name)
#         self.func()
#         print("Exiting " + self.name)


# class terminationThread(threading.Thread):
#     def __init__(self, threadID, name, func):
#         threading.Thread.__init__(self)
#         self.threadID = threadID
#         self.counter = 5
#         self.name = name
#         self.func = func
#
#     def run(self):
#         print("Starting " + self.name)
#         self.func()
#         print("Exiting " + self.name)


class PEEPProtocol(StackingProtocol):
    def __init__(self):
        self.deserializer = PEEPPacket.Deserializer()
        self.state = 0
        self.counter = 5
        random.seed()
        self.valid_sent = random.randrange(0, 4294967295)
        self.valid_received = 0

        #self.thread2 = terminationThread(1, "terminationThread", self.termination)
        self.ackReceived = []
        self.pktReceived = []
        super().__init__()

    def termination(self):
        while self.counter:
            print("Session ends in ", self.counter, " sec.")
            self.counter = self.counter - 1
            time.sleep(1)
        self.state = 5

    # def resend(self):
    #     while self.higherProtocol().transport:
    #         expected = self.higherProtocol().transport.expected_ack
    #         print("Resend checking")
    #         for i in range(0, len(expected)):
    #             if expected[i] not in self.ackReceived:
    #                 print("Reliable Transmission resending ACK#: ", i)
    #                 self.higherProtocol().transport.resend(i)
    #
    #         time.sleep(1)

    def sortPacketBySeqNum(self):
        self.pktReceived.sort(key=lambda pkt: pkt.Acknowledgement, reverse=False)

    def addAck2Queue(self, ack):
        if ack in self.higherProtocol().transport.expected_ack:
            self.ackReceived.append(ack)

    def addPackets2Queue(self, packet):
        shift = -1
        for i in range(0, 5):
            shift = i
            if(packet.Acknowledgement == self.higherProtocol().transport.expected_ack[i]):
                break
        if shift != -1:
            self.valid_sent = packet.Acknowledgement

        return shift+1


    def connection_lost(self, exc):
        print("PEEP: Lost connection to client. Cleaning up.")
        if self.transport:
            self.transport.close()
        if self.higherProtocol():
            self.higherProtocol().connection_lost(None)

    def data_received(self, data):
        self.counter = 5
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            if isinstance(pkt, PEEPPacket) and pkt.validate_checksum():
                print("PEEP: Received PEEP packet.", pkt.to_string())
                self.packet_processing(pkt)

    def packet_processing(self, pkt):
        if pkt.get_type_string() == "SYN" and self.state == 0:
            self.state = 1
            self.valid_received = pkt.SequenceNumber + 1
            packet_response = PEEPPacket.set_synack(self.valid_sent, pkt.SequenceNumber + 1)
            packet_response_bytes = packet_response.__serialize__()
            self.valid_sent = self.valid_sent + 1
            print("PEEP: Sending PEEP packet.", packet_response.to_string())
            self.transport.write(packet_response_bytes)
        elif pkt.get_type_string() == "SYN-ACK" and self.state == 1:
            self.valid_received = pkt.SequenceNumber + 1
            packet_response = PEEPPacket.set_ack(pkt.SequenceNumber + 1)
            response_bytes = packet_response.__serialize__()
            self.expecting_receive = pkt.SequenceNumber + 1
            self.valid_sent = pkt.Acknowledgement
            print("PEEP: Sending PEEP packet.", packet_response.to_string())
            self.transport.write(response_bytes)
            self.state = 2
            # Only when handshake is completed should we call higher protocol's connection_made
            print("PEEP: Handshake is completed.")
            higher_transport = Transport.MyProtocolTransport(self.transport)
            higher_transport.seq_start(self.valid_sent)
            higher_transport.reset_all()
            self.higherProtocol().connection_made(higher_transport)

        elif pkt.get_type_string() == "ACK" and self.state == 1:
            self.state = 2
            # Only when handshake is completed should we call higher protocol's connection_made
            print("PEEP: Handshake is completed.")
            self.ackReceived.append(pkt.Acknowledgement)
            higher_transport = Transport.MyProtocolTransport(self.transport)
            higher_transport.seq_start(self.valid_sent)
            higher_transport.reset_all()
            self.higherProtocol().connection_made(higher_transport)
        elif pkt.get_type_string() == "DATA" and self.state == 2:
            print(pkt.SequenceNumber, self.valid_received)
            print("data length : " ,  len(pkt.Data))
            assert(pkt.SequenceNumber == self.valid_received)
            if pkt.SequenceNumber == self.valid_received:
                self.valid_received = self.valid_received + len(pkt.Data)
                print("PEEP: Data passes up PEEPServerProtocol.")
                self.higherProtocol().data_received(pkt.Data)
            packet_response = PEEPPacket.set_ack(self.valid_received)
            packet_response_bytes = packet_response.__serialize__()
            print("PEEP: Sending PEEP packet.", packet_response.to_string())
            self.transport.write(packet_response_bytes)

        elif pkt.get_type_string() == "ACK" and self.state == 2:
            self.addAck2Queue(pkt.SequenceNumber)
            print("Expected Acknowledgement: ", self.higherProtocol().transport.expected_ack)
            print("Shift: ", self.addPackets2Queue(pkt))
            self.higherProtocol().transport.mvwindow(self.addPackets2Queue(pkt))

        elif pkt.get_type_string() == "RIP":
            print(pkt.SequenceNumber, self.valid_received)
            if pkt.SequenceNumber == self.valid_received:
                # print("  Receive a RIP")
                packet_response = PEEPPacket.set_ripack(pkt.SequenceNumber + 1)
                # print("    Receive a RIP line 1")
                packet_response_bytes = packet_response.__serialize__()
                # print("    Receive a RIP line 2")
                if self.transport != None:
                    self.transport.write(packet_response_bytes)
                    #self.transport.close()
                #self.connection_lost(None)
                print("    Receive a RIP line 3")
                self.state = 5
        else:
            print("Enter else in packet processing")
            self.state = 5
            if self.transport:
                self.transport.close()
            #self.connection_lost(None)

class PEEPServerProtocol(PEEPProtocol):

    def connection_made(self, transport):
        print("PEEPServer: Received a connection from {}".format(transport.get_extra_info("peername")))
        self.transport = transport



class PEEPClientProtocol(PEEPProtocol):

    def connection_made(self, transport):
        print("PEEPClient: Connection established with server")
        self.transport = transport
        self.handshake()



    def handshake(self):
        packet_response = PEEPPacket.set_syn(self.valid_sent)
        response_bytes = packet_response.__serialize__()
        print("PEEP: Starting handshake. Sending PEEP packet.", packet_response.to_string())
        self.transport.write(response_bytes)
        self.state = 1
