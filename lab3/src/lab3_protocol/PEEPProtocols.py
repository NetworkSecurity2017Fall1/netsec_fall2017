"""Protocols"""

import random, threading, time
from .PEEPTransport import MyProtocolTransport
from .PEEPPackets import PEEPPacket
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


class PEEPProtocol(StackingProtocol):
    def __init__(self):
        self.deserializer = PEEPPacket.Deserializer()
        self.state = 0
        self.counter = 5
        random.seed()
        self.valid_sent = random.randrange(0, 4294967295)
        self.valid_received = 0
        self.handshake_to_send = []
        self.ackReceived = []
        self.pktReceived = []
        super().__init__()

    def handshake_resend(self):
        while self.state == 1:
            # print("self.counter: ", self.counter)
            if self.counter <= 0:
                # print("It has been a while, restart handshake")
                # print("length of to_send: ", len(self.handshake_to_send))
                assert(len(self.handshake_to_send) == 1)
                self.transport.write(self.handshake_to_send[0].__serialize__())
                # print("PEEP: Sending PEEP packet.", self.handshake_to_send[0].to_string())
                self.counter = 0.3
            else:
                self.counter = self.counter - 0.1
            time.sleep(0.1)

    def sortPacketBySeqNum(self):
        self.pktReceived.sort(key=lambda pkt: pkt.SequenceNumber, reverse=False)

    def addAck2Queue(self, ack):
        if ack in self.higherProtocol().transport.expected_ack:
            self.ackReceived.append(ack)

    def ack_shift(self, packet):
        exp_ack = self.higherProtocol().transport.expected_ack
        if len(exp_ack) < 1:
            return 0
        shift = -1
        while(shift + 1 < len(exp_ack) and packet.Acknowledgement >= exp_ack[shift+1]):
            shift = shift + 1
        if shift != -1:
            self.valid_sent = packet.Acknowledgement
        return shift+1


    def connection_lost(self, exc):
        #print("PEEP: Lost connection to client. Cleaning up.")
        if self.transport != None:
            self.transport.close()
        if self.higherProtocol():
            self.higherProtocol().connection_lost(None)

    def data_received(self, data):
        self.counter = 5
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            if isinstance(pkt, PEEPPacket) and pkt.validate_checksum():
                # print("PEEP: Received PEEP packet.", pkt.to_string())
                # print("PEEP: Received PEEP packet.", pkt.get_type_string())
                # print("check: ", pkt.get_type_string() == "DATA" and self.state == 2)
                # print("check: ", pkt.get_type_string() == "DATA")
                # print("check: ", self.state)
                self.packet_processing(pkt)

    def packet_processing(self, pkt):
        if pkt.Type == 0 and self.state == 0:
            self.state = 1
            self.valid_received = pkt.SequenceNumber + 1
            packet_response = PEEPPacket.set_synack(self.valid_sent, pkt.SequenceNumber + 1)
            packet_response_bytes = packet_response.__serialize__()
            self.valid_sent = self.valid_sent + 1
            #print("PEEP: Sending PEEP packet.", packet_response.to_string())
            self.transport.write(packet_response_bytes)
            self.handshake_to_send.append(packet_response)
            thread1 = resendThread(1, "handshakeresendThread", self.handshake_resend)
            thread1.start()
        elif pkt.Type == 1 and self.state == 1:
            self.valid_received = pkt.SequenceNumber + 1
            packet_response = PEEPPacket.set_ack(pkt.SequenceNumber + 1)
            response_bytes = packet_response.__serialize__()
            self.expecting_receive = pkt.SequenceNumber + 1
            self.valid_sent = pkt.Acknowledgement
            #print("PEEP: Sending PEEP packet.", packet_response.to_string())
            self.transport.write(response_bytes)
            self.state = 2
            # Only when handshake is completed should we call higher protocol's connection_made
            # print("PEEP: Handshake is completed.")
            higher_transport = MyProtocolTransport(self.transport)
            higher_transport.seq_start(self.valid_sent)
            higher_transport.reset_all()
            self.higherProtocol().connection_made(higher_transport)

        elif pkt.Type == 2 and self.state == 1:
            self.state = 2
            # Only when handshake is completed should we call higher protocol's connection_made
            # print("PEEP: Handshake is completed.")
            self.ackReceived.append(pkt.Acknowledgement)
            higher_transport = MyProtocolTransport(self.transport)
            higher_transport.seq_start(self.valid_sent)
            higher_transport.reset_all()
            self.higherProtocol().connection_made(higher_transport)
        elif pkt.Type == 5 and self.state == 2:
            # print("incoming seq: ", pkt.SequenceNumber, "current valid received: ", self.valid_received)
            # print("data length : ", len(pkt.Data))
            if pkt.SequenceNumber == self.valid_received:
                assert(pkt.SequenceNumber == self.valid_received)
                self.valid_received = self.valid_received + len(pkt.Data)
                self.higherProtocol().data_received(pkt.Data)
                # print("PEEP: Data is passed up")
                while(len(self.pktReceived) > 0 and self.pktReceived[0].SequenceNumber <= self.valid_received):
                    if self.pktReceived[0].SequenceNumber < self.valid_received:
                        self.pktReceived.pop(0)
                    else:
                        self.valid_received = self.valid_received + len(self.pktReceived[0].Data)
                        self.higherProtocol().data_received(self.pktReceived[0].Data)
                        self.pktReceived.pop(0)
                        # print("PEEP: Data is passed up")
                # print("updated valid received: ", self.valid_received)
                packet_response = PEEPPacket.set_ack(self.valid_received)
                packet_response_bytes = packet_response.__serialize__()
                self.transport.write(packet_response_bytes)
                # print("PEEP: Sending PEEP packet.", packet_response.to_string())
            elif pkt.SequenceNumber > self.valid_received:
                self.pktReceived.append(pkt)
                self.sortPacketBySeqNum()
            else:
                packet_response = PEEPPacket.set_ack(self.valid_received)
                packet_response_bytes = packet_response.__serialize__()
                self.transport.write(packet_response_bytes)
                # print("PEEP: Sending PEEP packet.", packet_response.to_string())

        elif pkt.Type == 2 and self.state == 2:
            self.addAck2Queue(pkt.Acknowledgement)
            # print("Expected Acknowledgement: ", self.higherProtocol().transport.expected_ack)
            # print("Shift: ", self.ack_shift(pkt))
            self.higherProtocol().transport.mvwindow(self.ack_shift(pkt))

        elif pkt.Type == 3:
            #print(pkt.SequenceNumber, self.valid_received)
            if pkt.SequenceNumber == self.valid_received:
                # print("  Receive a RIP")
                packet_response = PEEPPacket.set_ripack(pkt.SequenceNumber + 1)
                # print("    Receive a RIP line 1")
                packet_response_bytes = packet_response.__serialize__()
                # print("    Receive a RIP line 2")
                if self.transport != None:
                    self.transport.write(packet_response_bytes)
                #print("    Receive a valid RIP ")
                self.state = 5

        elif pkt.Type == 4:
            #print("It's RIP-ACK!!!")
            #print("Expected Acknowledgement: ", self.higherProtocol().transport.expected_ack)
            #print("Shift: ", self.ack_shift(pkt))
            self.higherProtocol().transport.mvwindow(self.ack_shift(pkt))
            self.transport.close()

class PEEPServerProtocol(PEEPProtocol):

    def connection_made(self, transport):
        # print("PEEPServer: Received a connection from {}".format(transport.get_extra_info("peername")))
        self.transport = transport



class PEEPClientProtocol(PEEPProtocol):

    def connection_made(self, transport):
        # print("PEEPClient: Connection established with server")
        self.transport = transport
        self.handshake()



    def handshake(self):
        packet_response = PEEPPacket.set_syn(self.valid_sent)
        response_bytes = packet_response.__serialize__()
        # print("PEEP: Starting handshake. Sending PEEP packet.", packet_response.to_string())
        self.transport.write(response_bytes)
        self.state = 1
        self.handshake_to_send.append(packet_response)
        thread1 = resendThread(1, "handshakeresendThread", self.handshake_resend)
        thread1.start()
