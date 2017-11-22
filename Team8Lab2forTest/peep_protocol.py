#!/usr/bin/env python3
# Network Security - Lab 2

from playground.network.common import StackingProtocol, StackingTransport
from playground.network.packet import PacketType, FIELD_NOT_SET
from .peep_packet import PEEPPacket
from .peep_packet import TYPE_SYN, TYPE_ACK, TYPE_SYNACK, TYPE_DATA, TYPE_RIP, TYPE_RIPACK, TYPE_RST, typeStrings

from playground.common import logging as p_logging
import asyncio
p_logging.EnablePresetLogging(p_logging.PRESET_TEST)

STATE_IDLE = 0
STATE_OPENING = 1
STATE_TRANSMIT = 2
STATE_CLOSING = 3

MAX_DATA_CHUNK = 1024 # Bytes
#MAX_DATA_CHUNK = 2

""" ------------ PEEP Base Class ------------ """

class PEEPBase(StackingProtocol):

    """ Playground Protocol Functions """
    TIMEOUT = 0.1
    DATA_TIMEOUT = 5

    def __init__(self):
        # Playground
        super().__init__()
        self.deserializer =  PEEPPacket.Deserializer()

        # PEEP
        self.state = STATE_IDLE
        self.snd_una = None  # sent unack
        self.nxt_snd = None  # nxt byte we want to send
        self.nxt_rcv = None  # next byte we want to receive
        self.timer = None    # timer for timeouts
        self.good_data_timer = None # timer for duration since we received good packets

    def connection_made(self, transport):
        self.transport = transport
        self.forHigherTransport = PEEPStackingTransport(transport, self)

    def connection_lost(self, exc):
        if self.higherProtocol().transport is not None:
            self.higherProtocol().connection_lost(exc)
        self.transport = None

    """ PEEP Functions """

    def handleRcvData(self, dataPacket):
        if not dataPacket.verifyChecksum():
            print("Data packet failed checksum")
            return
        # Update snd_una
        if self.snd_una + 1 < dataPacket.Acknowledgement:
            self.snd_una = dataPacket.Acknowledgement - 1
        # Is this the next message we want?
        if (dataPacket.SequenceNumber - len(dataPacket.Data)) + 1 < self.nxt_rcv:
            print("incorrect sequence number")
            # ack the previous packet anyways
            self.sendAck(dataPacket.SequenceNumber + len(dataPacket.Data))
            return
        elif (dataPacket.SequenceNumber - len(dataPacket.Data)) + 1 == self.nxt_rcv:
            self.nxt_rcv += len(dataPacket.Data)
            self.sendAck(dataPacket.SequenceNumber + len(dataPacket.Data))
            print("we are sending back up")
            self.higherProtocol().data_received(dataPacket.Data)
        else:
            print("sequence number too big")

    def sendAck(self, ackNum):
        if self.state == STATE_TRANSMIT:
            print("SENDING ACK")
            ackPacket = PEEPPacket.makeAck(ackNum)
            ackPacket.updateChecksum()
            self.state = STATE_TRANSMIT
            self.transport.write(ackPacket.__serialize__())

    def validAck(self, packet):
        if not packet.verifyChecksum():
            return False
        print("ACK RECEIVED for ack " + str(packet.Acknowledgement))
        # if self.snd_una == packet.Acknowledgement:
        #     self.transport.send_buf.pop(0)
        expectedAck = -1
        if len(self.forHigherTransport.send_buf) > 0:
            if self.forHigherTransport.send_buf[0].Data == FIELD_NOT_SET:
                expectedAck = self.forHigherTransport.send_buf[0].SequenceNumber + 1
            else:
                expectedAck = self.forHigherTransport.send_buf[0].SequenceNumber + len(self.forHigherTransport.send_buf[0].Data)
        while (len(self.forHigherTransport.send_buf) > 0) and expectedAck <= packet.Acknowledgement:
            self.update_data_timeout()
            if self.timer is not None:
                self.timer.cancel()
            self.forHigherTransport.send_buf.pop(0)
            return True
        return False


    def sendRip(self, seqNum):
        print("send RIP")
        ripPacket = PEEPPacket.makeRip(seqNum)
        ripPacket.updateChecksum()
        self.transport.write(ripPacket.__serialize__())

    def sendRipAck(self, seqNum):
        print("send RIP-ACK")
        ripPacket = PEEPPacket.makeRipAck(seqNum)
        ripPacket.updateChecksum()
        self.transport.write(ripPacket.__serialize__())

    def writeDown(self):
        print("Entered write down")
        print("State is " + str(self.state))
        if len(self.forHigherTransport.send_buf) > 0:
            print("Sending first packet in queue")
            if self.timer is not None:
                self.timer.cancel()
            self.timer = asyncio.get_event_loop().call_later(self.TIMEOUT, self.timeout)
            self.transport.write(self.forHigherTransport.send_buf[0].__serialize__())
        elif len(self.forHigherTransport.send_buf)==0 and self.state==STATE_CLOSING:
            print("No more packets in queue, sending rip")
            self.sendRip(self.nxt_snd)
            self.transport.close()
            # self.connection_lost(None)

    def timeout(self):
        print("Timeout hit")
        self.writeDown()

    def data_timeout(self):
        print("DATA TIMEOUT")
        ripPacket = PEEPPacket.makeRip(0)
        ripPacket.updateChecksum()
        self.transport.write(ripPacket.__serialize__())
        self.transport.close()

    def update_data_timeout(self):
        if self.good_data_timer is not None:
            self.good_data_timer.cancel()
        self.good_data_timer = asyncio.get_event_loop().call_later(self.DATA_TIMEOUT, self.data_timeout)

""" ------------ PEEP Client ------------ """

class PEEPClient(PEEPBase):

    """ Playground Protocol Functions """

    def __init__(self):
        print("PEEP CLIENT INIT")
        super().__init__()

    def connection_made(self, transport):
        print("PEEP CLIENT CONNECTION MADE")
        self.update_data_timeout()
        super().connection_made(transport)
        self._sendSynHandshake()

    def data_received(self, data):
        self.deserializer.update(data)

        for packet in self.deserializer.nextPackets():
            if isinstance(packet, PEEPPacket) and packet.verifyChecksum():
                if packet.isType(TYPE_SYNACK) and (self.state == STATE_OPENING):
                    print("CLIENT RECIEVED SYNACK")
                    if self._validSynAckHandshake(packet):
                        self.update_data_timeout()
                        if self.timer is not None:
                            self.timer.cancel()
                        self.state = STATE_TRANSMIT
                        if len(self.forHigherTransport.send_buf) > 0 and self.forHigherTransport.send_buf[0].isType(TYPE_SYN):
                            self.forHigherTransport.send_buf.pop(0)
                            self.nxt_rcv = packet.SequenceNumber + 1
                            self.snd_una = packet.Acknowledgement
                            self.sendAck(self.nxt_rcv)
                            self.nxt_snd += 1
                            self.higherProtocol().connection_made(self.forHigherTransport)
                        else:
                            self.sendAck(self.nxt_rcv)
                    else:
                        print("CLIENT BAD SYNACK")
                        self.connection_lost(None)
                elif packet.isType(TYPE_SYNACK) and (self.state != STATE_OPENING):
                    self.update_data_timeout()
                    self.sendAck(self.nxt_rcv)
                elif packet.isType(TYPE_DATA) and (self.state == STATE_TRANSMIT):
                    self.update_data_timeout()
                    self.handleRcvData(packet)
                elif packet.isType(TYPE_DATA) and (self.state == STATE_CLOSING):
                    self.update_data_timeout()
                    pass
                elif packet.isType(TYPE_ACK):
                    self.update_data_timeout()
                    print("CLIENT GOT ACK")
                    self.validAck(packet)
                    self.writeDown()
                elif packet.isType(TYPE_RIP):
                    self.update_data_timeout()
                    self.state = STATE_CLOSING
                    self.sendRipAck(packet.SequenceNumber + 1)
                    # self.transport.super().close()
                    self.connection_lost(None)
                elif packet.isType(TYPE_RIPACK) and (self.state == STATE_CLOSING):
                    print ("CLIENT GOT RIP ACK")
                    self.connection_lost(None)
                else:
                    # Unexpected State - Terminate Connection
                    print ("Unexpected State 1")
                    print("packet type is: " + str(packet.Type))
                    print("current state is: " + str(self.state))
                    # self.connection_lost(None)
            else:
                # Unexpected State - Terminate Connection
                print ("Unexpected State 2")
                pass

    def connection_lost(self, exc):
        print("PEEP CLIENT CONNECTION LOST because {0}".format(exc))
        if self.timer is not None:
            self.timer.cancel()
        super().connection_lost(exc)

    """ PEEP Functions """

    def _sendSynHandshake(self):
        print("SEND SYN")
        synPacket = PEEPPacket.makeSyn()
        print("SYN SEQ NUM:", synPacket.SequenceNumber)
        self.snd_una = synPacket.SequenceNumber
        self.nxt_snd = synPacket.SequenceNumber + 1
        self.state = STATE_OPENING
        # self.transport.write(synPacket.__serialize__())
        self.forHigherTransport.send_buf.append(synPacket)
        if self.timer is not None:
            self.timer.cancel()
        self.timer = asyncio.get_event_loop().call_later(self.TIMEOUT, self.timeout)
        self.writeDown()

    def _validSynAckHandshake(self, synAckPacket):
        if self.nxt_snd != synAckPacket.Acknowledgement:
            return False
        if not synAckPacket.verifyChecksum():
            return False
        return True


""" ------------ PEEP Server ------------ """

class PEEPServer(PEEPBase):

    """ Playground Protocol Functions """

    def __init__(self):
        print("PEEP SERVER INIT")
        super().__init__()
        self.counter = 0

    def connection_made(self, transport):
        print("SERVER CONNECTION MADE")
        super().connection_made(transport)

    def data_received(self, data):
        self.deserializer.update(data)
        print("DATA RECEIVED")

        for packet in self.deserializer.nextPackets():
            if isinstance(packet, PEEPPacket):
                print("We have a packet")
            if isinstance(packet, PEEPPacket) and packet.verifyChecksum():
                if packet.isType(TYPE_SYN) and (self.state == STATE_IDLE):
                    if self._validSynHandshake(packet):
                        self.nxt_rcv = packet.SequenceNumber + 1
                        self.snd_una = packet.Acknowledgement
                        self.update_data_timeout()
                        self._sendSynAckHandshake(packet)
                    else:
                        print("SERVER BAD SYN")
                        self.connection_lost(None)
                elif packet.isType(TYPE_SYN) and (self.state == STATE_OPENING):
                    self._sendSynAckHandshake(packet)
                elif packet.isType(TYPE_ACK) and (self.state == STATE_OPENING):
                    print("CONNECTION ACK RECEIVED")
                    if self._validAckHandshake(packet):
                        self.update_data_timeout()
                        self.state = STATE_TRANSMIT
                        self.nxt_rcv += 1
                        self.snd_una = packet.Acknowledgement
                        self.higherProtocol().connection_made(self.forHigherTransport)
                    else:
                        print("SERVER BAD OPEN ACK")
                        self.connection_lost(None)
                elif packet.isType(TYPE_DATA) and (self.state == STATE_TRANSMIT):
                    self.update_data_timeout()
                    self.counter += 1
                    print("COUNTER IS " + str(self.counter))
                    self.handleRcvData(packet)
                    # TODO remove if true
                    # if True:
                    #     self.handleRcvData(packet)
                    # else:
                    #     print("Dropped packet w/ seq: " + str(packet.SequenceNumber))
                    #self.handleRcvData(packet)
                elif packet.isType(TYPE_DATA) and (self.state == STATE_CLOSING):
                    pass
                elif packet.isType(TYPE_ACK) and self.validAck(packet):
                    print ("SERVER GOT ACK")
                    self.writeDown()
                elif packet.isType(TYPE_RIP):
                    self.state = STATE_CLOSING
                    self.sendRipAck(packet.SequenceNumber + 1)
                    # self.transport.super().close()
                    self.connection_lost(None)
                elif packet.isType(TYPE_RIPACK) and (self.state == STATE_CLOSING):
                    #TODO need to check that this wasn't a retransmission (seq numbers should match)
                    print ("SERVER GOT RIP ACK")
                    self.connection_lost(None)
                else:
                    print ("Unexpected state 3")
                    # Unexpected State - Terminate Connection
                    print("packet type is: " + str(packet.Type))
                    print("current state is: " + str(self.state))
                    # self.connection_lost(None)
            else:
                # Unexpected State - Terminate Connection
                print ("Unexpected state 4")
                pass

    def connection_lost(self, exc):
        print("SERVER CONNECTION LOST because {0}".format(exc))
        if self.timer is not None:
            self.timer.cancel()
        super().connection_lost(exc)

    """ PEEP Functions """

    def _validSynHandshake(self, synPacket):
        if self.snd_una is not None or self.nxt_rcv is not None or self.nxt_snd is not None:
            return False
        if not synPacket.verifyChecksum():
            return False
        return True

    def _validAckHandshake(self, packet):
        # TODO does this handle if data is sent in the ACK? Might need to generalize
        if self.nxt_snd != packet.Acknowledgement:
            return False
        if not packet.verifyChecksum():
            return False
        return True

    def _sendSynAckHandshake(self, synPacket):
        print("SEND SYNACK")
        self.nxt_rcv = (synPacket.SequenceNumber + 1) % (2 ** 32)
        synAckPacket = PEEPPacket.makeSynAck(synPacket.SequenceNumber)
        self.nxt_snd = synAckPacket.SequenceNumber + 1
        self.state = STATE_OPENING
        # self.transport.write(synAckPacket.__serialize__())
        self.forHigherTransport.send_buf.append(synAckPacket)
        if self.timer is not None:
            self.timer.cancel()
        self.timer = asyncio.get_event_loop().call_later(self.TIMEOUT, self.timeout)
        self.writeDown()

""" ------------ PEEP Stacking Transport ------------ """

class PEEPStackingTransport(StackingTransport):
    def __init__(self, transport, PEEPProtocol):
        super().__init__(transport)
        self.PEEPProtocol = PEEPProtocol
        self.send_buf = list()

    def write(self, data):
        # Create PEEP Data Packet
        while len(data[:MAX_DATA_CHUNK]) > 0 and self.PEEPProtocol.state is not STATE_CLOSING:
            packet = self.getDataPkt(data[:MAX_DATA_CHUNK])
            data = data[MAX_DATA_CHUNK:]
            self.send_buf.append(packet)
        self.PEEPProtocol.writeDown()

    def close(self):
        print("TRANSPORT.CLOSE() CALLED -> WILL CALL CONNECTION_LOST()")
        print(type(self.PEEPProtocol))
        print("In transport, original state is " + str(self.PEEPProtocol.state))
        self.PEEPProtocol.state = STATE_CLOSING
        print("In transport, state is " + str(self.PEEPProtocol.state))
        self.PEEPProtocol.writeDown()
        # send rip
        #super().close()

    def getDataPkt(self, data):
        self.PEEPProtocol.nxt_snd = self.PEEPProtocol.nxt_snd + len(data)
        packet = PEEPPacket.makeData(self.PEEPProtocol.nxt_snd - 1,
                                     self.PEEPProtocol.nxt_rcv,
                                     data)
        return packet
