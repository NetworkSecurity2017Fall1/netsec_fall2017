"""Transport"""
import threading, time
from playground.network.common import StackingTransport
from . import Packets

class terminationThread(threading.Thread):
    def __init__(self, threadID, name, func):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.counter = 5
        self.name = name
        self.func = func

    def run(self):
        print("Starting " + self.name)
        self.func()
        print("Exiting " + self.name)

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



class MyProtocolTransport(StackingTransport):

    def reset_all(self):
        self.window_size = 5
        self.my_protocol_packets = []
        self.to_send = []
        self.expected_ack = []
        self.chunk_size = 1024
        self.state = 2
        self.counter = 0.3
        self.thread1 = resendThread(1, "resendThread", self.resend)
        self.thread1.start()

    def mvwindow(self, n):
        # print("move window ", n)
        # print("  before move expected_ack: ", self.expected_ack)
        # print("  before move to send: ", self.to_send)
        # print("  before move my protocol packets: ", self.my_protocol_packets)
        self.counter = 10
        while n > 0:
            # print("    enter first while loop")
            self.to_send.pop(0)
            self.expected_ack.pop(0)
            n-=1
        while len(self.to_send) < 5 and len(self.my_protocol_packets) > 0:
            # print("    enter second while loop")
            pkt = self.my_protocol_packets[0]
            # print("      second while loop line 1")
            self.lowerTransport().write(pkt.__serialize__())
            # print("      second while loop line 2")
            self.to_send.append(pkt)
            # print("      second while loop line 3")
            self.my_protocol_packets.pop(0)
            # print("PEEP: Sending PEEP packet.", pkt.to_string())
            if pkt.Type == 3:
                self.expected_ack.append(pkt.SequenceNumber + 1)
                print("the packet it sends is RIP")

            else:
                self.expected_ack.append(pkt.SequenceNumber + len(pkt.Data))
        self.counter = 0.3
        #
        # print("  after move expected_ack: ", self.expected_ack)
        # print("  after move to send: ", self.to_send)
        # print("  before move my protocol packets: ", self.my_protocol_packets)

    def close(self):
        print("transport.close")
        if self.state != 2:
            return
        pkt = Packets.PEEPPacket.set_rip(self.seq_sending)
        if len(self.to_send) < 5 and len(self.my_protocol_packets) == 0:
            self.state = 6
            self.lowerTransport().write(pkt.__serialize__())
            self.expected_ack.append(pkt.SequenceNumber + 1)
            self.to_send.append(pkt)
            self.lowerTransport().close()
        else:
            self.my_protocol_packets.append(pkt)
            self.state = 5
        self.thread2 = terminationThread(1, "terminationThread", self.termination)
        self.thread2.start()
        print("to_send after close", self.to_send)

    def termination(self):
        counter = 5
        while self.state != 6 and counter!=0:
            print("Session ends in ", counter, " sec.")
            counter = counter - 1
            time.sleep(1)
        self.lowerTransport().close()
        print("self.lowerTransport().close()")

    def resend(self):
        while self.state < 6:
            # print("self.counter: ", self.counter)
            if self.counter <= 0:
                print("It has been a while, resend packets")
                print("length of to_send: ", len(self.to_send))
                if len(self.to_send) == 1 and self.to_send[0].Type == 3:
                    self.state = 6
                    self.lowerTransport().write(self.to_send[0].__serialize__())
                    print("the packet it sends is RIP")
                else:
                    for i in range(0, len(self.to_send)):
                        self.lowerTransport().write(self.to_send[i].__serialize__())
                        print("PEEP: Sending PEEP packet.", self.to_send[i].to_string())
                self.counter = 0.3
            else:
                self.counter = self.counter - 0.1
            time.sleep(0.1)

    # def resend(self, index):
    #     if self.state == 5:
    #         return
    #     print("resend: ", index)
    #     assert(index < 5)
    #     self.lowerTransport().write(self.to_send[index].__serialize__())
    #     print("PEEP: Sending PEEP packet.", self.to_send[index].to_string())

    def seq_start(self, seq):
        self.seq_sending = seq

    def write(self, data):
        if self.state == 5:
            return
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

        # print("my protocol packets length: ", len(self.my_protocol_packets))
        while(len(self.to_send) < self.window_size and len(self.my_protocol_packets) != 0):
            pkt = self.my_protocol_packets[0]
            self.lowerTransport().write(pkt.__serialize__())
            self.to_send.append(pkt)
            self.expected_ack.append(pkt.SequenceNumber + len(pkt.Data))
            self.my_protocol_packets.pop(0)
            # print("PEEP: Sending PEEP packet.", pkt.to_string())
            self.counter = 0.3


        
