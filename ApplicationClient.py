"""Application Client"""

import ApplicationPackets
import asyncio
import lab2.src.lab2_protocol
from playground import getConnector
from playground.network.packet import PacketType


class ClientProtocol(asyncio.Protocol):
    def __init__(self, username, password, email):
        self.transport = None
        self.deserializer = PacketType.Deserializer()
        self.state = 0
        self.username = username
        self.password = password
        self.email = email

    def connection_made(self, transport):
        self.transport = transport
        print("Client: Connected to client.")
        self.sign_up()

    def data_received(self, data):
        self.deserializer.update(data)
        for packet in self.deserializer.nextPackets():
            if isinstance(packet, ApplicationPackets.UsernameAvailability) and self.state == 0:
                print("Client: Client receives UsernameAvailability packet.")
                if packet.username_availability:
                    print("Client: Username '" + self.username + "' is available.")
                    new_packet = ApplicationPackets.SignUpRequest()
                    new_packet.username = self.username
                    new_packet.password = self.password
                    new_packet.email = self.email
                    new_packet_se = new_packet.__serialize__()
                    self.state += 1
                    self.transport.write(new_packet_se)
                    print("Client: Client sends SignUpRequest packet.")
                else:
                    print("Client: Username '" + self.username + "' is unavailable.")
            elif isinstance(packet, ApplicationPackets.SignUpResult) and self.state == 1:
                print("Client: Client receives SignUpResult packet.")
                if packet.result:
                    print("Client: Signed up successfully. Username is '" + self.username + "'.")
                else:
                    print("Client: Failed to sign up.")
            else:
                print("Client: Wrong packet received on client side.")
                self.state = 0
                self.transport = None
                break

    def connection_lost(self, exc):
        self.transport = None

    def sign_up(self):
        packet = ApplicationPackets.CheckUsername()
        packet.username = self.username
        packet_se = packet.__serialize__()
        self.transport.write(packet_se)
        print("Client: Starting signup. Client sends CheckUsername packet.")


if __name__ == "__main__":

    loop = asyncio.get_event_loop()
    loop.set_debug(enabled=True)
    remote_address = "20174.1.1.1"
    coro = getConnector("lab2_protocol").create_playground_connection(
        lambda: ClientProtocol("harry", "123456", "harry@gmail.com"),
        remote_address, 101)
    transport, client = loop.run_until_complete(coro)
    print("Client: Client started. t:{}. p:{}.".format(transport, client))
    loop.run_forever()
    loop.close()

