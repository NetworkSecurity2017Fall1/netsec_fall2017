"""Application Server"""

import ApplicationPackets
import asyncio
import lab2.src.lab2_protocol  # should be deleted when __init__.py is put under .playground/connectors
from playground import getConnector
from playground.network.packet import PacketType


class ServerProtocol(asyncio.Protocol):
    def __init__(self):
        self.transport = None
        self.deserializer = PacketType.Deserializer()
        self.state = 0

    def connection_made(self, transport):
        self.transport = transport
        print("Server: Connected to server.")

    def data_received(self, data):
        self.deserializer.update(data)
        for packet in self.deserializer.nextPackets():
            if isinstance(packet, ApplicationPackets.CheckUsername) and self.state == 0:
                print("Server: Server receives CheckUsername packet.")
                username_availability = self.check_username_availability_in_database(packet.username)
                new_packet = ApplicationPackets.UsernameAvailability()
                new_packet.username_availability = username_availability
                new_packet_se = new_packet.__serialize__()
                self.state += 1
                self.transport.write(new_packet_se)
                print("Server: Server sends UsernameAvailability packet.")
            elif isinstance(packet, ApplicationPackets.SignUpRequest) and self.state == 1:
                print("Server: Server receives SignUp packet.")
                sign_up_result = self.sign_up_to_database(packet.username, packet.password, packet.email)
                new_packet = ApplicationPackets.SignUpResult()
                if sign_up_result[0]:
                    new_packet.result = True
                    new_packet.user_id = sign_up_result[1]
                else:
                    new_packet.result = False
                    new_packet.user_id = 0
                new_packet_se = new_packet.__serialize__()
                self.transport.write(new_packet_se)
                print("Server: Server sends SignUpResult packet.")
            else:
                print("Server: Wrong packet received on server side.")
                self.state = 0
                self.transport = None
                break

    def connection_lost(self, exc):
        self.transport = None

    def check_username_availability_in_database(self, username):  # mock database query method
        return True

    def sign_up_to_database(self, username, password, email):  # mock database query method
        return [True, 1]


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.set_debug(enabled=True)
    coro = getConnector("lab2_protocol").create_playground_server(lambda: ServerProtocol(), 101)
    server = loop.run_until_complete(coro)
    print("Server: Server started at {}".format(server.sockets[0].gethostname()))
    loop.run_forever()
    loop.close()
