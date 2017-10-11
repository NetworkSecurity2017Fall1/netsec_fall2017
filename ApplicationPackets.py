"""Application Packets"""

from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, BOOL


class CheckUsername(PacketType):
    DEFINITION_IDENTIFIER = "CheckUsername Packet"
    DEFINITION_VERSION = "1.0"
    FIELDS = [("username", STRING)]


class UsernameAvailability(PacketType):
    DEFINITION_IDENTIFIER = "UsernameAvailability Packet"
    DEFINITION_VERSION = "1.0"
    FIELDS = [("username_availability", BOOL)]


class SignUpRequest(PacketType):
    DEFINITION_IDENTIFIER = "SignUpRequest Packet"
    DEFINITION_VERSION = "1.0"
    FIELDS = [("username", STRING), ("password", STRING), ("email", STRING)]


class SignUpResult(PacketType):
    DEFINITION_IDENTIFIER = "SignUpResult Packet"
    DEFINITION_VERSION = "1.0"
    FIELDS = [("result", BOOL), ("user_id", UINT32)]