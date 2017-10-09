"""__init__"""

import playground
from playground.network.common import StackingProtocolFactory
from . import lab2_protocol
lab2ClientFactory = StackingProtocolFactory(lambda: lab2_protocol.PEEPClientProtocol())
lab2ServerFactory = StackingProtocolFactory(lambda: lab2_protocol.PEEPServerProtocol())
lab2Connector = playground.Connector(protocolStack=(lab2ClientFactory, lab2ServerFactory))
playground.setConnector("lab2_protocol", lab2Connector)
