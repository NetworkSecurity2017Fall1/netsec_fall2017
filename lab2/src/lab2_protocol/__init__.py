"""__init__"""

import playground
from playground.network.common import StackingProtocolFactory
from . import PEEPProtocols
lab2ClientFactory = StackingProtocolFactory(lambda: PEEPProtocols.PEEPClientProtocol())
lab2ServerFactory = StackingProtocolFactory(lambda: PEEPProtocols.PEEPServerProtocol())
lab2Connector = playground.Connector(protocolStack=(lab2ClientFactory, lab2ServerFactory))
playground.setConnector("lab2_protocol", lab2Connector)
