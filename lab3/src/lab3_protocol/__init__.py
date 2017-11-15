"""__init__"""

import playground
from playground.network.common import StackingProtocolFactory
from . import PEEPProtocols
from . import PLSProtocols
lab2ClientFactory = StackingProtocolFactory(lambda: PLSProtocols.PLSClientProtocol(), lambda: PEEPProtocols.PEEPClientProtocol())
lab2ServerFactory = StackingProtocolFactory(lambda: PLSProtocols.PLSServerProtocol(), lambda: PEEPProtocols.PEEPServerProtocol())
lab2Connector = playground.Connector(protocolStack=(lab2ClientFactory, lab2ServerFactory))
playground.setConnector("lab2_protocol", lab2Connector)
