"""__init__"""

import playground
from playground.network.common import StackingProtocolFactory
from . import PEEPProtocols
from . import PLSProtocols

team5ClientFactory = StackingProtocolFactory(lambda: PLSProtocols.PLSClientProtocol(), lambda: PEEPProtocols.PEEPClientProtocol())
team5ServerFactory = StackingProtocolFactory(lambda: PLSProtocols.PLSServerProtocol(), lambda: PEEPProtocols.PEEPServerProtocol())
team5Connector = playground.Connector(protocolStack=(team5ClientFactory, team5ServerFactory))
playground.setConnector("team5_protocol", team5Connector)
