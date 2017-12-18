"""__init__"""

import playground
from playground.network.common import StackingProtocolFactory
from . import PEEPProtocols
from . import PLSProtocols

team5ClientFactory = StackingProtocolFactory(lambda: PEEPProtocols.PEEPClientProtocol(), lambda: PLSProtocols.PLSClientProtocol())
team5ServerFactory = StackingProtocolFactory(lambda: PEEPProtocols.PEEPServerProtocol(), lambda: PLSProtocols.PLSServerProtocol())
team5Connector = playground.Connector(protocolStack=(team5ClientFactory, team5ServerFactory))
playground.setConnector("team5_protocol", team5Connector)
