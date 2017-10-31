"""__init__"""

import playground
from playground.network.common import StackingProtocolFactory
from . import PLSProtocols
lab3ClientFactory = StackingProtocolFactory(lambda: PLSProtocols.PLSClientProtocol())
lab3ServerFactory = StackingProtocolFactory(lambda: PLSProtocols.PLSServerProtocol())
lab3Connector = playground.Connector(protocolStack=(lab3ClientFactory, lab3ServerFactory))
playground.setConnector("lab3_protocol", lab3Connector)
