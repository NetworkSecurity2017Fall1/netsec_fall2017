import playground
from playground.network.common import StackingProtocolFactory
# from .lab2_protocol import lab2ClientFactory, lab2ServerFactory
from lab2_protocol import PEEPClientProtocol, PEEPServerProtocol, PassThroughLayer1
lab2ClientFactory = StackingProtocolFactory(lambda: PassThroughLayer1(), lambda: PEEPClientProtocol())
lab2ServerFactory = StackingProtocolFactory(lambda: PassThroughLayer1(), lambda: PEEPServerProtocol())
lab2Connector = playground.Connector(protocolStack=(lab2ClientFactory, lab2ServerFactory))
playground.setConnector("lab2_protocol", lab2Connector)
