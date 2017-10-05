import playground
from playground.network.common import StackingProtocolFactory
from . import lab2_protocol
#from lab2_protocol import PEEPClientProtocol, PEEPServerProtocol
#lab2ClientFactory = StackingProtocolFactory(lambda: PassThroughLayer1(), lambda: PEEPClientProtocol())
#lab2ServerFactory = StackingProtocolFactory(lambda: PassThroughLayer1(), lambda: PEEPServerProtocol())
lab2ClientFactory = StackingProtocolFactory(lambda: lab2_protocol.PEEPClientProtocol())
lab2ServerFactory = StackingProtocolFactory(lambda: lab2_protocol.PEEPServerProtocol())
lab2Connector = playground.Connector(protocolStack=(lab2ClientFactory, lab2ServerFactory))
playground.setConnector("lab2_protocol", lab2Connector)
