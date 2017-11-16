#!/usr/bin/env python3
# Network Security - Lab 2

import playground
from .peep_protocol import PEEPClient, PEEPServer

lab2Connector = playground.Connector(protocolStack=(lambda: PEEPClient(), lambda: PEEPServer()))
playground.setConnector("lab2_protocol", lab2Connector)
