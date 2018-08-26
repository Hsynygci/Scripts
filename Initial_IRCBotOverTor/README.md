# SimpleIRCBotOverTor
Simple IRC bot code over Tor network with python

Simple IRC bot connects via SOCKS port to Tor network. This code is skeleton.  

//Specify the port which is conneting Tor.
puttyEndPoint = TCP4ClientEndpoint(reactor, '127.0.0.1', 9050)

//Specify the '.onion' url of IRC server with configured SOCKs port, this code for v5. 
point = SOCKS5ClientEndpoint('p6ncbp3wozslmdlc.onion', 6667, puttyEndPoint)

//Specify the channel name for IRC Server
d = point.connect(MomBotFactory('#' + 'aa', clientName))
