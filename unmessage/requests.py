class InboundRequest:
    def __init__(self, conversation, packet):
        self.conversation = conversation
        self.packet = packet


class OutboundRequest:
    def __init__(self, conversation,
                 handshake_keys=None, ratchet_keys=None,
                 packet=None):
        self.conversation = conversation
        self.handshake_keys = handshake_keys
        self.ratchet_keys = ratchet_keys
        self.packet = packet
