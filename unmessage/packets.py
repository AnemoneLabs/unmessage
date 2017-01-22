from functools import wraps

from . import elements
from . import errors


IV_LEN = 8
LINESEP = '\n'


def raise_malformed(f):
    @wraps(f)
    def try_building(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except (IndexError, TypeError):
            packet_type = f.func_name.split('_')[1]
            raise errors.MalformedPacketError(packet_type)
    return try_building


@raise_malformed
def build_regular_packet(data):
    return RegularPacket(*data.splitlines())


@raise_malformed
def build_request_packet(data):
    return RequestPacket(*data.splitlines())


@raise_malformed
def build_handshake_packet(data):
    return HandshakePacket(*data.splitlines())


@raise_malformed
def build_element_packet(data):
    lines = data.splitlines()
    return ElementPacket(type_=lines[0],
                         id_=lines[1],
                         part_num=lines[2],
                         part_len=lines[3],
                         payload=lines[4])


class RegularPacket:
    def __init__(self, iv, iv_hash, payload_hash, handshake_key, payload):
        self.iv = iv
        self.iv_hash = iv_hash
        self.payload_hash = payload_hash
        self.handshake_key = handshake_key
        self.payload = payload

    def __str__(self):
        return LINESEP.join([self.iv,
                             self.iv_hash,
                             self.payload_hash,
                             self.handshake_key,
                             self.payload])


class RequestPacket:
    def __init__(self, iv, iv_hash, handshake_packet_hash, request_key,
                 handshake_packet):
        self.iv = iv
        self.iv_hash = iv_hash
        self.handshake_packet_hash = handshake_packet_hash
        self.request_key = request_key
        self.handshake_packet = handshake_packet

    def __str__(self):
        return LINESEP.join([self.iv,
                             self.iv_hash,
                             self.handshake_packet_hash,
                             self.request_key,
                             str(self.handshake_packet)])


class HandshakePacket:
    def __init__(self, identity, identity_key, handshake_key, ratchet_key):
        self.identity = identity
        self.identity_key = identity_key
        self.handshake_key = handshake_key
        self.ratchet_key = ratchet_key

    def __str__(self):
        return LINESEP.join([self.identity,
                             self.identity_key,
                             self.handshake_key,
                             self.ratchet_key])


class ElementPacket:
    def __init__(self, type_, payload, id_=None, part_num=1, part_len=1):
        self.type_ = type_
        self.payload = payload
        if not id_:
            id_ = elements.get_random_id()
        self.id_ = id_
        self.part_num = int(part_num)
        self.part_len = int(part_len)

    def __str__(self):
        return LINESEP.join([self.type_,
                             self.id_,
                             str(self.part_num),
                             str(self.part_len),
                             self.payload])
