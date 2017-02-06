from functools import wraps

from pyaxo import a2b

from . import elements
from . import errors


IV_LEN = 8
KEY_LEN = 32
ENC_KEY_LEN = 72
HASH_LEN = 32

LINESEP = '\n'


def raise_malformed(f):
    @wraps(f)
    def try_building(data):
        try:
            return f(data)
        except (AssertionError, IndexError, TypeError):
            packet_type = f.func_name.split('_')[1]
            e = errors.MalformedPacketError(packet_type)
            indexed_lines = ['[{}]: {}'.format(index, line)
                             for index, line in enumerate(data.splitlines())]
            e.message = LINESEP.join([e.message] + indexed_lines)
            raise e
    return try_building


def check_iv(packet):
    assert len(a2b(packet.iv)) == IV_LEN
    assert len(a2b(packet.iv_hash)) == HASH_LEN


def check_payload(packet):
    assert len(a2b(packet.payload_hash)) == HASH_LEN
    a2b(packet.payload)


@raise_malformed
def build_intro_packet(data):
    lines = data.splitlines()
    packet = IntroductionPacket(iv=lines[0],
                                iv_hash=lines[1],
                                data=data)

    check_iv(packet)

    return packet


@raise_malformed
def build_regular_packet(data):
    packet = RegularPacket(*data.splitlines())

    check_payload(packet)
    assert not len(a2b(packet.handshake_key))

    return packet


@raise_malformed
def build_reply_packet(data):
    packet = RegularPacket(*data.splitlines())

    check_payload(packet)
    assert len(a2b(packet.handshake_key)) == ENC_KEY_LEN

    return packet


@raise_malformed
def build_request_packet(data):
    packet = RequestPacket(*data.splitlines())

    assert len(a2b(packet.handshake_packet_hash)) == HASH_LEN
    assert len(a2b(packet.request_key)) == KEY_LEN
    a2b(packet.handshake_packet)

    return packet


@raise_malformed
def build_handshake_packet(data):
    packet = HandshakePacket(*data.splitlines())

    assert len(a2b(packet.identity_key)) == KEY_LEN
    assert len(a2b(packet.handshake_key)) == KEY_LEN
    assert len(a2b(packet.ratchet_key)) == KEY_LEN

    return packet


@raise_malformed
def build_element_packet(data):
    lines = data.splitlines()
    return ElementPacket(type_=lines[0],
                         id_=lines[1],
                         part_num=lines[2],
                         part_len=lines[3],
                         payload=lines[4])


class IntroductionPacket:
    def __init__(self, iv, iv_hash, data):
        self.iv = iv
        self.iv_hash = iv_hash
        self.data = data

    def __str__(self):
        return self.data


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
