from functools import wraps

import attr
from pyaxo import a2b

from . import errors
from .utils import raise_if_not


IV_LEN = 8
KEY_LEN = 32
ENC_KEY_LEN = 72
HASH_LEN = 32

LINESEP = '\n'


def raise_malformed(f):
    @wraps(f)
    def try_building(cls, data):
        try:
            return f(cls, data)
        except (AssertionError, IndexError, TypeError, ValueError):
            e = errors.MalformedPacketError(cls.__name__)
            indexed_lines = ['[{}]: {}'.format(index, line)
                             for index, line in enumerate(data.splitlines())]
            e.message = LINESEP.join([e.message] + indexed_lines)
            raise e
    return try_building


def is_valid_length(value, length):
    try:
        return isinstance(value, str) and len(a2b(value)) == length
    except TypeError:
        return False


def is_valid_non_empty(value):
    try:
        return isinstance(value, str) and len(a2b(value)) > 0
    except TypeError:
        return False


def is_valid_iv(value):
    return is_valid_length(value, IV_LEN)


def is_valid_key(value):
    return is_valid_length(value, KEY_LEN)


def is_valid_enc_key(value):
    return is_valid_length(value, ENC_KEY_LEN)


def is_valid_hash(value):
    return is_valid_length(value, HASH_LEN)


def is_valid_empty(value):
    return is_valid_length(value, 0)


@attr.s
class Packet(object):
    @classmethod
    @raise_malformed
    def build(cls, data):
        return cls(*data.splitlines())

    def __str__(self):
        return LINESEP.join([str(getattr(self, a.name))
                             for a in attr.fields(type(self))])


@attr.s
class IdentifiablePacket(Packet):
    iv = attr.ib(validator=raise_if_not(is_valid_iv))
    iv_hash = attr.ib(validator=raise_if_not(is_valid_hash))


@attr.s
class IntroductionPacket(IdentifiablePacket):
    tail = attr.ib(validator=raise_if_not(is_valid_non_empty))

    @classmethod
    @raise_malformed
    def build(cls, data):
        lines = data.splitlines()
        return cls(iv=lines[0],
                   iv_hash=lines[1],
                   tail=LINESEP.join(lines[2:]))


@attr.s
class RegularPacket(IdentifiablePacket):
    payload_hash = attr.ib(validator=raise_if_not(is_valid_hash))
    handshake_key = attr.ib(validator=raise_if_not(is_valid_empty))
    payload = attr.ib(validator=raise_if_not(is_valid_non_empty))


@attr.s
class ReplyPacket(IdentifiablePacket):
    payload_hash = attr.ib(validator=raise_if_not(is_valid_hash))
    handshake_key = attr.ib(validator=raise_if_not(is_valid_enc_key))
    payload = attr.ib(validator=raise_if_not(is_valid_non_empty))


@attr.s
class RequestPacket(IdentifiablePacket):
    handshake_packet_hash = attr.ib(validator=raise_if_not(is_valid_hash))
    request_key = attr.ib(validator=raise_if_not(is_valid_key))
    handshake_packet = attr.ib(raise_if_not(is_valid_non_empty))


@attr.s
class HandshakePacket(Packet):
    identity = attr.ib(validator=attr.validators.instance_of(str))
    identity_key = attr.ib(validator=raise_if_not(is_valid_key))
    handshake_key = attr.ib(validator=raise_if_not(is_valid_key))
    ratchet_key = attr.ib(validator=raise_if_not(is_valid_key))


@attr.s
class ElementPacket(Packet):
    type_ = attr.ib(validator=attr.validators.instance_of(str))
    id_ = attr.ib(validator=attr.validators.instance_of(str))
    part_num = attr.ib(convert=int)
    part_len = attr.ib(convert=int)
    payload = attr.ib(validator=attr.validators.instance_of(str))

    @classmethod
    @raise_malformed
    def build(cls, data):
        lines = data.splitlines()
        return cls(type_=lines[0],
                   id_=lines[1],
                   part_num=lines[2],
                   part_len=lines[3],
                   payload=LINESEP.join(lines[4:]))
