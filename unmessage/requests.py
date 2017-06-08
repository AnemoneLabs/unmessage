import attr
from pyaxo import Keypair

from .packets import RequestPacket


@attr.s
class InboundRequest(object):
    conversation = attr.ib()
    packet = attr.ib(validator=attr.validators.instance_of(RequestPacket))


@attr.s
class OutboundRequest(object):
    conversation = attr.ib()
    request_keys = attr.ib(
        validator=attr.validators.optional(
            attr.validators.instance_of(Keypair)),
        default=None)
    handshake_keys = attr.ib(
        validator=attr.validators.optional(
            attr.validators.instance_of(Keypair)),
        default=None)
    ratchet_keys = attr.ib(
        validator=attr.validators.optional(
            attr.validators.instance_of(Keypair)),
        default=None)
    packet = attr.ib(
        validator=attr.validators.optional(
            attr.validators.instance_of(RequestPacket)),
        default=None)
