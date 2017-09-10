from functools import wraps

import attr
from nacl.utils import random
from pyaxo import b2a

from . import errors
from .packets import ElementPacket
from .utils import Serializable


def raise_incomplete(f):
    @wraps(f)
    def wrapped_f(self, *args, **kwargs):
        if self.is_complete:
            return f(self, *args, **kwargs)
        else:
            raise errors.IncompleteElementError()
    return wrapped_f


@attr.s
class PartialElement(dict):
    type_ = attr.ib(validator=attr.validators.instance_of(str))
    id_ = attr.ib(validator=attr.validators.instance_of(str))
    part_total = attr.ib(validator=attr.validators.instance_of(int))
    sender = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(str)),
        default=None)
    receiver = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(str)),
        default=None)

    @classmethod
    def from_element(cls, element, id_=None, max_len=0):
        serialized_element = element.serialize()
        id_ = id_ or get_random_id()
        max_len = max_len / 4 * 3 if max_len else len(serialized_element)

        part_num = 0
        partial = cls(element.type_, id_, part_num,
                      element.sender, element.receiver)
        while len(serialized_element):
            partial[part_num] = serialized_element[:max_len]
            serialized_element = serialized_element[max_len:]
            part_num += 1
        partial.part_total = part_num

        return partial

    @classmethod
    def from_packet(cls, packet, sender=None, receiver=None):
        partial = cls(packet.type_, packet.id_, packet.part_total,
                      sender, receiver)
        partial[packet.part_num] = packet.payload
        return partial

    @raise_incomplete
    def __str__(self):
        return ''.join(self.values())

    @property
    def is_complete(self):
        return len(self) == self.part_total

    @raise_incomplete
    def to_packets(self):
        packets = list()
        for part_num, part in self.items():
            packets.append(ElementPacket(self.type_,
                                         self.id_,
                                         part_num,
                                         self.part_total,
                                         part))
        return packets

    def to_element(self):
        element = Element.build(self.type_, str(self))
        element.sender = self.sender
        element.receiver = self.receiver
        return element


@attr.s
class Element(Serializable):
    filtered_attr_names = ['content']

    element_classes = None

    type_ = 'elmt'

    content = attr.ib(default=None)
    sender = attr.ib(default=None)
    receiver = attr.ib(default=None)

    @classmethod
    def build(cls, type_, data):
        try:
            element_class = cls.get_element_classes()[type_]
        except KeyError:
            raise errors.UnknownElementError(type_)
        else:
            return element_class.deserialize(data)

    @classmethod
    def get_element_classes(cls):
        if not cls.element_classes:
            cls.element_classes = {c.type_: c
                                   for c in cls.__subclasses__() + [cls]}
        return cls.element_classes

    def __str__(self):
        return self.content


@attr.s
class RequestElement(Element):
    type_ = 'req'
    request_accepted = 'accepted'


@attr.s
class UntalkElement(Element):
    type_ = 'untalk'


@attr.s
class PresenceElement(Element):
    type_ = 'pres'
    status_online = 'online'
    status_offline = 'offline'


@attr.s
class MessageElement(Element):
    type_ = 'msg'


@attr.s
class AuthenticationElement(Element):
    type_ = 'auth'


@attr.s
class FileRequestElement(Element):
    filtered_attr_names = 'content size checksum'.split()

    type_ = 'filereq'
    request_accepted = 'accepted'

    size = attr.ib(default=None)
    checksum = attr.ib(default=None)

    @classmethod
    def is_valid_request(cls, element):
        # TODO improve this validator
        return (
            isinstance(element, cls) and
            isinstance(element.content, unicode) and len(element.content) and
            isinstance(element.size, int) and element.size > 0 and
            isinstance(element.checksum, unicode) and len(element.checksum))

    @classmethod
    def is_valid_accept(cls, element):
        # TODO improve this validator
        return (
            isinstance(element, cls) and
            isinstance(element.content, unicode) and len(element.content) and
            element.size is None and
            isinstance(element.checksum, unicode) and len(element.checksum))


@attr.s
class FileElement(Element):
    type_ = 'file'

    @classmethod
    def is_valid_file(cls, element):
        # TODO improve this validator
        return (isinstance(element, cls) and
                isinstance(element.content, unicode) and len(element.content))


REGULAR_ELEMENT_TYPES = [RequestElement.type_,
                         PresenceElement.type_,
                         MessageElement.type_,
                         AuthenticationElement.type_]


ID_LENGTH = 2


def get_random_id():
    return b2a(random(ID_LENGTH))
