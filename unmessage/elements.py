import json

import attr
from nacl.utils import random
from pyaxo import b2a

from .packets import ElementPacket


class PartialElement(dict):
    @classmethod
    def from_element(cls, element, id_=None, max_len=None):
        id_ = id_ or get_random_id()
        parts = list()
        if max_len is None:
            parts.append(element.serialize())
        else:
            # TODO split the element (#59)
            raise Exception('Not implemented')
        partial = cls(element.sender, element.receiver,
                      element.type_, id_, len(parts))
        for part_num, part in enumerate(parts):
            partial[part_num] = parts[part_num]
        return partial

    @classmethod
    def from_packet(cls, packet, sender, receiver):
        partial = cls(sender, receiver,
                      packet.type_, packet.id_, packet.part_len)
        partial[packet.part_num] = packet.payload
        return partial

    def __init__(self, sender, receiver, type_, id_, part_len):
        self.sender = sender
        self.receiver = receiver
        self.type_ = type_
        self.id_ = id_
        self.part_len = part_len

    def __str__(self):
        return ''.join(self.values())

    @property
    def is_complete(self):
        return len(self) == self.part_len

    def to_packets(self):
        packets = list()
        for part_num, part in self.items():
            packets.append(ElementPacket(self.type_,
                                         part,
                                         self.id_,
                                         part_num,
                                         self.part_len))
        return packets

    def to_element(self):
        element = Element.build(self.type_, str(self))
        element.sender = self.sender
        element.receiver = self.receiver
        return element


@attr.s
class Element(object):
    element_classes = None
    filtered_attr_names = ['content']

    content = attr.ib(default=None)
    sender = attr.ib(default=None)
    receiver = attr.ib(default=None)

    @classmethod
    def build(cls, type_, data):
        try:
            return cls.get_element_classes()[type_].deserialize(data)
        except KeyError:
            return Exception('Unknown element type: {}'.format(type_))

    @classmethod
    def get_element_classes(cls):
        if not cls.element_classes:
            cls.element_classes = {c.type_: c for c in cls.__subclasses__()}
        return cls.element_classes

    @classmethod
    def filter_attrs(cls, attribute, value):
        if cls.filtered_attr_names is None:
            return True
        else:
            return attribute.name in cls.filtered_attr_names

    @classmethod
    def deserialize(cls, data):
        return cls(**json.loads(data))

    def __str__(self):
        return self.content

    def serialize(self):
        return json.dumps(attr.asdict(self, filter=self.filter_attrs))


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
