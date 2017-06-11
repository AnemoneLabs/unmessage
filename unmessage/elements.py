import json

import attr
from nacl.utils import random
from pyaxo import b2a


class PartialElement(dict):
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


@attr.s
class ElementPayload(object):
    filtered_attr_names = None

    content = attr.ib(default=None)

    @classmethod
    def filter_attrs(cls, attribute, value):
        if cls.filtered_attr_names is None:
            return True
        else:
            return attribute.name in cls.filtered_attr_names

    @classmethod
    def deserialize(cls, data):
        return cls(**json.loads(data))

    def serialize(self):
        return json.dumps(attr.asdict(self, filter=self.filter_attrs))


@attr.s
class RequestElement(ElementPayload):
    type_ = 'req'
    request_accepted = 'accepted'


@attr.s
class UntalkElement(ElementPayload):
    type_ = 'untalk'


@attr.s
class PresenceElement(ElementPayload):
    type_ = 'pres'
    status_online = 'online'
    status_offline = 'offline'


@attr.s
class MessageElement(ElementPayload):
    type_ = 'msg'


@attr.s
class AuthenticationElement(ElementPayload):
    type_ = 'auth'


@attr.s
class FileRequestElement(ElementPayload):
    type_ = 'filereq'
    request_accepted = 'accepted'

    size = attr.ib(default=None)
    checksum = attr.ib(default=None)


@attr.s
class FileElement(ElementPayload):
    type_ = 'file'


REGULAR_ELEMENT_TYPES = [RequestElement.type_,
                         PresenceElement.type_,
                         MessageElement.type_,
                         AuthenticationElement.type_]


ID_LENGTH = 2


def get_random_id():
    return b2a(random(ID_LENGTH))
