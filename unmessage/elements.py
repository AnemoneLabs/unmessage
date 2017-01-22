from nacl.utils import random
from pyaxo import b2a


class Element(dict):
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


class RequestElement:
    type_ = 'req'
    request_accepted = 'accepted'


class PresenceElement:
    type_ = 'pres'
    status_online = 'online'
    status_offline = 'offline'


class MessageElement:
    type_ = 'msg'


class AuthenticationElement:
    type_ = 'auth'


ID_LENGTH = 2


def get_random_id():
    return b2a(random(ID_LENGTH))
