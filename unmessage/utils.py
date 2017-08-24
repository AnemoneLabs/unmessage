import json
import os
import re
from functools import wraps

import attr
from nacl.public import PublicKey
from twisted.internet.threads import deferToThread as fork

from . import errors


@attr.s
class Serializable(object):
    filtered_attr_names = None

    @classmethod
    def filter_attrs(cls, attribute, value=None):
        if cls.filtered_attr_names is None:
            return True
        else:
            return attribute.name in cls.filtered_attr_names

    @classmethod
    def deserialize(cls, data):
        return cls(**json.loads(data))

    def serialize(self):
        return json.dumps(attr.asdict(self, filter=self.filter_attrs))


def default_factory_attrib(factory, init=False, takes_self=True):
    return attr.ib(init=False,
                   default=attr.Factory(factory, takes_self=takes_self))


@attr.s
class Paths(object):
    head = attr.ib(validator=attr.validators.instance_of(str))
    tail = attr.ib(validator=attr.validators.instance_of(str))

    def __str__(self):
        return self.base

    @property
    def base(self):
        return os.path.join(self.head, self.tail)

    def join(self, *args):
        return os.path.join(self.base, *args)

    def to_new(self, new_tail):
        return Paths(self.base, new_tail)


@attr.s
class Address(object):
    host = attr.ib(attr.validators.instance_of(str))
    port = attr.ib(attr.validators.instance_of(int))


@attr.s
class Regex(object):
    pattern = attr.ib(attr.validators.instance_of(str))

    def match(self, string, flags=0, match_end=True):
        end = '$' if match_end else ''
        return re.match(self.pattern + end, string, flags)

    def search(self, string, flags=0):
        return re.search(self.pattern, string, flags)


Regex.peer_name = Regex(r'[a-zA-Z0-9_-]+')
Regex.onion_domain = Regex(r'[a-z2-7]{16}\.onion')
Regex.address_port = Regex(r'\d+')
Regex.peer_identity = Regex(r'{}@{}:{}'.format(Regex.peer_name.pattern,
                                               Regex.onion_domain.pattern,
                                               Regex.address_port.pattern))


def raise_if_not(f, error=ValueError):
    @wraps(f)
    def raising_f(instance=None, attribute=None, value=None):
        if not f(value):
            raise error()
    return raising_f


def is_valid_name(value):
    return (isinstance(value, str) and
            Regex.peer_name.match(value) is not None)


raise_invalid_name = raise_if_not(is_valid_name,
                                  errors.InvalidNameError)


def is_valid_identity(value):
    return (isinstance(value, str) and
            Regex.peer_identity.match(value) is not None)


raise_invalid_identity = raise_if_not(is_valid_identity,
                                      errors.InvalidIdentityError)


def is_valid_curve25519_key(value):
    return isinstance(value, bytes) and len(value) == PublicKey.SIZE


def is_valid_priv_key(value):
    return is_valid_curve25519_key(value)


raise_invalid_priv_key = raise_if_not(is_valid_priv_key,
                                      errors.InvalidPrivateKeyError)


def is_valid_pub_key(value):
    return is_valid_curve25519_key(value)


raise_invalid_pub_key = raise_if_not(is_valid_pub_key,
                                     errors.InvalidPublicKeyError)


def is_valid_shared_key(value):
    return is_valid_curve25519_key(value)


raise_invalid_shared_key = raise_if_not(is_valid_shared_key,
                                        errors.InvalidSharedKeyError)


def is_valid_file_name(value):
    # TODO make a real file name validator
    try:
        expath = os.path.expanduser(value)
        assert expath == value
        abspath = os.path.abspath(value)
        assert abspath == os.path.join(os.getcwd(), value)
        head, tail = os.path.split(value)
        assert not len(head) and tail == value
    except:
        return False
    else:
        return True
