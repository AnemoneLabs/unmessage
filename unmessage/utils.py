import os
import re
from functools import wraps
from threading import Event

import attr
from nacl.public import PublicKey
from twisted.internet.threads import deferToThread as fork

from . import errors


def join(d):
    results = [None, None]
    event = Event()

    def callback(result):
        results[0] = result
        event.set()

    def errback(failure):
        results[1] = failure
        event.set()

    d.addCallbacks(callback, errback)
    event.wait()

    if results[1]:
        results[1].raiseException()
    else:
        return results[0]


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
