import re

from nacl.public import PublicKey

from . import errors
from .utils import Address


class Contact(object):
    def __init__(self, identity, key, is_verified=False, has_presence=False):
        self._identity = None
        self._key = None

        self.identity = identity
        self.key = key
        self.is_verified = is_verified
        self.has_presence = has_presence

    @property
    def identity(self):
        return self._identity

    @identity.setter
    def identity(self, identity):
        if re.match(r'[a-zA-Z0-9_-]+@[a-z2-7]{16}\.onion:\d+$', identity):
            self._identity = identity
        else:
            raise errors.InvalidIdentityError()

    @property
    def name(self):
        return self.identity.split('@')[0]

    @property
    def address(self):
        host, port = self.identity.split('@')[-1].split(':')
        return Address(host, int(port))

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, key):
        if isinstance(key, bytes) and len(key) == PublicKey.SIZE:
            self._key = key
        else:
            raise errors.InvalidPublicKeyError()
