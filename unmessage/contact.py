import re

import attr
from nacl.public import PublicKey

from . import errors
from .utils import Address


@attr.s
class Contact(object):
    identity = attr.ib()
    key = attr.ib()
    is_verified = attr.ib(default=False)
    has_presence = attr.ib(default=False)

    @identity.validator
    def is_valid_identity(self, attribute, value):
        if not (isinstance(value, str) and
                re.match(r'[a-zA-Z0-9_-]+@[a-z2-7]{16}\.onion:\d+$', value)):
            raise errors.InvalidIdentityError()

    @key.validator
    def is_valid_key(self, attribute, value):
        if not (isinstance(value, bytes) and
                len(value) == PublicKey.SIZE):
            raise errors.InvalidPublicKeyError()

    @property
    def name(self):
        return self.identity.split('@')[0]

    @property
    def address(self):
        host, port = self.identity.split('@')[-1].split(':')
        return Address(host, int(port))
