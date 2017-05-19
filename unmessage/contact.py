import attr

from . import errors
from .utils import Address, is_valid_identity, is_valid_pub_key


@attr.s
class Contact(object):
    identity = attr.ib()
    key = attr.ib()
    is_verified = attr.ib(default=False)
    has_presence = attr.ib(default=False)

    @identity.validator
    def validate_identity(self, attribute, value):
        if not is_valid_identity(value):
            raise errors.InvalidIdentityError()

    @key.validator
    def validate_key(self, attribute, value):
        if not is_valid_pub_key(value):
            raise errors.InvalidPublicKeyError()

    @property
    def name(self):
        return self.identity.split('@')[0]

    @property
    def address(self):
        host, port = self.identity.split('@')[-1].split(':')
        return Address(host, int(port))
