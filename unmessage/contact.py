import attr

from . import errors
from .utils import Address, is_valid_identity, raise_invalid_pub_key


@attr.s
class Contact(object):
    identity = attr.ib()
    key = attr.ib(validator=raise_invalid_pub_key)
    is_verified = attr.ib(default=False)
    has_presence = attr.ib(default=False)

    @identity.validator
    def validate_identity(self, attribute, value):
        if not is_valid_identity(value):
            raise errors.InvalidIdentityError()

    @property
    def name(self):
        return self.identity.split('@')[0]

    @property
    def address(self):
        host, port = self.identity.split('@')[-1].split(':')
        return Address(host, int(port))
