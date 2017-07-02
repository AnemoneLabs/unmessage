import attr

from .utils import Address, raise_invalid_identity, raise_invalid_pub_key


@attr.s
class Contact(object):
    identity = attr.ib(validator=raise_invalid_identity)
    key = attr.ib(validator=raise_invalid_pub_key)
    is_verified = attr.ib(validator=attr.validators.instance_of(bool),
                          default=False)
    has_presence = attr.ib(validator=attr.validators.instance_of(bool),
                           default=False)

    @property
    def name(self):
        return self.identity.split('@')[0]

    @property
    def address(self):
        host, port = self.identity.split('@')[-1].split(':')
        return Address(host, int(port))
