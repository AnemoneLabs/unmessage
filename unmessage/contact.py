from .utils import Address


class Contact:
    def __init__(self, identity,
                 key=None, is_verified=False, has_presence=False):
        self.identity = identity
        self.key = key
        self.is_verified = is_verified
        self.has_presence = has_presence

    @property
    def address(self):
        host, port = self.identity.split('@')[-1].split(':')
        return Address(host, int(port))

    @property
    def name(self):
        return '@'.join(self.identity.split('@')[:-1])
