import re
from collections import namedtuple

import attr


Address = namedtuple('Address', 'host port')


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
