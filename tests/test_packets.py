import pytest

from hypothesis import given
from hypothesis.strategies import binary

from unmessage import errors
from unmessage import packets
from pyaxo import b2a


def join_encode_data(lines):
    return packets.LINESEP.join([b2a(l) for l in lines])


@given(
    binary(),
    binary(),
    binary(),
    binary(),
    binary(),
)
def test_build_regular_packet(iv,
                              iv_hash,
                              payload_hash,
                              handshake_key,
                              payload):
    data = join_encode_data([iv,
                             iv_hash,
                             payload_hash,
                             handshake_key,
                             payload])
    if (len(iv) == packets.IV_LEN and
            len(iv_hash) == packets.HASH_LEN and
            len(payload_hash) == packets.HASH_LEN and
            not len(handshake_key) and
            len(payload_hash)):
        assert isinstance(packets.build_regular_packet(data),
                          packets.RegularPacket)
    else:
        with pytest.raises(errors.MalformedPacketError):
            packets.build_regular_packet(data)
