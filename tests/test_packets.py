import pytest

from hypothesis import example, given
from hypothesis.strategies import binary

from nacl.utils import random
from unmessage import errors
from unmessage import packets
from pyaxo import b2a


CORRECT_LEN_IV = random(packets.IV_LEN)
CORRECT_LEN_HASH = random(packets.HASH_LEN)
CORRECT_LEN_KEY = random(packets.KEY_LEN)
CORRECT_LEN_ENC_KEY = random(packets.ENC_KEY_LEN)
CORRECT_LEN_PAYLOAD = random(1)
CORRECT_LEN_HANDSHAKE_PACKET = random(1)


def join_encode_data(lines):
    return packets.LINESEP.join([b2a(l) for l in lines])


@given(
    binary(),
    binary(),
    binary(),
    binary(),
    binary(),
)
@example(
    CORRECT_LEN_IV,
    CORRECT_LEN_HASH,
    CORRECT_LEN_HASH,
    '',
    CORRECT_LEN_PAYLOAD,
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
            len(payload)):
        assert isinstance(packets.build_regular_packet(data),
                          packets.RegularPacket)
    else:
        with pytest.raises(errors.MalformedPacketError):
            packets.build_regular_packet(data)


@given(
    binary(),
    binary(),
    binary(),
    binary(),
    binary(),
)
@example(
    CORRECT_LEN_IV,
    CORRECT_LEN_HASH,
    CORRECT_LEN_HASH,
    CORRECT_LEN_ENC_KEY,
    CORRECT_LEN_PAYLOAD,
)
def test_build_reply_packet(iv,
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
            len(handshake_key) == packets.ENC_KEY_LEN and
            len(payload)):
        assert isinstance(packets.build_reply_packet(data),
                          packets.RegularPacket)
    else:
        with pytest.raises(errors.MalformedPacketError):
            packets.build_reply_packet(data)


@given(
    binary(),
    binary(),
    binary(),
    binary(),
    binary(),
)
@example(
    CORRECT_LEN_IV,
    CORRECT_LEN_HASH,
    CORRECT_LEN_HASH,
    CORRECT_LEN_KEY,
    CORRECT_LEN_HANDSHAKE_PACKET,
)
def test_build_request_packet(iv,
                              iv_hash,
                              handshake_packet_hash,
                              request_key,
                              handshake_packet):
    data = join_encode_data([iv,
                             iv_hash,
                             handshake_packet_hash,
                             request_key,
                             handshake_packet])
    if (len(iv) == packets.IV_LEN and
            len(iv_hash) == packets.HASH_LEN and
            len(handshake_packet_hash) == packets.HASH_LEN and
            len(request_key) == packets.KEY_LEN and
            len(handshake_packet)):
        assert isinstance(packets.build_request_packet(data),
                          packets.RequestPacket)
    else:
        with pytest.raises(errors.MalformedPacketError):
            packets.build_request_packet(data)
