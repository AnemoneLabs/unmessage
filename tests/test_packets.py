import pytest

from hypothesis import assume, example, given
from hypothesis.strategies import binary, integers, text

from nacl.utils import random
from unmessage import errors
from unmessage import packets
from pyaxo import a2b, b2a
from twisted.python.compat import nativeString


CORRECT_LEN_INTRO_DATA = random(1)
CORRECT_LEN_IV = random(packets.IV_LEN)
CORRECT_LEN_HASH = random(packets.HASH_LEN)
CORRECT_LEN_KEY = random(packets.KEY_LEN)
CORRECT_LEN_ENC_KEY = random(packets.ENC_KEY_LEN)
CORRECT_LEN_PAYLOAD = random(1)
CORRECT_LEN_HANDSHAKE_PACKET = random(1)
CORRECT_LEN_IDENTITY = random(1)


def is_ascii_encodable(value):
    try:
        nativeString(value)
    except (TypeError, UnicodeError):
        return False
    else:
        return True


@given(
    text(),
    integers(),
)
@example(
    b2a(random(1)),
    1,
)
@example(
    b2a(random(1)),
    2,
)
def test_is_valid_b64_length(value, length):
    assume(is_ascii_encodable(value))

    ascii_value = nativeString(value)
    try:
        byte_value = a2b(ascii_value)
    except TypeError:
        assert not packets.is_valid_length(ascii_value, length)
    else:
        assert (packets.is_valid_length(ascii_value, length) is
                (len(byte_value) == length))


@given(
    text(),
)
@example(
    b2a(random(1)),
)
@example(
    '',
)
def test_is_valid_non_empty_b64(value):
    assume(is_ascii_encodable(value))

    ascii_value = nativeString(value)
    try:
        byte_value = a2b(ascii_value)
    except TypeError:
        assert not packets.is_valid_non_empty(ascii_value)
    else:
        assert packets.is_valid_non_empty(ascii_value) is (len(byte_value) > 0)


LEN_VALIDATORS = {v[0].__name__: v
                  for v in [(packets.is_valid_iv, packets.IV_LEN),
                            (packets.is_valid_key, packets.KEY_LEN),
                            (packets.is_valid_enc_key, packets.ENC_KEY_LEN),
                            (packets.is_valid_hash, packets.HASH_LEN),
                            (packets.is_valid_empty, 0)]}


@given(
    text(),
)
@example(
    b2a(random(packets.IV_LEN)),
)
@example(
    b2a(random(packets.KEY_LEN)),
)
@example(
    b2a(random(packets.ENC_KEY_LEN)),
)
@example(
    b2a(random(packets.HASH_LEN)),
)
@example(
    '',
)
@pytest.mark.parametrize(('validator', 'length'),
                         LEN_VALIDATORS.values(),
                         ids=LEN_VALIDATORS.keys())
def test_length_validators(validator, length, value):
    assume(is_ascii_encodable(value))

    ascii_value = nativeString(value)
    try:
        byte_value = a2b(ascii_value)
    except TypeError:
        assert not validator(ascii_value)
    else:
        assert validator(ascii_value) is (len(byte_value) == length)


def join_encode_data(lines):
    return packets.LINESEP.join([b2a(l) for l in lines])


@given(
    binary(),
    binary(),
    binary(),
)
@example(
    CORRECT_LEN_IV,
    CORRECT_LEN_HASH,
    CORRECT_LEN_INTRO_DATA,
)
def test_build_intro_packet(iv,
                            iv_hash,
                            data):
    data = join_encode_data([iv,
                             iv_hash,
                             data])
    if (len(iv) == packets.IV_LEN and
            len(iv_hash) == packets.HASH_LEN and
            len(data)):
        assert isinstance(packets.IntroductionPacket.build(data),
                          packets.IntroductionPacket)
    else:
        with pytest.raises(errors.MalformedPacketError):
            packets.IntroductionPacket.build(data)


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
        assert isinstance(packets.RegularPacket.build(data),
                          packets.RegularPacket)
    else:
        with pytest.raises(errors.MalformedPacketError):
            packets.RegularPacket.build(data)


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
        assert isinstance(packets.ReplyPacket.build(data),
                          packets.ReplyPacket)
    else:
        with pytest.raises(errors.MalformedPacketError):
            packets.ReplyPacket.build(data)


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
        assert isinstance(packets.RequestPacket.build(data),
                          packets.RequestPacket)
    else:
        with pytest.raises(errors.MalformedPacketError):
            packets.RequestPacket.build(data)


@given(
    binary(),
    binary(),
    binary(),
    binary(),
)
@example(
    CORRECT_LEN_IDENTITY,
    CORRECT_LEN_KEY,
    CORRECT_LEN_KEY,
    CORRECT_LEN_KEY,
)
def test_build_handshake_packet(identity,
                                identity_key,
                                handshake_key,
                                ratchet_key):
    data = join_encode_data([identity,
                             identity_key,
                             handshake_key,
                             ratchet_key])
    if (len(identity) and
            len(identity_key) == packets.KEY_LEN and
            len(handshake_key) == packets.KEY_LEN and
            len(ratchet_key) == packets.KEY_LEN):
        assert isinstance(packets.HandshakePacket.build(data),
                          packets.HandshakePacket)
    else:
        with pytest.raises(errors.MalformedPacketError):
            packets.HandshakePacket.build(data)
