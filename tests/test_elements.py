import json
from math import ceil

import pytest
from hypothesis import example, given
from hypothesis.strategies import integers
from pyaxo import hash_, a2b, b2a

from unmessage import errors
from unmessage.elements import Element, FileRequestElement, PartialElement
from unmessage.elements import ID_LENGTH, get_random_id
from unmessage.packets import ElementPacket
from unmessage.peer import MAX_ELEMENT_LEN


ELEMENT_CLASSES = {cls.__name__: cls for cls in Element.__subclasses__()}


@pytest.mark.parametrize('cls',
                         ELEMENT_CLASSES.values(),
                         ids=ELEMENT_CLASSES.keys())
def test_element_factory(cls,
                         serialized_payload, file_request_serialized_payload):
    if cls is FileRequestElement:
        payload = file_request_serialized_payload
    else:
        payload = serialized_payload
    e = Element.build(cls.type_, payload)
    assert isinstance(e, cls)
    assert e.serialize() == payload


def test_element_factory_unknown_type(serialized_payload):
    with pytest.raises(errors.UnknownElementError):
        Element.build('unknown', serialized_payload)


@given(integers(min_value=4, max_value=MAX_ELEMENT_LEN))
@example(0)
@example(4)
@example(10)
@example(MAX_ELEMENT_LEN)
def test_partial_from_element(element, id_, max_len):
    packets = to_packets(max_len, element, id_, element.serialize())
    partial = PartialElement.from_element(element, id_, max_len)
    assert partial.id_ == id_
    assert partial.part_total == len(packets)
    assert len(partial) == partial.part_total
    assert partial.to_element() == element


@given(integers(min_value=4, max_value=MAX_ELEMENT_LEN))
@example(0)
@example(4)
@example(10)
@example(MAX_ELEMENT_LEN)
def test_partial_to_packets(element, id_, max_len):
    packets = to_packets(max_len, element, id_, element.serialize())
    partial = PartialElement.from_element(element, id_, max_len)
    assert partial.to_packets() == packets


def test_partial_from_packet(element, id_, packets):
    for packet in packets:
        partial = PartialElement.from_packet(packet)
        assert partial.type_ == element.type_
        assert partial.id_ == id_
        assert packet.part_total == len(packets)
        assert len(partial) == 1
        assert partial.keys()[0] == packet.part_num


def test_partial_from_packets(element, id_, packets):
    partial = None
    for packet in packets:
        if partial is None:
            partial = PartialElement.from_packet(packet)
        else:
            partial.add_packet(packet)
        assert partial[packet.part_num] == packet.payload
    assert partial.to_element() == element


def test_incomplete_partial_from_packet(packets):
    if len(packets) > 1:
        partial = PartialElement.from_packet(packets[0])
        with pytest.raises(errors.IncompleteElementError):
            str(partial)
        with pytest.raises(errors.IncompleteElementError):
            partial.to_packets()


def test_element_id(id_):
    assert len(a2b(id_)) == ID_LENGTH


def test_get_random_element_id():
    id_0 = get_random_id()
    id_1 = get_random_id()
    assert id_1 != id_0


@pytest.fixture
def serialized_payload(content):
    return json.dumps({'content': content})


@pytest.fixture
def file_size():
    return 1


@pytest.fixture
def file_checksum():
    return b2a(hash_(''))


@pytest.fixture
def file_request_serialized_payload(content, file_checksum, file_size):
    return json.dumps({'content': content,
                       'checksum': file_checksum,
                       'size': file_size})


@pytest.fixture
def element(content):
    return Element(content)


@pytest.fixture
def id_():
    return get_random_id()


MAX_ELEMENT_LENS = [0, 4, 10, MAX_ELEMENT_LEN]


@pytest.fixture(params=MAX_ELEMENT_LENS)
def packets(request, element, id_, serialized_payload):
    return to_packets(request.param, element, id_, serialized_payload)


def to_packets(max_len, element, id_, serialized_payload):
    element_packets = list()
    part_len = max_len / 4 * 3 if max_len else len(serialized_payload)
    part_total = int(ceil(float(len(serialized_payload)) / part_len))
    for part_num in range(part_total):
        start = part_num * part_len
        element_packets.append(
            ElementPacket(element.type_, id_, part_num, part_total,
                          payload=serialized_payload[start:start+part_len]))
    return element_packets
