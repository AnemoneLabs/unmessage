import pytest

from unmessage import errors
from unmessage.elements import Element, PartialElement, get_random_id
from unmessage.packets import ElementPacket


def test_serialize_element_payload(element, serialized_payload):
    assert element.serialize() == serialized_payload


def test_deserialize_element_payload(content, serialized_payload):
    assert (Element.deserialize(serialized_payload) ==
            Element(content))


def test_serialize_deserialize_element_payload(element):
    assert Element.deserialize(element.serialize()) == element


def test_single_partial_from_element(element, id_):
    partial = PartialElement.from_element(element, id_)
    assert partial.to_element() == element


def test_multi_partial_from_element(element):
    with pytest.raises(Exception):
        PartialElement.from_element(element, max_len=1)


def test_partial_to_packets(element, id_, packet):
    partial = PartialElement.from_element(element, id_)
    packets = partial.to_packets()
    assert len(packets) == 1
    assert packets[0] == packet


def test_partial_from_packet(element, packet):
    partial = PartialElement.from_packet(packet)
    assert len(partial) == packet.part_len
    assert partial.to_element() == element


def test_incomplete_partial_from_packet(packet):
    packet.part_len = 2
    partial = PartialElement.from_packet(packet)
    with pytest.raises(errors.IncompleteElementError):
        str(partial)
    with pytest.raises(errors.IncompleteElementError):
        partial.to_packets()


@pytest.fixture
def content():
    return 'foo'


@pytest.fixture
def serialized_payload(content):
    return '{{"content": "{}"}}'.format(content)


@pytest.fixture
def element(content):
    return Element(content)


@pytest.fixture
def id_():
    return get_random_id()


@pytest.fixture
def packet(element, id_):
    return ElementPacket(element.type_, element.serialize(), id_)
