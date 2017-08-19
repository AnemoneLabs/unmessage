import pytest
from pyaxo import hash_, a2b, b2a

from unmessage import errors
from unmessage.elements import Element, FileRequestElement, PartialElement
from unmessage.elements import ID_LENGTH, get_random_id
from unmessage.packets import ElementPacket


def test_serialize_element_payload(element, serialized_payload):
    assert element.serialize() == serialized_payload


def test_deserialize_element_payload(content, serialized_payload):
    assert (Element.deserialize(serialized_payload) ==
            Element(content))


def test_serialize_deserialize_element_payload(element):
    assert Element.deserialize(element.serialize()) == element


ELEMENT_CLASSES = Element.__subclasses__()
ELEMENT_CLASSES_IDS = [cls.__name__ for cls in ELEMENT_CLASSES]


@pytest.mark.parametrize('cls', ELEMENT_CLASSES, ids=ELEMENT_CLASSES_IDS)
def test_element_factory(cls,
                         serialized_payload, file_request_serialized_payload):
    if cls is FileRequestElement:
        payload = file_request_serialized_payload
    else:
        payload = serialized_payload
    e = Element.build(cls.type_, payload)
    assert isinstance(e, cls)
    assert e.serialize() == payload


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


def test_element_id(id_):
    assert len(a2b(id_)) == ID_LENGTH


def test_get_random_element_id():
    id_0 = get_random_id()
    id_1 = get_random_id()
    assert id_1 != id_0


@pytest.fixture
def serialized_payload(content):
    return '{{"content": "{}"}}'.format(content)


@pytest.fixture
def file_size():
    return 1


@pytest.fixture
def file_checksum():
    return b2a(hash_(''))


@pytest.fixture
def file_request_serialized_payload(content, file_size, file_checksum):
    return ('{{'
            '"content": "{}", '
            '"checksum": "{}", '
            '"size": {}'
            '}}'.format(content, file_checksum, file_size))


@pytest.fixture
def element(content):
    return Element(content)


@pytest.fixture
def id_():
    return get_random_id()


@pytest.fixture
def packet(element, id_):
    return ElementPacket(element.type_, element.serialize(), id_)
