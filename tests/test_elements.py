import pytest

from unmessage.elements import Element


def test_serialize_element_payload(element, serialized_payload):
    assert element.serialize() == serialized_payload


def test_deserialize_element_payload(content, serialized_payload):
    assert (Element.deserialize(serialized_payload) ==
            Element(content))


def test_serialize_deserialize_element_payload(element):
    assert Element.deserialize(element.serialize()) == element


@pytest.fixture
def content():
    return 'foo'


@pytest.fixture
def serialized_payload(content):
    return '{{"content": "{}"}}'.format(content)


@pytest.fixture
def element(content):
    return Element(content)
