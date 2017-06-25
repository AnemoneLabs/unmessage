from unmessage.elements import Element


CONTENT = 'foo'
SERIALIZED_ELEMENT_PAYLOAD = '{{"content": "{}"}}'.format(CONTENT)


def test_serialize_element_payload():
    e = Element(CONTENT)

    assert e.serialize() == SERIALIZED_ELEMENT_PAYLOAD


def test_deserialize_element_payload():
    assert (Element.deserialize(SERIALIZED_ELEMENT_PAYLOAD) ==
            Element(CONTENT))


def test_serialize_deserialize_element_payload():
    e0 = Element(CONTENT)
    e1 = Element.deserialize(e0.serialize())

    assert e1 == e0
