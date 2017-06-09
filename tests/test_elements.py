from unmessage.elements import ElementPayload


CONTENT = 'foo'
SERIALIZED_ELEMENT_PAYLOAD = '{{"content": "{}"}}'.format(CONTENT)


def test_serialize_element_payload():
    e = ElementPayload(CONTENT)

    assert e.serialize() == SERIALIZED_ELEMENT_PAYLOAD


def test_deserialize_element_payload():
    assert (ElementPayload.deserialize(SERIALIZED_ELEMENT_PAYLOAD) ==
            ElementPayload(CONTENT))


def test_serialize_deserialize_element_payload():
    e0 = ElementPayload(CONTENT)
    e1 = ElementPayload.deserialize(e0.serialize())

    assert e1 == e0
