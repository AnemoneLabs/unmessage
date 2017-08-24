import json

import attr
import pytest

from unmessage.utils import Serializable


ATTRIBUTE = 'attribute'
FILTERED_OUT_ATTRIBUTE = 'filtered_out_attribute'
VALUE = 'value'


def test_serialize(simple_serializable, serialized):
    assert simple_serializable.serialize() == serialized


def test_deserialize(serialized):
    assert (SimpleSerializable.deserialize(serialized) ==
            SimpleSerializable(VALUE))


def test_serialize_deserialize(simple_serializable):
    assert (SimpleSerializable.deserialize(simple_serializable.serialize()) ==
            simple_serializable)


def test_serialize_filtered(filtered_serializable, serialized):
    assert filtered_serializable.serialize() == serialized


@attr.s
class Attribute(object):
    name = attr.ib()


ATTRIBUTES = {ATTRIBUTE: Attribute(ATTRIBUTE),
              FILTERED_OUT_ATTRIBUTE: Attribute(FILTERED_OUT_ATTRIBUTE)}


@pytest.mark.parametrize('attribute',
                         ATTRIBUTES.values(),
                         ids=ATTRIBUTES.keys())
def test_filter(attribute, filtered_serializable):
    assert (filtered_serializable.filter_attrs(attribute) is
            (attribute.name in filtered_serializable.filtered_attr_names))


@attr.s
class SimpleSerializable(Serializable):
    attribute = attr.ib()


@pytest.fixture
def simple_serializable():
    return SimpleSerializable(VALUE)


@attr.s
class FilteredSerializable(SimpleSerializable):
    filtered_attr_names = [ATTRIBUTE]

    filtered_out_attribute = attr.ib(default=None)


@pytest.fixture
def filtered_serializable():
    return FilteredSerializable(VALUE, VALUE)


@pytest.fixture
def serialized():
    return json.dumps({ATTRIBUTE: VALUE})
