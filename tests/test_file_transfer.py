import os

import pytest
from twisted.internet.defer import Deferred

from unmessage import elements
from unmessage.peer import b2a, FileTransfer, MAX_ELEMENT_LEN
from pyaxo import hash_

from .utils import remove_file


@pytest.inlineCallbacks
def test_send_file(out_content, out_hash, b64_out_hash, out_path, in_path,
                   conversations, callback_side_effect):
    conv_a, conv_b = yield conversations

    d_req_in = Deferred()
    conv_b.ui.notify_in_file_request = callback_side_effect(d_req_in)
    d_file_out = Deferred()
    conv_a.ui.notify_finished_out_file = callback_side_effect(d_file_out)
    d_file_in = Deferred()
    conv_b.ui.notify_finished_in_file = callback_side_effect(d_file_in)

    yield conv_a.send_file(out_path)
    yield d_req_in
    yield conv_b.accept_file(b64_out_hash, in_path)
    yield d_file_out
    yield d_file_in

    in_content = open(in_path, 'r').read()
    assert in_content == out_content
    assert hash_(in_content) == out_hash


@pytest.inlineCallbacks
def test_prepare_file_request(out_path, request_element, conversations):
    conv_a, _ = yield conversations

    manager = conv_a.init_file()
    element, _ = manager.prepare_request(out_path)

    assert element == request_element


@pytest.inlineCallbacks
def test_prepare_file_accept(b64_out_hash, transfer, accept_element,
                             conversations):
    _, conv_b = yield conversations

    manager = conv_b.init_file()
    manager.in_requests[b64_out_hash] = transfer
    element, _ = manager.prepare_accept(b64_out_hash)

    assert element == accept_element


@pytest.inlineCallbacks
def test_prepare_file(b64_out_hash, transfer, file_element, conversations):
    conv_a, _ = yield conversations

    manager = conv_a.init_file()
    manager.out_requests[b64_out_hash] = transfer
    element, _ = manager.prepare_file(b64_out_hash)

    assert element == file_element

CONTENTS = {'short': lambda c: c,
            'long': lambda c: MAX_ELEMENT_LEN * 2 / len(c) * c}


@pytest.fixture(params=CONTENTS.values(), ids=CONTENTS.keys())
def out_content(request, content):
    return request.param(content)


@pytest.fixture
def b64_out_content(out_content):
    return b2a(out_content.decode('ascii'))


@pytest.fixture
def file_size(out_content):
    return len(out_content)


@pytest.fixture
def out_hash(out_content):
    return hash_(out_content)


@pytest.fixture
def b64_out_hash(out_hash):
    return b2a(out_hash)


@pytest.fixture
def out_path():
    return '/tmp/unmessage-out-file.txt'


@pytest.fixture
def file_name(out_path):
    return os.path.split(out_path)[1]


@pytest.fixture
def request_element(file_name, file_size, out_hash):
    return elements.FileRequestElement(file_name,
                                       size=file_size,
                                       checksum=b2a(out_hash))


@pytest.fixture
def accept_element(out_hash):
    return elements.FileRequestElement(
        elements.FileRequestElement.request_accepted,
        checksum=b2a(out_hash))


@pytest.fixture
def file_element(out_content, b64_out_content):
    return elements.FileElement(b64_out_content)


@pytest.fixture
def transfer(request_element, b64_out_content):
    return FileTransfer(request_element, b64_out_content)


@pytest.fixture
def in_path():
    return '/tmp/unmessage-in-file.txt'


@pytest.fixture(autouse=True)
def setup_teardown(out_content, out_path, in_path):
    open(out_path, 'w').write(out_content)
    remove_file(in_path)
    yield
    remove_file(out_path)
    remove_file(in_path)
