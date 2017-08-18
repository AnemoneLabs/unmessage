import os

import pytest
from twisted.internet.defer import Deferred

from unmessage import elements
from unmessage.peer import b2a, FileTransfer
from pyaxo import hash_

from .utils import remove_file


@pytest.inlineCallbacks
def test_send_file(out_contents, out_hash, out_path, in_path, peers,
                   callback_side_effect):
    peer_a, peer_b, conv_a, conv_b = yield peers

    d_req_in = Deferred()
    conv_b.ui.notify_in_file_request = callback_side_effect(d_req_in)
    d_file_out = Deferred()
    conv_a.ui.notify_finished_out_file = callback_side_effect(d_file_out)
    d_file_in = Deferred()
    conv_b.ui.notify_finished_in_file = callback_side_effect(d_file_in)

    yield peer_a.send_file(peer_b.name, out_path)
    yield d_req_in
    yield peer_b.accept_file(peer_a.name, b2a(out_hash), in_path)
    yield d_file_out
    yield d_file_in

    in_contents = open(in_path, 'r').read()
    assert in_contents == out_contents
    assert hash_(in_contents) == out_hash


@pytest.inlineCallbacks
def test_prepare_file_request(out_contents, out_hash, out_path, file_name,
                              file_size, request_element, in_path, peers):
    peer_a, _, conv_a, _ = yield peers

    manager = conv_a.init_file()
    element, _ = manager.prepare_request(out_path)

    assert element == request_element


@pytest.inlineCallbacks
def test_prepare_file_accept(out_contents, out_hash, b64_out_hash, out_path,
                             file_size, file_name, request_element, transfer,
                             in_path, accept_element, peers):
    peer_a, peer_b, _, conv_b = yield peers

    manager = conv_b.init_file()
    manager.in_requests[b64_out_hash] = transfer
    element, _ = manager.prepare_accept(b64_out_hash)

    assert element == accept_element


@pytest.inlineCallbacks
def test_prepare_file(out_contents, out_hash, b64_out_hash, out_path, transfer,
                      file_element, in_path, peers):
    peer_a, peer_b, conv_a, _ = yield peers

    manager = conv_a.init_file()
    manager.out_requests[b64_out_hash] = transfer
    element, _ = manager.prepare_file(b64_out_hash)

    assert element == file_element


@pytest.fixture
def out_contents():
    return 'contents'


@pytest.fixture
def b64_out_contents(out_contents):
    return b2a(out_contents.decode('ascii'))


@pytest.fixture
def file_size(out_contents):
    return len(out_contents)


@pytest.fixture
def out_hash(out_contents):
    return hash_(out_contents)


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
def file_element(out_contents, b64_out_contents):
    return elements.FileElement(b64_out_contents)


@pytest.fixture
def transfer(request_element, b64_out_contents):
    return FileTransfer(request_element, b64_out_contents)


@pytest.fixture
def in_path():
    return '/tmp/unmessage-in-file.txt'


@pytest.fixture(autouse=True)
def setup_teardown(out_contents, out_path, in_path):
    open(out_path, 'w').write(out_contents)
    remove_file(in_path)
    yield
    remove_file(out_path)
    remove_file(in_path)
