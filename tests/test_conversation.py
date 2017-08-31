import pytest
from twisted.internet.defer import Deferred

from unmessage import elements
from unmessage.contact import Contact
from unmessage.peer import b2a

from .utils import attach, slow


def test_conversation_request(peer_a, peer_b):
    contact_a = Contact(peer_a.identity, peer_a.identity_keys.pub)
    out_request = peer_b._create_request(contact_a)
    packet = out_request.packet

    in_request = peer_a._process_request(str(packet))
    contact_b = in_request.conversation.contact

    assert contact_b.identity == peer_b.identity
    assert contact_b.key == peer_b.identity_keys.pub


def check_established_conversation(peer_x, peer_y, conv_x, conv_y):
    assert conv_x.contact.identity == peer_y.identity
    assert conv_y.contact.identity == peer_x.identity
    assert conv_x.contact.key == peer_y.identity_keys.pub
    assert conv_y.contact.key == peer_x.identity_keys.pub
    assert conv_x.axolotl.id_ == conv_y.axolotl.id_
    assert conv_x.keys.key == conv_y.keys.key


@pytest.inlineCallbacks
def test_establish_conversation(peer_a, peer_b, mocker):
    attach(peer_a, peer_b, mocker)

    yield peer_b.send_request(peer_a.identity, b2a(peer_a.identity_keys.pub))
    yield peer_a.accept_request(peer_b.identity)

    conv_a = peer_a._conversations[peer_b.name]
    conv_b = peer_b._conversations[peer_a.name]

    check_established_conversation(peer_a, peer_b, conv_a, conv_b)


@pytest.inlineCallbacks
def test_prepare_accept_request(request_element, peer_a, peer_b, mocker):
    attach(peer_a, peer_b, mocker)

    yield peer_b.send_request(peer_a.identity, b2a(peer_a.identity_keys.pub))
    request = peer_a._inbound_requests[peer_b.identity]
    element, _ = peer_a._prepare_accept_request(request)

    assert element == request_element


@pytest.inlineCallbacks
def test_established_peers(peers):
    peer_a, peer_b, conv_a, conv_b = yield peers

    check_established_conversation(peer_a, peer_b, conv_a, conv_b)


@pytest.inlineCallbacks
def test_send_presence(peers, callback_side_effect):
    peer_a, peer_b, conv_a, conv_b = yield peers

    d_offline = Deferred()
    conv_b.ui.notify_offline = callback_side_effect(d_offline)
    d_online_a = Deferred()
    conv_a.ui.notify_online = callback_side_effect(d_online_a)
    d_online_b = Deferred()
    conv_b.ui.notify_online = callback_side_effect(d_online_b)

    peer_a.set_presence(peer_b.name, enable=True)

    yield peer_a._send_offline_presence()
    yield d_offline
    conv_a.close()
    assert not conv_a.is_active
    assert not conv_b.is_active

    peer_a._send_online_presence()
    yield d_online_a
    yield d_online_b
    assert conv_a.is_active
    assert conv_b.is_active


PRESENCE_STATUSES = {elements.PresenceElement.status_offline: True,
                     elements.PresenceElement.status_online: False}


@pytest.inlineCallbacks
@pytest.mark.parametrize('status',
                         PRESENCE_STATUSES.values(),
                         ids=PRESENCE_STATUSES.keys())
def test_prepare_presence(status, peers):
    peer_a, peer_b, conv_a, _ = yield peers

    peer_a.set_presence(peer_b.name, enable=True)

    presence_elements = peer_a._prepare_presence(status)
    peer_b_presence_element, peer_b_presence_conv = presence_elements[0]
    contents = {v: k for k, v in PRESENCE_STATUSES.items()}

    assert peer_b_presence_conv == conv_a
    assert len(presence_elements) == 1
    assert isinstance(peer_b_presence_element, elements.PresenceElement)
    assert str(peer_b_presence_element) == contents[status]


@pytest.inlineCallbacks
def test_send_message(content, peers, callback_side_effect):
    peer_a, peer_b, conv_a, conv_b = yield peers

    d = Deferred()
    conv_b.ui.notify_message = callback_side_effect(d)

    yield peer_a.send_message(conv_a, content)
    received_message = yield d
    assert str(received_message) == content


@pytest.inlineCallbacks
def test_prepare_message(message_element, content, peers):
    _, _, conv_a, _ = yield peers

    element = conv_a._prepare_message(content)
    assert element == message_element


SECRETS = {'same': ('secret', 'secret'),
           'distinct': ('secret', 'wrong secret')}


@slow
@pytest.inlineCallbacks
@pytest.mark.parametrize('secrets', SECRETS.values(), ids=SECRETS.keys())
def test_authenticate(secrets, peers, callback_side_effect):
    peer_a, peer_b, conv_a, conv_b = yield peers

    d_receive_b = Deferred()
    conv_b.ui.notify_in_authentication = callback_side_effect(d_receive_b)
    d_finish_a = Deferred()
    conv_a.ui.notify_finished_authentication = callback_side_effect(d_finish_a)
    d_finish_b = Deferred()
    conv_b.ui.notify_finished_authentication = callback_side_effect(d_finish_b)

    secret_a, secret_b = secrets
    yield peer_a.authenticate(conv_a, secret_a)
    yield d_receive_b
    yield peer_b.authenticate(conv_b, secret_b)
    yield d_finish_b
    yield d_finish_a

    authenticated = secret_a == secret_b

    assert conv_a.is_authenticated is authenticated
    assert conv_b.is_authenticated is authenticated


@pytest.inlineCallbacks
def test_prepare_authentication(peers):
    peer_a, peer_b, conv_a, _ = yield peers

    secret = 'secret'
    conv_a.init_auth()
    element, _ = peer_a._prepare_authentication(conv_a, secret)
    assert isinstance(element, elements.AuthenticationElement)


@pytest.fixture
def request_element():
    return elements.RequestElement(elements.RequestElement.request_accepted)


@pytest.fixture
def message_element(content):
    return elements.MessageElement(content)
