import pytest
from twisted.internet import defer
from twisted.internet.defer import Deferred

from unmessage.contact import Contact
from unmessage.peer import b2a, Conversation, Peer

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
def test_established_peers(peers):
    peer_a, peer_b = yield peers
    conv_a = peer_a._conversations[peer_b.name]
    conv_b = peer_b._conversations[peer_a.name]

    check_established_conversation(peer_a, peer_b, conv_a, conv_b)


@pytest.inlineCallbacks
def test_send_message(peers, callback_side_effect):
    peer_a, peer_b = yield peers
    conv_a = peer_a._conversations[peer_b.name]
    conv_b = peer_b._conversations[peer_a.name]

    d = Deferred()
    conv_b.ui.notify_message = callback_side_effect(d)

    sent_message = 'message'
    yield peer_a.send_message(peer_b.name, sent_message)
    received_message = yield d
    assert str(received_message) == sent_message


SECRETS = [['secret', 'secret'],
           ['secret', 'wrong secret']]
SECRETS_IDS = ['same', 'distinct']


@slow
@pytest.inlineCallbacks
@pytest.mark.parametrize('secrets', SECRETS, ids=SECRETS_IDS)
def test_authenticate(secrets, peers, callback_side_effect):
    peer_a, peer_b = yield peers
    conv_a = peer_a._conversations[peer_b.name]
    conv_b = peer_b._conversations[peer_a.name]

    d_receive_b = Deferred()
    conv_b.ui.notify_in_authentication = callback_side_effect(d_receive_b)
    d_finish_a = Deferred()
    conv_a.ui.notify_finished_authentication = callback_side_effect(d_finish_a)
    d_finish_b = Deferred()
    conv_b.ui.notify_finished_authentication = callback_side_effect(d_finish_b)

    secret_a, secret_b = secrets
    yield peer_a.authenticate(peer_b.name, secret_a)
    yield d_receive_b
    yield peer_b.authenticate(peer_a.name, secret_b)
    yield d_finish_b
    yield d_finish_a

    authenticated = secret_a == secret_b

    assert conv_a.is_authenticated is authenticated
    assert conv_b.is_authenticated is authenticated
