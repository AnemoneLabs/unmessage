import pytest
from twisted.internet import defer

from unmessage.contact import Contact
from unmessage.peer import b2a, Conversation, Peer

from .utils import attach


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
def test_establish_conversation(peer_a, peer_b, conn_a, conn_b, mocker):
    attach(peer_a, peer_b, conn_a, conn_b, mocker)

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
