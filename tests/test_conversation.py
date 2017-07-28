import pytest

from unmessage.contact import Contact
from unmessage.peer import Peer


def test_conversation_request(peer_a, peer_b):
    contact_a = Contact(peer_a.identity, peer_a.identity_keys.pub)
    out_request = peer_b._create_request(contact_a)
    packet = out_request.packet

    in_request = peer_a._process_request(str(packet))
    contact_b = in_request.conversation.contact

    assert contact_b.identity == peer_b.identity
    assert contact_b.key == peer_b.identity_keys.pub
