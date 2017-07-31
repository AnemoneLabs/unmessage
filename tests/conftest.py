import pytest

from unmessage.peer import Peer, _ConversationProtocol
from unmessage.log import begin_logging, Logger, LogLevel

from .utils import attach


@pytest.fixture(scope='session')
def reactor():
    from twisted.internet import reactor as _reactor
    return _reactor


def create_peer(name, reactor):
    return Peer(name, reactor)


@pytest.fixture()
def peer_a(reactor):
    return create_peer('pytest-a', reactor)


@pytest.fixture()
def peer_b(reactor):
    return create_peer('pytest-b', reactor)


def create_connection(peer):
    return _ConversationProtocol(peer._twisted_factory)


@pytest.fixture()
def conn_a(peer_a):
    return create_connection(peer_a)


@pytest.fixture()
def conn_b(peer_b):
    return create_connection(peer_b)


@pytest.fixture()
def peers(peer_a, peer_b, conn_a, conn_b, mocker):
    attach(peer_a, peer_b, conn_a, conn_b, mocker)
    return (peer_b._send_request(peer_a.identity, peer_a.identity_keys.pub)
            .addCallback(lambda *args: peer_a.accept_request(peer_b.identity))
            .addCallback(lambda *args: (peer_a, peer_b)))


@pytest.fixture(scope='session')
def log():
    begin_logging('/tmp/unmessage.log', LogLevel.debug)
    return Logger('pytest')
