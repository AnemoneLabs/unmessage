import pytest

from unmessage.peer import Peer, _ConversationProtocol
from unmessage.log import begin_logging, Logger, LogLevel


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


@pytest.fixture(scope='session')
def log():
    begin_logging('/tmp/unmessage.log', LogLevel.debug)
    return Logger('pytest')
