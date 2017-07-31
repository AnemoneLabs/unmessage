import pytest

from unmessage.peer import Peer, _ConversationProtocol
from unmessage.log import begin_logging, Logger, LogLevel


@pytest.fixture(scope='session')
def reactor():
    from twisted.internet import reactor as _reactor
    return _reactor


@pytest.fixture()
def peer_a(reactor):
    return Peer('pytest-a', reactor)


@pytest.fixture()
def peer_b(reactor):
    return Peer('pytest-b', reactor)


@pytest.fixture()
def conn_a(peer_a):
    return _ConversationProtocol(peer_a._twisted_factory)


@pytest.fixture()
def conn_b(peer_b):
    return _ConversationProtocol(peer_b._twisted_factory)


@pytest.fixture(scope='session')
def log():
    begin_logging('/tmp/unmessage.log', LogLevel.debug)
    return Logger('pytest')
