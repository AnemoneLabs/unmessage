import pytest

from unmessage.log import begin_logging, Logger, LogLevel

from .utils import attach, create_peer


@pytest.fixture(scope='session')
def reactor():
    from twisted.internet import reactor as _reactor
    return _reactor


@pytest.fixture()
def peer_a(reactor):
    return create_peer('pytest-a', reactor)


@pytest.fixture()
def peer_b(reactor):
    return create_peer('pytest-b', reactor)


@pytest.fixture()
def peers(peer_a, peer_b, mocker):
    attach(peer_a, peer_b, mocker)
    return (peer_b._send_request(peer_a.identity, peer_a.identity_keys.pub)
            .addCallback(lambda *args: peer_a.accept_request(peer_b.identity))
            .addCallback(lambda *args: (peer_a, peer_b)))


@pytest.fixture(scope='session')
def log():
    begin_logging('/tmp/unmessage.log', LogLevel.debug)
    return Logger('pytest')
