import pytest

from unmessage.peer import Peer


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
