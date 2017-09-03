import pytest

from unmessage.log import begin_logging, Logger, LogLevel

from .utils import attach, create_peer
from .utils import slow, slow_help, slow_option


def skipif_option(option):
    return pytest.mark.skipif(not pytest.config.getoption(option),
                              reason='need {} option to run'.format(option))


def pytest_collection_modifyitems(items):
    for item in items:
        if slow.name in item.keywords:
            item.add_marker(skipif_option(slow_option))


def pytest_addoption(parser):
    parser.addoption(slow_option, action='store_true', help=slow_help)


@pytest.fixture
def callback_side_effect(mocker):
    def side_effect(d):
        return mocker.Mock(side_effect=lambda *args: d.callback(*args))
    return side_effect


@pytest.fixture(scope='session')
def reactor():
    from twisted.internet import reactor as _reactor
    return _reactor


@pytest.fixture
def peer_a(reactor):
    return create_peer('pytest-a', reactor)


@pytest.fixture
def peer_b(reactor):
    return create_peer('pytest-b', reactor)


@pytest.fixture
def peers(peer_a, peer_b, mocker):
    attach(peer_a, peer_b, mocker)
    return (peer_b._send_request(peer_a.identity, peer_a.identity_keys.pub)
            .addCallback(lambda *args: peer_a.accept_request(peer_b.identity))
            .addCallback(lambda *args: (peer_a, peer_b)))


@pytest.fixture
def peers_conversations(peers):
    return peers.addCallback(
        lambda (peer_a, peer_b): (peer_a,
                                  peer_b,
                                  peer_a._conversations[peer_b.name],
                                  peer_b._conversations[peer_a.name]))


@pytest.fixture
def conversations(peers):
    return peers.addCallback(
        lambda (peer_a, peer_b): (peer_a._conversations[peer_b.name],
                                  peer_b._conversations[peer_a.name]))


@pytest.fixture
def content():
    return 'foo'


@pytest.fixture(scope='session')
def log():
    begin_logging('/tmp/unmessage.log', LogLevel.debug)
    return Logger('pytest')
