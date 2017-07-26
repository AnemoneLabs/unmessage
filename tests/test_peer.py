import pytest

from unmessage.peer import Peer


@pytest.inlineCallbacks
def test_start_stop(reactor):
    peer = Peer.from_disk('pytest', reactor)
    notification = yield peer.start(local_mode=True)
    assert str(notification) == 'Peer started'
    yield peer.stop()
