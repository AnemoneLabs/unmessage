from os.path import join

import pytest

from unmessage.peer import ConversationPaths, PeerPaths


@pytest.inlineCallbacks
def test_start_stop(peer_a):
    notification = yield peer_a.start(local_mode=True)
    assert str(notification) == 'Peer started'
    yield peer_a.stop()


def test_peer_paths():
    base = 'base'
    peer_name = 'pytest'
    peer_base = join(base, peer_name)
    peer_paths = PeerPaths(base, peer_name)

    assert peer_paths.base == peer_base
    assert peer_paths.peer_db == join(peer_base, 'peer.db')
    assert peer_paths.axolotl_db == join(peer_base, 'axolotl.db')
    assert peer_paths.tor_dir.base == join(peer_base, 'tor')
    assert peer_paths.tor_data_dir == join(peer_paths.tor_dir.base, 'data')
    assert peer_paths.log_file == join(peer_base, 'peer.log')
    assert peer_paths.conversations_dir == join(peer_base, 'conversations')

    other_name = 'alice'
    conv_paths = ConversationPaths(peer_paths.conversations_dir, other_name)
    assert conv_paths.base == join(peer_paths.conversations_dir, other_name)
    assert (conv_paths.file_transfer_dir.base ==
            join(conv_paths.base, 'file-transfer'))
