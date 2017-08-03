import pytest
from twisted.internet import defer

from unmessage.peer import Peer, _ConversationProtocol


slow_help = 'run slow tests'
slow_option = '--run-slow'


def create_peer(name, reactor):
    return Peer(name, reactor)


def create_connection(peer):
    return _ConversationProtocol(peer._twisted_factory)


def fake_send(conn_in):
    def send(data):
        conn_in.stringReceived(data)
    return send


def fake_connect(peer_in, peer_out, mocker):
    def connect(address):
        conn_in = create_connection(peer_in)
        conn_out = create_connection(peer_out)

        conn_in.transport = mocker.Mock()
        conn_out.transport = mocker.Mock()

        conn_in.transport.loseConnection = mocker.Mock(
            side_effect=lambda: conn_out.connectionLost(None))
        conn_in.transport.loseConnection = mocker.Mock(
            side_effect=lambda: conn_in.connectionLost(None))

        conn_in.send = mocker.Mock(side_effect=fake_send(conn_out))
        conn_out.send = mocker.Mock(side_effect=fake_send(conn_in))

        peer_in._add_intro_manager(conn_in)

        return defer.succeed(conn_out)
    return connect


def attach(peer_x, peer_y, mocker):
    peer_x._connect = mocker.Mock(side_effect=fake_connect(peer_y, peer_x,
                                                           mocker))
    peer_y._connect = mocker.Mock(side_effect=fake_connect(peer_x, peer_y,
                                                           mocker))
