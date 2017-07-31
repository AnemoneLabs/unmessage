from twisted.internet import defer


def fake_connect(peer_in, conn_in, conn_out):
    def connect(address):
        peer_in._add_intro_manager(conn_in)
        return defer.succeed(conn_out)
    return connect


def fake_send(conn_in):
    def send(data):
        conn_in.stringReceived(data)
    return send


def attach(peer_x, peer_y, conn_x, conn_y, mocker):
    peer_x._connect = mocker.Mock(side_effect=fake_connect(peer_y, conn_y,
                                                           conn_x))
    peer_y._connect = mocker.Mock(side_effect=fake_connect(peer_x, conn_x,
                                                           conn_y))
    conn_x.send = mocker.Mock(side_effect=fake_send(conn_y))
    conn_y.send = mocker.Mock(side_effect=fake_send(conn_x))
