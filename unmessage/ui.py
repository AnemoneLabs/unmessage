class _Ui(object):
    def notify(self, notification):
        pass

    def notify_error(self, error):
        pass


class ConversationUi(_Ui):
    def notify_disconnect(self, notification):
        pass

    def notify_offline(self, notification):
        pass

    def notify_online(self, notification):
        pass

    def notify_message(self, notification):
        pass

    def notify_in_authentication(self, notification):
        pass

    def notify_out_authentication(self, notification):
        pass

    def notify_finished_authentication(self, notification):
        pass


class PeerUi(_Ui):
    def notify_bootstrap(self, notification):
        pass

    def notify_peer_started(self, notification):
        pass

    def notify_peer_failed(self, notification):
        pass

    def notify_in_request(self, notification):
        pass

    def notify_out_request(self, notification):
        pass

    def notify_conv_established(self, notification):
        pass
