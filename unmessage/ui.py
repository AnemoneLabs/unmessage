from functools import wraps

from twisted.internet.defer import Deferred

from . import errors


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

    def notify_in_file_request(self, notification):
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

    def notify_conv_established(self, notification):
        pass


def displays_error(f, display):
    @wraps(f)
    def wrapped_f(self, *args, **kwargs):
        try:
            result = f(self, *args, **kwargs)
        except Exception as e:
            display(self, errors.to_unmessage_error(e))
        else:
            if isinstance(result, Deferred):
                value = Deferred()
                result.addErrback(
                    lambda failure: display(
                        self,
                        errors.to_unmessage_error(failure)))
                result.addCallbacks(value.callback, value.errback)
            else:
                value = result
            return value
    return wrapped_f


def displays_result(f, display):
    @wraps(f)
    def wrapped_f(self, *args, **kwargs):
        def _display(r):
            if r is not None:
                display(self, r)
            return r

        result = f(self, *args, **kwargs)
        if isinstance(result, Deferred):
            value = Deferred()
            result.addCallback(_display)
            result.addCallbacks(value.callback, value.errback)
        else:
            _display(result)
            value = result
        return value
    return wrapped_f
