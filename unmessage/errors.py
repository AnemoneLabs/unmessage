class UnmessageError(Exception):
    def __init__(self, message, title=None):
        super(UnmessageError, self).__init__()
        self.title = title or 'unMessage error'
        self.message = message


class UntalkError(UnmessageError):
    def __init__(self, message, title=None):
        super(UntalkError, self).__init__(
            message,
            title or 'unTalk error')


class ConnectionLostError(UnmessageError):
    def __init__(self, contact):
        super(ConnectionLostError, self).__init__(
            title='Connection lost',
            message='The connection to {} has been lost'.format(contact))


class CorruptedPacketError(UnmessageError):
    def __init__(self, packet_type):
        super(CorruptedPacketError, self).__init__(
            title='Corrupted packet error',
            message='The packet integrity check failed')


class CursesScreenResizedError(UnmessageError):
    def __init__(self):
        super(CursesScreenResizedError, self).__init__(
            title='Curses screen resized',
            message='The curses screen has been resized')


class OfflinePeerError(UnmessageError):
    def __init__(self, title, contact, is_request=False):
        message = "{} is offline".format(contact)
        if is_request:
            message += ' or such Onion Service does not exist'

        super(OfflinePeerError, self).__init__(
            title=title,
            message=message)


class InvalidIdentityError(UnmessageError):
    def __init__(self):
        super(InvalidIdentityError, self).__init__(
            title='Value error',
            message='The identity provided is not valid')


class InvalidPublicKeyError(UnmessageError):
    def __init__(self):
        super(InvalidPublicKeyError, self).__init__(
            title='Value error',
            message='The public key provided is not valid')


class InvalidNameError(UnmessageError):
    def __init__(self):
        super(InvalidNameError, self).__init__(
            title='Value error',
            message='The name provided is not valid')


class MalformedPacketError(UnmessageError):
    def __init__(self, packet_type):
        super(MalformedPacketError, self).__init__(
            title='Malformed packet error',
            message='The data provided cannot be used to build a '
                    '{} packet'.format(packet_type))


class TransportError(UnmessageError):
    def __init__(self, message):
        super(TransportError, self).__init__(
            title='Transport error',
            message=message)


class UnknownContactError(UnmessageError):
    def __init__(self, contact):
        super(UnknownContactError, self).__init__(
            title='Unknown contact error',
            message='There is no contact called "{}"'.format(contact))


class VerificationError(UnmessageError):
    def __init__(self, contact):
        super(VerificationError, self).__init__(
            title='Key verification error',
            message="The key provided does not match {}'s!".format(contact))
