class UnmessageError(Exception):
    def __init__(self, message, title=None):
        super(UnmessageError, self).__init__()
        self.title = title or 'unMessage error'
        self.message = message


class ConnectionLostError(UnmessageError):
    def __init__(self, contact):
        super(ConnectionLostError, self).__init__(
            title='Connection lost',
            message='The connection to {} has been lost'.format(contact))


class CorruptedPacketError(UnmessageError):
    def __init__(self, packet_type):
        super(MalformedPacketError, self).__init__(
            title='Corrupted packet error',
            message='The packet integrity check failed')


class CursesScreenResizedError(UnmessageError):
    def __init__(self):
        super(CursesScreenResizedError, self).__init__(
            title='Curses screen resized',
            message='The curses screen has been resized')


class HostUnreachableError(UnmessageError):
    def __init__(self):
        super(HostUnreachableError, self).__init__(
            title='Host unreachable',
            message="The other party's Onion Service is not online or has not "
                    'been established yet - try again in a minute')


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
