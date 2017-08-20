from twisted.python.failure import Failure


class UnmessageError(Exception):
    def __init__(self, message, title=None):
        super(UnmessageError, self).__init__()
        self.title = title or 'unMessage error'
        self.message = message

    def __str__(self):
        return self.message


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


class InactiveManagerError(UnmessageError):
    def __init__(self, contact):
        super(InactiveManagerError, self).__init__(
            title='Inactive manager error',
            message=('This feature cannot be used without a connection to '
                     '{}'.format(contact)))


class IncompleteElementError(UnmessageError):
    def __init__(self):
        super(IncompleteElementError, self).__init__(
            title='Incomplete element error',
            message=('The partial element does not contain enough parts to '
                     'create a complete element'))


class InvalidElementError(UnmessageError):
    def __init__(self):
        super(InvalidElementError, self).__init__(
            title='Invalid element error',
            message='The element provided is not valid')


class InvalidFileNameError(UnmessageError):
    def __init__(self):
        super(InvalidFileNameError, self).__init__(
            title='Invalid file name error',
            message='The file name provided is not valid')


class InvalidIdentityError(UnmessageError):
    def __init__(self):
        super(InvalidIdentityError, self).__init__(
            title='Value error',
            message='The identity provided is not valid')


class InvalidPrivateKeyError(UnmessageError):
    def __init__(self):
        super(InvalidPrivateKeyError, self).__init__(
            title='Value error',
            message='The private key provided is not valid')


class InvalidPublicKeyError(UnmessageError):
    def __init__(self):
        super(InvalidPublicKeyError, self).__init__(
            title='Value error',
            message='The public key provided is not valid')


class InvalidSharedKeyError(UnmessageError):
    def __init__(self):
        super(InvalidSharedKeyError, self).__init__(
            title='Value error',
            message='The shared key provided is not valid')


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


class ManagerNotFoundError(UnmessageError):
    def __init__(self, type_):
        super(ManagerNotFoundError, self).__init__(
            title='Manager not found error',
            message='A manager for {} could not be found'.format(type_))


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


class UnknownElementError(UnmessageError):
    def __init__(self, type_):
        super(UnknownElementError, self).__init__(
            title='Unknown element error',
            message='The element type "{}" is unknown'.format(type_))


class VerificationError(UnmessageError):
    def __init__(self, contact):
        super(VerificationError, self).__init__(
            title='Key verification error',
            message="The key provided does not match {}'s!".format(contact))


def to_unmessage_error(error):
    e = error.value if isinstance(error, Failure) else error
    if isinstance(e, UnmessageError):
        return e
    else:
        return UnmessageError(message=str(e), title=type(e).__name__)
