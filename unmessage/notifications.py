class UnmessageNotification(object):
    def __init__(self, message, title=None):
        self.title = title or 'unMessage'
        self.message = message


class UntalkNotification(UnmessageNotification):
    def __init__(self, message, title=None):
        super(UntalkNotification, self).__init__(
            message,
            title or 'unTalk')


class ContactNotification(UnmessageNotification):
    def __init__(self, contact, message, title=None):
        super(ContactNotification, self).__init__(
            message,
            title)
        self.contact = contact


class ConversationNotification(UnmessageNotification):
    def __init__(self, conversation, message, title=None):
        super(ConversationNotification, self).__init__(
            message,
            title)
        self.conversation = conversation


class ElementNotification(UnmessageNotification):
    def __init__(self, element, message=None, title=None):
        super(ElementNotification, self).__init__(
            message or str(element),
            title)
        self.element = element


class FileNotification(UnmessageNotification):
    def __init__(self, message, transfer, title=None):
        super(FileNotification, self).__init__(
            message,
            title)
        self.transfer = transfer
