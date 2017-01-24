#!/usr/bin/env python
import Queue
import sys
import Tkinter as Tk
import ttk
from functools import wraps
from tkMessageBox import askyesno, showerror, showinfo
from tkSimpleDialog import askstring

from pyaxo import b2a

from . import errors
from .peer import APP_NAME, Peer
from .ui import ConversationUi, PeerUi


def threadsafe(f):
    @wraps(f)
    def threadsafe_f(self, *args, **kwargs):
        self.calls_queue.put([f, self, args, kwargs])
    return threadsafe_f


def write_on_text(text, content, clear=True):
    state = text.cget('state')
    text.config(state=Tk.NORMAL)
    if clear:
        text.delete(1.0, Tk.END)
    for c in content:
        text.insert(Tk.INSERT, c)
    text.config(state=state)


class Gui(Tk.Tk, PeerUi):
    def __init__(self, name):
        super(Gui, self).__init__()

        self.calls_queue = Queue.Queue()
        self.title(APP_NAME)
        self.peer = None

        frame_notebook = Tk.Frame(self)
        frame_notebook.pack()

        self.notebook = ttk.Notebook(frame_notebook)
        self.notebook.pack()
        self.notebook.pack(fill=Tk.BOTH, expand=True)

        # hidden tab used only to set the size of the window
        hidden_tab = ChatTab(parent=self.notebook,
                             gui=self,
                             peer=self.peer,
                             conversation=None)
        self.notebook.add(hidden_tab, text='Hidden')
        self.notebook.hide(hidden_tab)

        self.bootstrap_tab = BootstrapTab(parent=self.notebook, gui=self)

        self.menu_bar = Tk.Menu(self)
        self.menu_bar.add_command(label='New Chat', state=Tk.DISABLED,
                                  command=self.create_request)
        self.menu_bar.add_command(label='Copy Identity', state=Tk.DISABLED,
                                  command=self.copy_identity)
        self.menu_bar.add_command(label='Copy Key', state=Tk.DISABLED,
                                  command=self.copy_key)
        self.menu_bar.add_command(label='Copy Peer', state=Tk.DISABLED,
                                  command=self.copy_peer)
        self.menu_bar.add_command(label='Copy Onion', state=Tk.DISABLED,
                                  command=self.copy_onion)
        self.menu_bar.add_command(label='Quit', command=self.quit)
        self.config(menu=self.menu_bar)

        if name:
            self.init_peer(name)
        else:
            self.tab_new = PeerCreationTab(parent=self.notebook, gui=self)
            self.notebook.add(self.tab_new, text='Start Peer', sticky=Tk.NS)

        self.check_calls()

    def check_calls(self):
        try:
            while 1:
                method, instance, args, kwargs = self.calls_queue.get_nowait()
                method(instance, *args, **kwargs)
                self.update_idletasks()
        except Queue.Empty:
            pass
        self.after(100, self.check_calls)

    def init_peer(self, name, local_server_port=None,
                  tor_port=None, tor_control_port=None):
        self.notebook.add(self.bootstrap_tab, text='Bootstrap')

        self.peer = Peer(name, self)
        self.peer.start(local_server_port=local_server_port,
                        tor_port=tor_port,
                        tor_control_port=tor_control_port)

    @threadsafe
    def notify_error(self, error):
        showerror(error.title, error.message)

    @threadsafe
    def notify_bootstrap(self, notification):
        self.bootstrap_tab.write_on_text(notification.message)

    @threadsafe
    def notify_peer_started(self, notification):
        self.bootstrap_tab.destroy()

        self.title(' '.join([self.peer.name,
                             'is online at',
                             self.peer.address.host,
                             '-',
                             APP_NAME]))

        # load existing conversations
        for c in self.peer.conversations:
            self.add_conversation(c)

        # enable the 'New Chat' menu button
        self.menu_bar.entryconfig(1, state=Tk.NORMAL)

        # enable the 'Copy Identity' menu button
        self.menu_bar.entryconfig(2, state=Tk.NORMAL)

        # enable the 'Copy Key' menu button
        self.menu_bar.entryconfig(3, state=Tk.NORMAL)

        # enable the 'Copy Peer' menu button
        self.menu_bar.entryconfig(4, state=Tk.NORMAL)

        # enable the 'Copy Onion' menu button
        self.menu_bar.entryconfig(5, state=Tk.NORMAL)

    @threadsafe
    def notify_peer_failed(self, notification):
        showerror(notification.title, notification.message)

    def send_request(self, identity, key):
        self.peer.send_request(identity, key)

    @threadsafe
    def notify_conv_established(self, notification):
        self.add_conversation(notification.conversation)

    def add_conversation(self, conversation):
        new_tab = ChatTab(parent=self.notebook,
                          gui=self,
                          peer=self.peer,
                          conversation=conversation)
        new_tab.text_message.mark_set(Tk.INSERT, 1.0)
        new_tab.text_message.focus_set()
        conversation.ui = new_tab
        self.notebook.add(new_tab, text=conversation.contact.name)

    @threadsafe
    def create_request(self):
        w = OutboundRequestWindow(gui=self,
                                  peer=self.peer)
        self.wait_window(w)

    @threadsafe
    def notify_in_request(self, notification):
        w = InboundRequestWindow(gui=self,
                                 peer=self.peer,
                                 contact=notification.contact)
        self.wait_window(w)

    @threadsafe
    def notify_out_request(self, notification):
        pass

    def copy_identity(self):
        self.peer.copy_identity()

    def copy_key(self):
        self.peer.copy_key()

    def copy_peer(self):
        self.peer.copy_peer()

    def copy_onion(self):
        self.peer.copy_onion()

    def quit(self):
        try:
            self.peer.stop()
        except AttributeError:
            # the user never initialized a peer
            pass
        self.destroy()


class BootstrapTab(Tk.Frame, object):
    def __init__(self, parent, gui):
        super(BootstrapTab, self).__init__(parent)

        self.gui = gui

        frame_tab = Tk.Frame(self)
        frame_tab.grid(padx=15, pady=15)

        frame_text = Tk.LabelFrame(frame_tab)
        frame_text.grid()

        self.text = Tk.Text(frame_text,
                            height=34,
                            state=Tk.DISABLED,
                            wrap=Tk.WORD)
        self.text.grid(row=0, column=0)
        scrollbar_body = Tk.Scrollbar(frame_text,
                                      command=self.text.yview)
        scrollbar_body.grid(row=0, column=1, sticky=Tk.NSEW)
        self.text.config(yscrollcommand=scrollbar_body.set)

    def write_on_text(self, content):
        write_on_text(self.text,
                      content=[content + '\n'],
                      clear=False)


def bind_checkbutton(checkbutton, method):
    def handler(event):
        new_state = not checkbutton.var.get()
        method(new_state)
    events = ['<Return>', '<Key-space>', '<Button-1>']
    bind_handler_to_widget_events(handler, checkbutton, events)


def bind_handler_to_widget_events(handler, widget, events):
    for event in events:
        widget.bind(event, handler)


class ChatTab(Tk.Frame, ConversationUi, object):
    def __init__(self, parent, gui, peer, conversation):
        super(ChatTab, self).__init__(parent)

        self.conversation = conversation
        self.gui = gui
        self.peer = peer
        self.calls_queue = gui.calls_queue

        frame_tab = Tk.Frame(self)
        frame_tab.grid(padx=15, pady=15)

        self.frame_conversation = Tk.LabelFrame(frame_tab, text='Conversation')
        self.frame_conversation.grid()

        self.update_frame()

        self.text_conversation = Tk.Text(self.frame_conversation,
                                         height=22,
                                         state=Tk.DISABLED,
                                         wrap=Tk.WORD)
        self.text_conversation.grid(row=0, column=0)
        scrollbar_body = Tk.Scrollbar(self.frame_conversation,
                                      command=self.text_conversation.yview)
        scrollbar_body.grid(row=0, column=1, sticky=Tk.NSEW)
        self.text_conversation.config(yscrollcommand=scrollbar_body.set)

        frame_input = Tk.Frame(frame_tab)
        frame_input.grid(pady=(10, 0))

        frame_message = Tk.LabelFrame(frame_input, text='Message')
        frame_message.grid(row=0, column=0)
        self.text_message = Tk.Text(frame_message,
                                    width=71, height=4, wrap=Tk.WORD)
        self.text_message.grid(row=0, column=0)
        scrollbar_message = Tk.Scrollbar(frame_message,
                                         command=self.text_message.yview)
        scrollbar_message.grid(row=0, column=1, sticky=Tk.NSEW)
        self.text_message.config(yscrollcommand=scrollbar_message.set)

        button_send = Tk.Button(
            frame_input, text='Send',
            command=lambda: self.send_message(
                self.text_message.get(1.0, Tk.END).strip()))
        button_send.grid(row=0, column=1, pady=(6, 0), sticky=Tk.NSEW)

        var_presence = Tk.BooleanVar(
            value=conversation and conversation.contact.has_presence)
        self.check_presence = Tk.Checkbutton(frame_tab,
                                             text='Send Presence',
                                             variable=var_presence)
        self.check_presence.var = var_presence
        self.check_presence.grid(pady=(10, 0), sticky=Tk.W)
        bind_checkbutton(self.check_presence, self.set_presence)

        buttons_row = frame_tab.grid_size()[1] + 1

        button_delete = Tk.Button(frame_tab,
                                  text='Delete',
                                  command=self.delete)
        button_delete.grid(row=buttons_row, pady=(10, 0), sticky=Tk.W)

        button_verify = Tk.Button(frame_tab,
                                  text='Verify',
                                  command=self.verify)
        button_verify.grid(row=buttons_row, pady=(10, 0))

        button_authenticate = Tk.Button(frame_tab,
                                        text='Authenticate',
                                        command=self.authenticate)
        button_authenticate.grid(row=buttons_row, pady=(10, 0), sticky=Tk.E)

        self.text_message.bind('<Return>',
                               lambda event: self.send_with_return(
                                   self.text_message.get(1.0, Tk.END).strip()))

    def update_frame(self):
        if self.conversation:
            text, color = get_auth_frame_configs(self.conversation)
            self.frame_conversation.config(
                text='{} Conversation'.format(text), foreground=color)

    def send_with_return(self, message):
        self.send_message(message)

        # prevent propagation of the event to other handlers so that a line
        # break is not added to the ``Text``
        return "break"

    def write_on_text(self, content):
        write_on_text(text=self.text_conversation,
                      content=[content + '\n'],
                      clear=False)

    def send_message(self, message):
        if len(message):
            self.peer.send_message(self.conversation.contact.name, message)
            self.text_message.delete(1.0, Tk.END)

    def set_presence(self, enable):
        self.peer.set_presence(self.conversation.contact.name, enable)

    def delete(self):
        if askyesno(title='Deletion',
                    message='Are you sure you wish to delete this '
                            'conversation?'):
            self.peer.delete_conversation(self.conversation.contact.name)
            self.destroy()

    def verify(self):
        key = askstring(title='Verification',
                        prompt="Provide the contact's public key:",
                        parent=self)
        if key:
            try:
                self.peer.verify_contact(self.conversation.contact.name, key)
            except errors.VerificationError as e:
                showerror(e.title, e.message)
            else:
                showinfo(title='Verification',
                         message="{}'s key has been verified.".format(
                             self.conversation.contact.name))
            self.update_frame()

    def authenticate(self):
        secret = askstring(title='Authentication',
                           prompt='Provide the shared secret:',
                           parent=self,
                           show='*')
        if secret:
            self.peer.authenticate(self.conversation.contact.name, secret)

    @threadsafe
    def notify_disconnect(self, notification):
        self.notify_status_change(notification)

    @threadsafe
    def notify_offline(self, notification):
        self.notify_status_change(notification)

    @threadsafe
    def notify_online(self, notification):
        self.notify_status_change(notification)

    @threadsafe
    def notify_status_change(self, notification):
        self.update_frame()
        self.write_on_text(notification.message)

    @threadsafe
    def notify_message(self, notification):
        self.write_on_text(content=''.join([notification.element.sender,
                                            ': ',
                                            notification.message]))

        # scroll to the bottom
        self.text_conversation.yview('moveto', 1.0)

    @threadsafe
    def notify_finished_authentication(self, notification):
        self.write_on_text(notification.message)
        self.update_frame()

    @threadsafe
    def notify_in_authentication(self, notification):
        self.write_on_text('{} - click "Authenticate" to proceed'.format(
            notification.message))

    @threadsafe
    def notify_out_authentication(self, notification):
        self.write_on_text(notification.message)


class PeerCreationTab(Tk.Frame, object):
    def __init__(self, parent, gui):
        super(PeerCreationTab, self).__init__(parent)

        self.gui = gui

        frame_tab = Tk.Frame(self)
        frame_tab.grid(padx=15, pady=15)

        label_info = Tk.Label(frame_tab, text='How will peers find you?')
        label_info.pack()

        label_name = Tk.Label(frame_tab, text='Name')
        label_name.pack(anchor=Tk.W)
        entry_name = Tk.Entry(frame_tab)
        entry_name.pack()

        label_local_server_port = Tk.Label(frame_tab,
                                           text='Local Server Port (Optional)')
        label_local_server_port.pack(anchor=Tk.W)
        entry_local_server_port = Tk.Entry(frame_tab)
        entry_local_server_port.pack()

        label_tor_port = Tk.Label(frame_tab,
                                  text='Tor Port (Optional)')
        label_tor_port.pack(anchor=Tk.W)
        entry_tor_port = Tk.Entry(frame_tab)
        entry_tor_port.pack()

        label_tor_control_port = Tk.Label(
            frame_tab,
            text='Tor Control Port (Optional)')
        label_tor_control_port.pack(anchor=Tk.W)
        entry_tor_control_port = Tk.Entry(frame_tab)
        entry_tor_control_port.pack()

        button_start = Tk.Button(
            frame_tab, text='Start',
            command=lambda: self.init_peer(
                entry_name.get().strip(),
                entry_local_server_port.get().strip(),
                entry_tor_port.get().strip(),
                entry_tor_control_port.get().strip()))
        button_start.pack(pady=(10, 0))

        entry_name.focus_set()

        self.bind_class('Entry',
                        '<Return>',
                        lambda event: self.init_peer(
                            entry_name.get().strip(),
                            entry_local_server_port.get().strip(),
                            entry_tor_port.get().strip(),
                            entry_tor_control_port.get().strip()))

    def init_peer(self, name, local_server_port,
                  tor_port, tor_control_port):
        try:
            self.gui.init_peer(name, local_server_port,
                               tor_port, tor_control_port)
        except errors.InvalidNameError as e:
            showerror(e.title, e.message)
        else:
            self.destroy()


class RequestWindow(Tk.Toplevel, object):
    def __init__(self, gui, peer, contact=None):
        super(RequestWindow, self).__init__(gui)

        self.title('New Chat')
        self.gui = gui
        self.peer = peer
        self.contact = contact

        frame = Tk.Frame(self)
        frame.pack(padx=15, pady=15)

        if contact:
            state = Tk.DISABLED
            identity = contact.identity
            key = b2a(contact.key)
            host, port = contact.address
            info_text = 'Chat request received!\nDo you know this peer?'
            button_text = 'Accept Request'
        else:
            state = Tk.NORMAL
            identity = ''
            key = ''
            info_text = 'Whom would you like\nto chat with?'
            button_text = 'Send Request'

        label_info = Tk.Label(frame, text=info_text)
        label_info.pack()

        label_identity = Tk.Label(frame, text='Identity Address')
        label_identity.pack(anchor=Tk.W)
        self.entry_identity = Tk.Entry(frame, state=state, width=44)
        write_on_text(self.entry_identity, content=[identity], clear=False)
        self.entry_identity.pack()

        label_key = Tk.Label(frame, text='Identity Key')
        label_key.pack(anchor=Tk.W)
        self.entry_key = Tk.Entry(frame, state=state, width=44)
        write_on_text(self.entry_key, content=[key], clear=False)
        self.entry_key.pack()

        if contact:
            label_name = Tk.Label(frame, text='New name (Optional)')
            label_name.pack(anchor=Tk.W)
            self.entry_name = Tk.Entry(frame, width=44)
            self.entry_name.pack()

        button_create = Tk.Button(frame, text=button_text,
                                  command=self.send_or_accept)
        button_create.pack(pady=(10, 0))

        self.bind('<Return>',
                  lambda event: self.send_or_accept())

        if contact:
            self.entry_name.focus_set()
        else:
            self.entry_identity.focus_set()

    def send_or_accept(self):
        pass


class InboundRequestWindow(RequestWindow):
    def __init__(self, gui, peer, contact):
        super(InboundRequestWindow, self).__init__(gui, peer, contact)

    def send_or_accept(self):
        new_name = self.entry_name.get().strip()
        self.peer.accept_request(self.contact.identity, new_name)
        self.destroy()


class OutboundRequestWindow(RequestWindow):
    def __init__(self, gui, peer):
        super(OutboundRequestWindow, self).__init__(gui, peer)

    def send_or_accept(self):
        self.gui.send_request(identity=self.entry_identity.get().strip(),
                              key=self.entry_key.get().strip())
        self.destroy()


COLOR_PURPLE = 'purple'
COLOR_GREEN = 'green'
COLOR_RED = 'red'


def get_auth_frame_configs(conversation):
    if conversation.is_authenticated:
        return 'Authenticated', COLOR_PURPLE
    elif conversation.contact.is_verified:
        return 'Verified', COLOR_GREEN
    else:
        return 'Unverified', COLOR_RED


def main(name=None):
    Gui(name).mainloop()


if __name__ == '__main__':
    sys.exit(main())
