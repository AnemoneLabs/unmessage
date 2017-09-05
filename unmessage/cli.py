#!/usr/bin/env python
import argparse
import curses
import struct
import sys

from curses.textpad import Textbox
from functools import wraps
from fcntl import ioctl
from signal import signal, SIGWINCH
from termios import TIOCGWINSZ
from threading import RLock

from pyaxo import b2a
from twisted.internet.defer import inlineCallbacks, returnValue

from . import errors
from . import peer
from .log import loggerFor, LogLevel
from .notifications import UnmessageNotification
from .peer import APP_NAME, Peer
from .ui import ConversationUi, PeerUi
from .ui import displays_error as _displays_error
from .ui import displays_result as _displays_result


DEFAULT_PREFIX = '>'
DEFAULT_PREFIX_ARGS_LIST = [[DEFAULT_PREFIX + ' ']]
SENDING_SUFFIX = '<'
RECEIVING_SUFFIX = ':'

COMMANDS = {
    '/auth': ['authenticate a conversation with a shared secret',
              '<peer_name> <secret>'],
    '/convs': ['display existing conversations',
               ''],
    '/delete': ['delete conversation with a peer',
                '<peer_name>'],
    '/file-accept': ['accept receiving a file from a peer',
                     '<peer_name> <checksum> [<target_path>]'],
    '/file-save': ['save a file sent by a peer',
                   '<peer_name> <checksum> [<target_path>]'],
    '/file-send': ['send a file to a peer',
                   '<peer_name> <source_path>'],
    '/help': ['display commands that ' + APP_NAME + ' responds to',
              ''],
    '/identity': ['display your identity in the format '
                  '<peer_name>@<onion_server>:<port>',
                  ''],
    '/key': ['display your identity key',
             ''],
    '/msg': ['send message to a peer you maintain a conversation',
             '<peer_name> <message>'],
    '/onion': ['display your onion server',
               ''],
    '/peer': ['display your peer address and key',
              ''],
    '/pres-off': ['disable sending your presence to a peer at startup',
                  '<peer_name>'],
    '/pres-on': ['enable sending your presence to a peer at startup',
                 '<peer_name>'],
    '/quit': ['quit ' + APP_NAME,
              ''],
    '/req-accept': ['accept a conversation request',
                    '<peer_name>@<onion_server>:<port> [<new_peer_name>]'],
    '/req-send': ['send a conversation request',
                  '<peer_name>@<onion_server>[:<port>] <identity_key>'],
    '/reqs-in': ['display inbound requests',
                 ''],
    '/reqs-out': ['display outbound requests',
                  ''],
    '/untalk': ['send or accept a request to talk with a peer using voice',
                '<peer_name> [<input_device_index> <output_device_index>]'],
    '/untalk-devices': ['display audio devices available',
                        ''],
    '/verify': ["verify a peer's identity key",
                '<peer_name> <identity_key>'],
}
NOT_RUNNING_COMMANDS = [
    '/help',
    '/quit',
]

RED = 1
GREEN = 2
CYAN = 3
BLUE = 4
YELLOW = 5


def create_help():
    help_lines = list()
    commands = sorted(COMMANDS.keys())
    longest = max(map(lambda command: len(command), commands))
    for c in commands:
        padding = (longest - len(c)) * ' '
        info = COMMANDS[c]
        help_lines.append('\t'.join([c + padding, info[0]]))
        if info[1]:
            help_lines.append('\t'.join([longest * ' ',
                                         '  args: ' + info[1]]))
    return '\n'.join(help_lines)


def sum_args_len(args_list):
    return sum(map(lambda args: len(args[0]), args_list))


def join_args_str(args_list):
    return ''.join(map(lambda args: args[0], args_list))


def get_auth_color(conversation):
    if conversation.is_authenticated:
        return CursesHelper.get_color_pair(CYAN)
    elif conversation.contact.is_verified:
        return CursesHelper.get_color_pair(GREEN)
    else:
        return CursesHelper.get_color_pair(RED)


def displays_error(f):
    def display(self, error):
        self.display_attention(message=str(error),
                               title=error.title,
                               error=True)
    return _displays_error(f, display)


def displays_result(f):
    def display(self, result):
        if isinstance(result, UnmessageNotification):
            title = result.title
        else:
            title = None
        self.display_info(message=str(result),
                          title=title)
    return _displays_result(f, display)


class Cli(PeerUi):
    @classmethod
    def get_conv_established_notification(cls, notification):
        cmd = '/msg'
        params = notification.conversation.contact.name + ' <message>'
        notification.message += ' using "{} {}"'.format(cmd, params)
        return notification

    def __init__(self, reactor):
        self.reactor = reactor

        self.log = loggerFor(self)

        self.help_info = None
        self.remote_mode = False

        self.curses_helper = None

        self.peer = None
        self.active_conv = None
        self._handlers_conv = dict()

    @property
    def handlers_conv(self):
        return self._handlers_conv.values()

    @property
    def prefix_str(self):
        return join_args_str(self.prefix)

    @property
    def prefix(self):
        try:
            return [[self.active_conv.contact.name,
                     get_auth_color(self.active_conv)],
                    [SENDING_SUFFIX + ' ']]
        except AttributeError:
            return DEFAULT_PREFIX_ARGS_LIST

    def notify(self, notification):
        self.display_info(notification.message, notification.title)

    def notify_error(self, error):
        self.display_attention(error.message, error.title, error=True)

    def add_conv_handler(self, conversation):
        handler = _ConversationHandler(conversation, self)
        conversation.ui = handler
        self._handlers_conv[conversation.contact.name] = handler

    def display_info(self, message, title=None, color=BLUE,
                     window=None, clear=False,
                     success=False):
        if success:
            color = GREEN
        self.display_alert(symbol='*',
                           message=message,
                           title=title,
                           color=color,
                           window=window,
                           clear=clear)

    def display_attention(self, message, title=None, color=YELLOW,
                          window=None, clear=False,
                          error=False):
        if error:
            color = RED
        self.display_alert(symbol='!',
                           message=message,
                           title=title,
                           color=color,
                           window=window,
                           clear=clear)

    def display_alert(self, symbol, message, title=None, color=None,
                      window=None, clear=False):
        symbol_args = [' ' + symbol + ' ']
        if color:
            symbol_args.append(CursesHelper.get_color_pair(color))
        if title:
            text = title + ': '
        else:
            text = ''
        text += message + '\n'
        self.display_args_list([symbol_args, [text]], window, clear)

    def display_str(self, output, color=None, break_line=True,
                    window=None, clear=False):
        if break_line:
            output += '\n'

        args = [output]

        if color:
            args.append(CursesHelper.get_color_pair(color))

        self.display_args_list([args], window, clear)

    def display_args_list(self, args_list, window=None, clear=False):
        window = window or self.curses_helper.output_win
        window.add(args_list, clear)

        # repositon cursor in input window
        self.curses_helper.input_win.curses_window.refresh()

    def clear_window(self, window=None):
        window = window or self.curses_helper.output_win
        window.clear()

    @inlineCallbacks
    def start(self, name,
              local_server_ip=None,
              local_server_port=None,
              launch_tor=True,
              tor_socks_port=None,
              tor_control_port=None,
              remote_mode=False,
              local_mode=False):
        self.help_info = create_help()
        self.remote_mode = remote_mode

        if not name:
            print 'unMessage could not find a name to use'
            print 'Run unMessage with `-name`'
            return

        self.curses_helper = CursesHelper(ui=self)

        self.display_info(message=APP_NAME,
                          window=self.curses_helper.header_win, clear=True)

        self.curses_helper.update_input_window(self.prefix)
        self.reactor.addReader(self)

        try:
            yield self.init_peer(name,
                                 local_server_ip,
                                 local_server_port,
                                 launch_tor,
                                 tor_socks_port,
                                 tor_control_port,
                                 local_mode)
        except errors.UnmessageError as e:
            self.display_attention(e.message, e.title, error=True)

    @inlineCallbacks
    def before_stop(self):
        yield self.peer.stop()

    def stop(self):
        self.reactor.stop()

    def display_help(self):
        self.display_str(self.help_info)

    @inlineCallbacks
    def init_peer(self, name,
                  local_server_ip,
                  local_server_port,
                  launch_tor,
                  tor_socks_port,
                  tor_control_port,
                  local_mode):
        self.peer = Peer.from_disk(name,
                                   self.reactor,
                                   ui=self,
                                   begin_log=True,
                                   log_level=LogLevel.debug)
        try:
            notification = yield self.peer.start(local_server_ip,
                                                 local_server_port,
                                                 launch_tor,
                                                 tor_socks_port,
                                                 tor_control_port,
                                                 local_mode)
        except Exception as e:
            self.notify_peer_failed(
                errors.UnmessageError(title=str(type(e)), message=str(e)))
        else:
            self.reactor.addSystemEventTrigger('before',
                                               'shutdown',
                                               self.before_stop)
            self.notify_peer_started(notification)

    def load_convs(self):
        for c in self.peer.conversations:
            self.add_conv_handler(c)

    def display_convs(self):
        if self.peer.conversations:
            output = ['Conversations:']
            for c in self.peer.conversations:
                output.append('\t{} {}'.format(c.contact.identity,
                                               b2a(c.contact.key)))
        else:
            output = ['There are no conversations']
        self.display_info('\n'.join(output))

    def display_identity(self):
        self.display_info('Your identity: {}'.format(self.peer.identity))
        self.peer.copy_identity()

    def display_key(self):
        self.display_info('Your identity key: {}'.format(
            b2a(self.peer.identity_keys.pub)))
        self.peer.copy_key()

    def display_onion(self):
        self.display_info('Your onion server: {}:{}'.format(
            self.peer.address.host,
            self.peer.address.port))
        self.peer.copy_onion()

    def display_peer(self):
        self.display_info('Your peer: {} {}'.format(
            self.peer.identity,
            b2a(self.peer.identity_keys.pub)))
        self.peer.copy_peer()

    @displays_error
    @displays_result
    def send_request(self, identity, key):
        return self.peer.send_request(identity, key)

    def notify_in_request(self, notification):
        cmd = '/req-accept'
        self.display_info('{} - accept using "{} {} [<new_peer_name>]"'.format(
                notification.message,
                cmd,
                notification.contact.identity),
            notification.title)

    @displays_result
    def notify_conv_established(self, notification):
        self.add_conv_handler(notification.conversation)
        return Cli.get_conv_established_notification(notification)

    @displays_error
    @displays_result
    @inlineCallbacks
    def accept_request(self, identity, new_name=None):
        notification = yield self.peer.accept_request(identity, new_name)
        self.add_conv_handler(notification.conversation)
        returnValue(Cli.get_conv_established_notification(notification))

    def display_in_reqs(self):
        if self.peer.inbound_requests:
            output = ['Inbound requests:']
            for r in self.peer.inbound_requests:
                handshake_packet = r.packet.handshake_packet
                output.append('\t{} {}'.format(handshake_packet.identity,
                                               handshake_packet.identity_key))
        else:
            output = ['There are no inbound requests']
        self.display_info('\n'.join(output))

    def display_out_reqs(self):
        if self.peer.outbound_requests:
            output = ['Outbound requests:']
            for r in self.peer.outbound_requests:
                contact = r.conversation.contact
                output.append('\t{} {}'.format(contact.identity,
                                               b2a(contact.key)))
        else:
            output = ['There are no outbound requests']
        self.display_info('\n'.join(output))

    def delete_conversation(self, name):
        try:
            self.peer.delete_conversation(name)
        except errors.UnknownContactError as e:
            self.display_attention(e.message)
        else:
            del self._handlers_conv[name]
            self.display_info(
                'Conversation with {} has been deleted'.format(name))

    @displays_error
    @inlineCallbacks
    def send_message(self, name, message):
        if len(message):
            conv = self.peer.get_conversation(name)
            self.active_conv = conv
            yield conv.send_message(message)
            handler = self._handlers_conv[name]
            handler.display_message(message, is_receiving=False)

    @displays_error
    @inlineCallbacks
    def send_file(self, name, file_path):
        transfer = yield self.peer.get_conversation(name).send_file(file_path)
        self.display_info(
            'File request for "{}" sent to {}'.format(
                transfer.element.content, name))

    @displays_error
    @inlineCallbacks
    def accept_file(self, name, checksum, file_path=None):
        transfer = yield self.peer.get_conversation(name).accept_file(
            checksum, file_path)
        self.display_info(
            'Accepted receiving "{}" from {}'.format(
                transfer.element.content, name))

    @displays_error
    def save_file(self, name, checksum, file_path=None):
        try:
            self.peer.get_conversation(name).save_file(checksum, file_path)
        except Exception as e:
            self.display_attention(title=str(type(e)),
                                   message=e.message,
                                   error=True)

    @displays_error
    @displays_result
    def untalk(self, name, input_device=None, output_device=None):
        return self.peer.get_conversation(name).untalk(input_device,
                                                       output_device)

    def display_audio_devices(self):
        devices = self.peer.get_audio_devices()
        if devices:
            output = ['Audio devices:']
            for name, index in devices.items():
                output.append('\tDevice {} has index {}'.format(name, index))
        else:
            output = ['There are no audio devices available']
        self.display_info('\n'.join(output))

    def verify_contact(self, name, key):
        try:
            self.peer.verify_contact(name, key)
        except errors.UnknownContactError as e:
            self.display_attention(e.message)
        except errors.VerificationError as e:
            self.display_attention(e.message, error=True)
        else:
            self.display_info(name + "'s key has been verified.", success=True)

    def enable_presence(self, name):
        self.set_presence(name, enable=True)

    def disable_presence(self, name):
        self.set_presence(name, enable=False)

    def set_presence(self, name, enable):
        try:
            self.peer.set_presence(name, enable)
        except errors.UnknownContactError as e:
            self.display_attention(e.message)
        else:
            self.display_info(
                'You have {} sending your presence to {}'.format(
                    'started' if enable else 'stopped', name),
                success=True)

    @displays_error
    @displays_result
    def authenticate(self, name, secret):
        return self.peer.get_conversation(name).authenticate(secret)

    def notify_bootstrap(self, notification):
        self.display_info(notification.message)

    def notify_peer_started(self, notification):
        self.clear_window()

        title = ' '.join([
            APP_NAME,
            '-',
            self.peer.identity,
            b2a(self.peer.identity_keys.pub)])

        self.load_convs()

        self.display_info(title, window=self.curses_helper.header_win,
                          clear=True, success=True)

        self.display_convs()

    def notify_peer_failed(self, notification):
        self.display_attention(APP_NAME,
                               window=self.curses_helper.header_win,
                               clear=True, error=True)
        self.display_attention(notification.message, notification.title,
                               error=True)

    def doRead(self):
        textpad = self.curses_helper.textpad
        ch = textpad.win.getch()
        if ch:
            if textpad.do_command(ch):
                textpad.win.refresh()
            else:
                self.gather(textpad)

    def gather(self, textpad):
        data = textpad.gather().strip()
        command, args = self.parse_data(data)
        if command:
            if self.peer.is_running or command in NOT_RUNNING_COMMANDS:
                self.make_call(command, args)
            else:
                self.display_attention('This command can only be called when '
                                       'the peer is running')
        self.curses_helper.update_input_window(self.prefix)

    def parse_data(self, data):
        command = args = None
        prefix_len = sum_args_len(self.prefix)
        if len(data) > prefix_len:
            echo = True
            split_data = data.split()
            try:
                if data.startswith(DEFAULT_PREFIX) or \
                        split_data[1].startswith('/'):
                    command, args = split_data[1], split_data[2:]
                else:
                    # the data does not start with DEFAULT_PREFIX (a
                    # conversation is active) and the message does not start
                    # with COMMAND_PREFIX, so the user is in fact sending a
                    # message
                    command = '/msg'
                    name = split_data[0].split(SENDING_SUFFIX)[0]
                    message = data[prefix_len:]
                    args = [name, message]
                    echo = False
            except IndexError:
                # the user modified the prefix
                # TODO prevent it
                pass
            if echo:
                self.display_str(data)
        return command, args

    def make_call(self, command, args):
        try:
            if command.startswith('/'):
                method_name = command.replace('/', 'call_').replace('-', '_')
                method = getattr(self, method_name)
            else:
                raise AttributeError
        except AttributeError:
            # the command does not exist and this error should be raised when:
            #
            #   - ``command`` is not a string
            #
            #   - ``command`` does not start with ``'/'``
            #
            #   - ``command`` is a valid command string but the ``Cli`` does
            #     not have its respective method
            self.display_attention(' '.join(
                ['Unknown command:', str(command)] + args + ['(call /help)']))
        else:
            try:
                method(*args)
            except TypeError:
                # the command method did not receive the right arguments
                self.display_attention(' '.join(['Usage:',
                                                 command,
                                                 COMMANDS[command][1]]))

    def call_auth(self, name, *words):
        secret = ' '.join(words).strip()
        if not secret:
            raise TypeError()
        self.authenticate(name, secret)

    def call_convs(self):
        self.display_convs()

    def call_delete(self, name):
        self.delete_conversation(name)

    def call_help(self):
        self.display_help()

    def call_file_accept(self, name, checksum, file_path=None):
        self.accept_file(name, checksum, file_path)

    def call_file_save(self, name, checksum, file_path=None):
        self.save_file(name, checksum, file_path)

    def call_file_send(self, name, file_path):
        self.send_file(name, file_path)

    def call_identity(self):
        self.display_identity()

    def call_key(self):
        self.display_key()

    def call_msg(self, name, *words):
        msg = ' '.join(words).rstrip()
        if not msg:
            raise TypeError()
        self.send_message(name, msg)

    def call_onion(self):
        self.display_onion()

    def call_peer(self):
        self.display_peer()

    def call_pres_off(self, name):
        self.disable_presence(name)

    def call_pres_on(self, name):
        self.enable_presence(name)

    def call_quit(self):
        self.stop()

    def call_req_accept(self, identity, new_name=None):
        self.accept_request(identity, new_name)

    def call_req_send(self, identity, key):
        self.send_request(identity, key)

    def call_reqs_in(self):
        self.display_in_reqs()

    def call_reqs_out(self):
        self.display_out_reqs()

    def call_untalk_devices(self):
        self.display_audio_devices()

    def call_verify(self, name, key):
        self.verify_contact(name, key)

    def call_untalk(self, name, input_device=None, output_device=None):
        self.untalk(name, input_device, output_device)

    def connectionLost(self, *args, **kwargs):
        """End curses when the connection to the input reader is lost."""
        CursesHelper.end_curses()

    def fileno(self):
        """Return the File Descriptor index used to read input."""
        return 0

    def logPrefix(self):
        """Return the log prefix of the input reader."""
        return 'curses'


class _ConversationHandler(ConversationUi):
    def __init__(self, conversation, cli):
        super(_ConversationHandler, self).__init__()
        self.conversation = conversation
        self.cli = cli

    def display_message(self, message, is_receiving):
        peer = self.conversation.contact.name
        suffix = RECEIVING_SUFFIX if is_receiving else SENDING_SUFFIX
        self.cli.display_args_list([[peer, get_auth_color(self.conversation)],
                                    [suffix + ' ' + message + '\n']])

    def update_prefix(self):
        # check if the converstation is active in the UI
        if self.conversation == self.cli.active_conv:
            self.cli.curses_helper.update_input_window(self.cli.prefix)

    def notify(self, notification):
        self.cli.notify(notification)

    def notify_error(self, error):
        self.cli.notify_error(error)

    def notify_disconnect(self, notification):
        self.cli.display_attention(notification.message)
        self.update_prefix()

    def notify_offline(self, notification):
        self.cli.display_attention(notification.message,
                                   notification.title)
        self.update_prefix()

    def notify_online(self, notification):
        self.cli.display_info(notification.message, success=True)

    def notify_message(self, notification):
        is_receiving = notification.element.receiver == self.cli.peer.name
        remote = self.cli.remote_mode if is_receiving else False

        self.display_message(notification.message, is_receiving)

        if remote:
            msg = notification.message.strip()
            if msg.startswith('\\'):
                msg = self.cli.prefix_str + msg[1:]
                cmd, args = self.cli.parse_data(msg)
                if cmd:
                    self.cli.make_call(cmd, args)

    def notify_in_authentication(self, notification):
        cmd = '/auth'
        self.cli.display_info('{} - advance using "{} {} <secret>"'.format(
                                  notification.message,
                                  cmd,
                                  self.conversation.contact.name),
                              notification.title)

    def notify_out_authentication(self, notification):
        self.cli.display_info(notification.message,
                              notification.title)

    def notify_finished_authentication(self, notification):
        if self.conversation.is_authenticated:
            self.cli.display_info(notification.message,
                                  notification.title,
                                  success=True)
        else:
            self.cli.display_attention(notification.message,
                                       notification.title,
                                       error=True)

        self.update_prefix()

    def notify_in_file_request(self, notification):
        cmd = '/file-accept'
        self.cli.display_info(
            '{} - accept using "{} {} {} [<taget_path>]"'.format(
                notification.message,
                cmd,
                self.conversation.contact.name,
                notification.transfer.element.checksum),
            notification.title)

    def notify_finished_in_file(self, notification):
        self.notify(notification)

    def notify_finished_out_file(self, notification):
        self.notify(notification)


def sync_curses(f):
    @wraps(f)
    def synced_f(*args, **kwargs):
        with CursesHelper.lock:
            return f(*args, **kwargs)
    return synced_f


class CursesHelper(object):
    lock = RLock()
    stdscr = None

    input_win_height = 8
    header_win_height = 3

    Colors = {RED: curses.COLOR_RED,
              GREEN: curses.COLOR_GREEN,
              CYAN: curses.COLOR_CYAN,
              BLUE: curses.COLOR_BLUE,
              YELLOW: curses.COLOR_YELLOW}

    @classmethod
    @sync_curses
    def _init_color_pairs(cls):
        default_bg = -1
        for number, fg in cls.Colors.items():
            curses.init_pair(number, fg, default_bg)

    @classmethod
    @sync_curses
    def _create_window(cls, get_size_y, get_begin_y,
                       get_size_x=None, get_begin_x=None,
                       config_extra=None, history_size=0):
        get_size_x = get_size_x or cls.get_size_x

        get_begin_x = get_begin_x or (lambda: 0)

        config_extra = config_extra or (lambda window: None)

        return _Window(get_size_y, get_size_x, get_begin_y, get_begin_x,
                       config_extra, history_size)

    @classmethod
    @sync_curses
    def init_curses(cls):
        stdscr = curses.initscr()
        cls.stdscr = stdscr

        # An attempt to limit the damage from this bug in curses:
        # https://bugs.python.org/issue13051
        # The input textbox is 8 rows high. So assuming a maximum terminal
        # width of 512 columns, we arrive at 8x512=4096. Most terminal windows
        # should be smaller than this.
        sys.setrecursionlimit(4096)

        stdscr.keypad(True)
        stdscr.nodelay(True)

        curses.start_color()
        curses.use_default_colors()
        cls._init_color_pairs()

        curses.noecho()
        curses.cbreak()
        curses.curs_set(1)

    @classmethod
    @sync_curses
    def get_term_size(cls):
        return struct.unpack('hh', ioctl(1, TIOCGWINSZ, ' '*4))

    @classmethod
    @sync_curses
    def get_size_y(cls):
        return cls.stdscr.getmaxyx()[0]

    @classmethod
    @sync_curses
    def get_size_x(cls):
        return cls.stdscr.getmaxyx()[1]

    @classmethod
    @sync_curses
    def get_color_pair(cls, color):
        return curses.color_pair(color)

    @classmethod
    @sync_curses
    def end_curses(cls):
        cls.stdscr.keypad(False)
        curses.echo()
        curses.nocbreak()
        curses.endwin()

    @sync_curses
    def __init__(self, ui):
        CursesHelper.init_curses()

        self.input_win = self._create_input_window()
        self.output_win = self._create_output_window()
        self.header_win = self._create_header_window()

        self.textpad = None

        self.ui = ui

        # re-initialize the windows with new sizes and positions on resize
        signal(SIGWINCH, lambda *args: self.resize_windows())

        self.init_windows()

    @sync_curses
    def _create_header_window(self):
        def get_size_y():
            return self.header_win_height

        def get_begin_y():
            return 0

        return self._create_window(get_size_y, get_begin_y,
                                   history_size=4)

    @sync_curses
    def _create_output_window(self):
        def get_size_y():
            return (self.get_size_y() - self.input_win_height -
                    self.header_win_height)

        def get_begin_y():
            return self.header_win_height

        return self._create_window(get_size_y, get_begin_y,
                                   history_size=90)

    @sync_curses
    def _create_input_window(self):
        def get_size_y():
            return self.input_win_height

        def get_begin_y():
            return self.get_size_y() - self.input_win_height

        def config_extra(window):
            window.curses_window.nodelay(1)
            window.curses_window.timeout(100)

        return self._create_window(get_size_y, get_begin_y,
                                   config_extra=config_extra)

    @sync_curses
    def init_windows(self):
        self.input_win.init()
        self.output_win.init()
        self.header_win.init()

        self.textpad = _Textbox(self.input_win)
        self.textpad.stripspaces = True

    @sync_curses
    def resize_windows(self):
        y, x = CursesHelper.get_term_size()
        curses.resize_term(y, x)
        self.init_windows()

    @sync_curses
    def update_input_window(self, args_list):
        self.input_win.add(args_list, clear=True)
        args_len = sum_args_len(args_list)
        self.input_win.curses_window.move(0, args_len)
        self.input_win.curses_window.cursyncup()


class _Window(object):
    def __init__(self, get_size_y, get_size_x, get_begin_y, get_begin_x,
                 config_extra, history_size):
        self.curses_window = None
        self.history = list()

        self.get_size_y = get_size_y
        self.get_size_x = get_size_x
        self.get_begin_y = get_begin_y
        self.get_begin_x = get_begin_x
        self.config_extra = config_extra
        self.history_size = history_size

    @sync_curses
    def init(self):
        w = curses.newwin(self.get_size_y(), self.get_size_x(),
                          self.get_begin_y(), self.get_begin_x())
        w.idlok(1)
        w.scrollok(1)
        w.leaveok(0)
        self.curses_window = w
        self.config_extra(self)

        self.add(self.history, clear=True, save_history=False)

    @sync_curses
    def add(self, args_list, clear=False, save_history=True):
        w = self.curses_window
        if clear:
            w.clear()
            if save_history:
                self.history = []
        for args in args_list:
            w.addstr(*args)
            w.noutrefresh()
            if save_history:
                self.history.append(args)
        curses.doupdate()
        if save_history and len(self.history) > self.history_size:
            self.history = self.history[-self.history_size:]

    def clear(self):
        self.add(args_list=(), clear=True)


class _Textbox(Textbox, object):
    """
    curses.textpad.Textbox requires users to ^g on completion, which is sort
    of annoying for an interactive chat client such as this, which typically
    only requires an <Enter>. This subclass fixes this problem by signalling
    completion on <Enter> as well as ^g. Also, map <Backspace> key to ^h.
    """
    def __init__(self, win, insert_mode=True):
        super(_Textbox, self).__init__(win.curses_window, insert_mode)

    @sync_curses
    def do_command(self, ch):
        if ch == 10:  # Enter
            return 0
        if ch == 127:  # BackSpace
            return 8

        return Textbox.do_command(self, ch)


def main(name=None):
    parser = argparse.ArgumentParser(description='''{}'''.format(APP_NAME))

    parser.add_argument('-n', '--name',
                        default=name)
    parser.add_argument('-i', '--local-server-ip',
                        default=peer.HOST)
    parser.add_argument('-l', '--local-server-port',
                        default=None,
                        type=int)
    parser.add_argument('--connect-to-tor',
                        action='store_false')
    parser.add_argument('-s', '--tor-socks-port',
                        default=peer.TOR_SOCKS_PORT,
                        type=int)
    parser.add_argument('-c', '--tor-control-port',
                        default=peer.TOR_CONTROL_PORT,
                        type=int)
    parser.add_argument('-r', '--remote-mode',
                        action='store_true')
    parser.add_argument('-L', '--local-mode',
                        action='store_true')

    args = parser.parse_args()

    from twisted.internet import reactor

    cli = Cli(reactor)
    cli.start(args.name,
              args.local_server_ip,
              args.local_server_port,
              args.connect_to_tor,
              args.tor_socks_port,
              args.tor_control_port,
              args.remote_mode,
              args.local_mode)
    reactor.run()


if __name__ == '__main__':
    sys.exit(main())
