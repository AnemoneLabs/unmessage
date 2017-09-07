import ConfigParser
import hmac
import os
from functools import wraps
from hashlib import sha256
from threading import Event, Lock

import attr
import pyaxo
import pyperclip
import txtorcon
from nacl.utils import random
from nacl.exceptions import CryptoError
from pyaxo import Axolotl, AxolotlConversation, Keypair, a2b, b2a
from twisted.internet.base import ReactorBase
from twisted.internet.defer import DeferredList, maybeDeferred
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.internet.endpoints import connectProtocol
from twisted.internet.endpoints import TCP4ClientEndpoint, TCP4ServerEndpoint
from twisted.internet.protocol import Factory
from twisted.protocols.basic import NetstringReceiver
from twisted.python.failure import Failure
from txtorcon import TorClientEndpoint

from . import __version__
from . import elements
from . import errors
from . import notifications
from . import packets
from . import ui
from . import untalk
from .contact import Contact
from .elements import RequestElement, UntalkElement, PresenceElement
from .elements import MessageElement, AuthenticationElement
from .elements import FileRequestElement, FileElement
from .log import begin_logging, loggerFor
from .ui import ConversationUi, PeerUi
from .utils import fork, default_factory_attrib, Paths, Address
from .utils import is_valid_identity, is_valid_file_name
from .utils import raise_if_not, raise_invalid_name, raise_invalid_shared_key
from .persistence import PeerInfo, Persistence
from .smp import SMP


APP_NAME = 'unMessage'

USER_DIR = os.path.expanduser('~')
APP_DIR = os.path.join(USER_DIR, '.config', APP_NAME)
CONFIG_FILE = os.path.join(APP_DIR, '{}.cfg'.format(APP_NAME))

CONFIG = ConfigParser.ConfigParser()
CONFIG.read(CONFIG_FILE)

DATA_LENGTH = 1024
TIMEOUT = 30

HOST = '127.0.0.1'
PORT = 11887

TOR_SOCKS_PORT = 9054
TOR_CONTROL_PORT = 9055


@attr.s
class PeerPaths(Paths):
    @classmethod
    def create(cls, name, base=APP_DIR):
        return cls(base, name)

    peer_db = default_factory_attrib(
        lambda self: self.join('peer.db'))
    axolotl_db = default_factory_attrib(
        lambda self: self.join('axolotl.db'))
    tor_dir = default_factory_attrib(
        lambda self: self.to_new('tor'))
    tor_data_dir = default_factory_attrib(
        lambda self: self.tor_dir.join('data'))
    log_file = default_factory_attrib(
        lambda self: self.join('peer.log'))
    conversations_dir = default_factory_attrib(
        lambda self: self.join('conversations'))


@attr.s
class ConversationPaths(Paths):
    file_transfer_dir = default_factory_attrib(
        lambda self: self.to_new('file-transfer'))


@attr.s
class Peer(object):
    state_created = 'created'
    state_running = 'running'
    state_stopped = 'stopped'

    _peer_name = attr.ib(validator=raise_invalid_name)
    _reactor = attr.ib(validator=attr.validators.instance_of(ReactorBase))
    _paths = attr.ib(
        validator=attr.validators.optional(
            attr.validators.instance_of(PeerPaths)),
        default=attr.Factory(lambda self: PeerPaths.create(self._peer_name),
                             takes_self=True))
    _persistence = attr.ib(
        validator=attr.validators.optional(
            attr.validators.instance_of(Persistence)),
        default=None)
    _info = attr.ib(
        validator=attr.validators.optional(
            attr.validators.instance_of(PeerInfo)),
        default=attr.Factory(lambda: PeerInfo(port_local_server=PORT)))
    _ui = attr.ib(
        validator=attr.validators.optional(
            attr.validators.instance_of(PeerUi)),
        default=attr.Factory(PeerUi))

    _axolotl = attr.ib(init=False, default=None)
    _conversations = attr.ib(init=False, default=attr.Factory(dict))
    _inbound_requests = attr.ib(init=False, default=attr.Factory(dict))
    _outbound_requests = attr.ib(init=False, default=attr.Factory(dict))

    _tor = attr.ib(init=False, default=None)
    _onion_service = attr.ib(init=False, default=None)
    _port_tor_socks = attr.ib(init=False, default=TOR_SOCKS_PORT)
    _port_tor_control = attr.ib(init=False, default=TOR_CONTROL_PORT)

    _ip_local_server = attr.ib(init=False, default=HOST)
    _local_mode = attr.ib(init=False, default=False)

    _twisted_server_endpoint = attr.ib(init=False, default=None)
    _twisted_factory = attr.ib(init=False, default=None)

    _managers_conv = attr.ib(init=False, default=attr.Factory(list))

    _presence_convs = attr.ib(init=False, default=attr.Factory(list))
    _presence_event = attr.ib(init=False, default=attr.Factory(Event))

    _event_stop = attr.ib(init=False, default=attr.Factory(Event))

    _state = attr.ib(init=False)

    log = attr.ib(init=False, default=attr.Factory(loggerFor, takes_self=True))

    def __attrs_post_init__(self):
        self.log.info('{} {}'.format(APP_NAME, __version__))

        self._name = self._peer_name

        self._axolotl = Axolotl(name=self.name,
                                dbname=self._paths.axolotl_db,
                                dbpassphrase=None,
                                nonthreaded_sql=False)
        if self.identity_keys is None:
            self._identity_keys = pyaxo.generate_keypair()

        self._conversations = self._load_conversations()

        self._twisted_factory = _ConversationFactory(
            peer=self,
            connection_made=self._add_intro_manager)

        self._state = Peer.state_created

    @classmethod
    def from_disk(cls, name, reactor, ui=None,
                  begin_log=False, begin_log_std=False, log_level=None):
        paths = PeerPaths.create(name)

        cls.create_peer_dir(paths)
        persistence = Persistence.create(paths)
        info = cls.load_peer_info(persistence, paths)

        kwargs = {'paths': paths,
                  'persistence': persistence}
        if info is not None:
            kwargs['info'] = info
        if ui is not None:
            kwargs['ui'] = ui
        peer = Peer(name, reactor, **kwargs)

        if begin_log:
            if log_level is None:
                begin_logging(peer._paths.log_file, begin_std=begin_log_std)
            else:
                begin_logging(peer._paths.log_file, log_level, begin_log_std)

        peer._update_config()

        return peer

    @classmethod
    def create_peer_dir(cls, paths):
        if not os.path.exists(paths.base):
            os.makedirs(paths.base)
        if not os.path.exists(paths.conversations_dir):
            os.makedirs(paths.conversations_dir)
        if not os.path.exists(paths.tor_dir.base):
            os.makedirs(paths.tor_dir.base)

    @classmethod
    def load_peer_info(cls, persistence, paths):
        if os.path.exists(paths.peer_db):
            return persistence.load_peer_info()

    @property
    def _contacts(self):
        return self._info.contacts

    @_contacts.setter
    def _contacts(self, contacts):
        self._info.contacts = contacts

    @property
    def name(self):
        return self._info.name

    @name.setter
    def _name(self, name):
        self._info.name = name

    @property
    def onion_service_key(self):
        return self._info.onion_service_key

    @onion_service_key.setter
    def _onion_service_key(self, onion_service_key):
        self._info.onion_service_key = onion_service_key

    @property
    def address(self):
        try:
            onion_domain = self._onion_service.hostname
        except AttributeError:
            onion_domain = 'hostnamenotfound.onion'
        return Address(onion_domain, self._port_local_server)

    @property
    def port_local_server(self):
        return self._info.port_local_server

    @port_local_server.setter
    def _port_local_server(self, port_local_server):
        self._info.port_local_server = port_local_server

    @property
    def identity(self):
        return '{}@{}:{}'.format(self.name,
                                 self.address.host, self.address.port)

    @property
    def identity_keys(self):
        return self._info.identity_keys

    @identity_keys.setter
    def _identity_keys(self, keys):
        self._info.identity_keys = keys

    @property
    def contacts(self):
        return self._contacts.values()

    @property
    def conversations(self):
        return self._conversations.values()

    @property
    def inbound_requests(self):
        return self._inbound_requests.values()

    @property
    def outbound_requests(self):
        return self._outbound_requests.values()

    @property
    def has_persistence(self):
        return self._persistence is not None

    @property
    def is_running(self):
        return self._state == Peer.state_running

    def _notify_bootstrap(self, status):
        self.log.info(status)
        self._ui.notify_bootstrap(notifications.UnmessageNotification(status))

    def _update_config(self):
        if not CONFIG.has_section('unMessage'):
            CONFIG.add_section('unMessage')
        CONFIG.set('unMessage', 'ui', type(self._ui).__name__)
        CONFIG.set('unMessage', 'name', self.name)

        with open(CONFIG_FILE, 'w') as f:
            CONFIG.write(f)

    def _save_peer_info(self):
        self.log.info('Saving peer info')
        self._persistence.save_peer_info(self._info)

    def _load_conversations(self):
        """Load all existing conversations in the peer's database.

        Return a dictionary mapping a contact's name to its respective
        ``Conversation`` object.
        """
        convs = dict()
        for other_name in self._axolotl.get_other_names():
            axolotl = self._axolotl.load_conversation(other_name)
            convs[other_name] = Conversation(
                self,
                self._contacts[other_name],
                keys=ConversationKeys(axolotl.id_),
                axolotl=axolotl)
        return convs

    def _send_online_presence(self):
        for d in self._send_presence():
            d.addCallback(
                lambda (_, conversation): conversation.ui.notify_online(
                    notifications.UnmessageNotification(
                        '{} is online'.format(conversation.contact.name))))
            # ignore failures
            d.addErrback(lambda _: None)

    def _send_offline_presence(self):
        # wait until all conversations are notified
        return DeferredList(self._send_presence(offline=True),
                            consumeErrors=True)

    def _send_presence(self, offline=False):
        deferreds = list()

        for element, conversation in self._prepare_presence(offline):
            if (offline and conversation.is_active or
                    not offline and not conversation.is_active):
                self.log.info('Sending {status} presence to {contact.name}',
                              status=str(element),
                              contact=conversation.contact)
                d = conversation._send_element(element)
                deferreds.append(d)

        return deferreds

    def _prepare_presence(self, offline=False):
        if offline:
            status = PresenceElement.status_offline
        else:
            status = PresenceElement.status_online
        presence_elements = list()

        for conversation in self.conversations:
            if conversation.contact.has_presence:
                presence_elements.append(
                    (PresenceElement(status), conversation))

        return presence_elements

    def _add_intro_manager(self, connection):
        manager = Introduction(self, connection)
        self._managers_conv.append(manager)
        return manager

    def _connect(self, address):
        if self._local_mode:
            point = TCP4ClientEndpoint(self._reactor,
                                       host=HOST, port=address.port)

        else:
            point = TorClientEndpoint(address.host, address.port,
                                      socks_hostname=HOST,
                                      socks_port=self._port_tor_socks,
                                      reactor=self._reactor)

        return connectProtocol(point,
                               _ConversationProtocol(self._twisted_factory))

    def _create_request(self, contact):
        """Create an ``OutboundRequest`` to be sent to a ``Contact``."""
        iv = random(packets.IV_LEN)

        req = OutboundRequest(Conversation(self, contact))
        req.request_keys = pyaxo.generate_keypair()
        req.handshake_keys = pyaxo.generate_keypair()
        req.ratchet_keys = pyaxo.generate_keypair()

        shared_request_key = pyaxo.generate_dh(req.request_keys.priv,
                                               contact.key)
        req.conversation.request_keys = ConversationKeys(shared_request_key)

        hs_packet = packets.HandshakePacket(self.identity,
                                            b2a(self.identity_keys.pub),
                                            b2a(req.handshake_keys.pub),
                                            b2a(req.ratchet_keys.pub))
        enc_hs_packet = pyaxo.encrypt_symmetric(
            req.conversation.request_keys.handshake_enc_key,
            str(hs_packet))

        req.packet = packets.RequestPacket(
            b2a(iv),
            b2a(pyaxo.hash_(iv + contact.key +
                            req.conversation.request_keys.iv_hash_key)),
            b2a(keyed_hash(req.conversation.request_keys.payload_hash_key,
                           enc_hs_packet)),
            b2a(req.request_keys.pub),
            b2a(enc_hs_packet))

        return req

    def _process_request(self, data):
        """Create a ``RequestPacket`` from the data received."""
        req_packet = packets.RequestPacket.build(data)
        hs_packet = a2b(req_packet.handshake_packet)

        shared_request_key = pyaxo.generate_dh(self.identity_keys.priv,
                                               a2b(req_packet.request_key))
        request_keys = ConversationKeys(shared_request_key)
        hs_packet_hash = keyed_hash(request_keys.payload_hash_key, hs_packet)

        if hs_packet_hash == a2b(req_packet.handshake_packet_hash):
            try:
                dec_hs_packet = pyaxo.decrypt_symmetric(
                    request_keys.handshake_enc_key,
                    hs_packet)
            except CryptoError:
                e = errors.MalformedPacketError('request')
                e.message += ' - decryption failed'
                raise e

            req_packet.handshake_packet = packets.HandshakePacket.build(
                dec_hs_packet)

            contact = Contact(req_packet.handshake_packet.identity,
                              a2b(req_packet.handshake_packet.identity_key))
            conv = Conversation(self, contact, request_keys=request_keys)

            return InboundRequest(conversation=conv, packet=req_packet)
        else:
            raise errors.CorruptedPacketError()

    def _init_conv(self, conv,
                   priv_handshake_key, other_handshake_key,
                   ratchet_keys=Keypair(None, None), other_ratchet_key=None,
                   mode=False):
        # if mode:
        #     the peer is Alice: she does not need to provide her ratchet
        #     keys as they will be generated when she starts ratcheting,
        #     but in order to do that she needs Bob's ratchet key (provided
        #     by Bob in his ``RequestPacket``), which is passed to
        #     ``Axolotl.init_conversation`` as ``other_ratchet_key=``
        # else:
        #     the peer is Bob: he sent a request to Alice with a random
        #     ratchet key and for that reason the state has to be created
        #     using that same key pair
        axolotl = self._axolotl.init_conversation(
            other_name=conv.contact.name,
            priv_identity_key=self.identity_keys.priv,
            identity_key=self.identity_keys.pub,
            priv_handshake_key=priv_handshake_key,
            other_identity_key=conv.contact.key,
            other_handshake_key=other_handshake_key,
            priv_ratchet_key=ratchet_keys.priv,
            ratchet_key=ratchet_keys.pub,
            other_ratchet_key=other_ratchet_key,
            mode=mode)
        if self.has_persistence:
            axolotl.save()

        conv.axolotl = axolotl
        conv.state = Conversation.state_conv
        conv.keys = ConversationKeys(axolotl.id_)

        self._contacts[conv.contact.name] = conv.contact
        self._conversations[conv.contact.name] = conv

    def _delete_conversation(self, conversation):
        conversation.close()
        conversation.axolotl.delete()
        del self._contacts[conversation.contact.name]
        del self._conversations[conversation.contact.name]

    @inlineCallbacks
    def _start_server(self, launch_tor):
        self._notify_bootstrap('Configuring local server')

        self._twisted_server_endpoint = TCP4ServerEndpoint(
            self._reactor,
            self._port_local_server,
            interface=self._ip_local_server)

        self._notify_bootstrap('Running local server')

        yield self._twisted_server_endpoint.listen(self._twisted_factory)

        if self._local_mode:
            result = None
        else:
            result = yield self._start_tor(launch_tor)
        returnValue(result)

    @inlineCallbacks
    def _start_tor(self, launch_tor):
        if launch_tor:
            self._notify_bootstrap('Launching Tor')

            def display_bootstrap_lines(prog, tag, summary):
                self._notify_bootstrap('{}%: {}'.format(prog, summary))

            self._tor = yield txtorcon.launch(
                self._reactor,
                progress_updates=display_bootstrap_lines,
                data_directory=self._paths.tor_data_dir,
                socks_port=self._port_tor_socks)
        else:
            self._notify_bootstrap('Connecting to existing Tor')

            endpoint = TCP4ClientEndpoint(self._reactor,
                                          HOST,
                                          self._port_tor_control)
            self._tor = yield txtorcon.connect(self._reactor, endpoint)

        self._notify_bootstrap('Controlling Tor process')

        onion_service_string = '{} {}:{}'.format(self._port_local_server,
                                                 self._ip_local_server,
                                                 self._port_local_server)

        if self.onion_service_key:
            args = ([onion_service_string], self.onion_service_key)
            save_key = False
        else:
            args = ([onion_service_string],)
            save_key = True

        self._onion_service = txtorcon.EphemeralHiddenService(*args)

        self._notify_bootstrap('Waiting for the Onion Service')

        yield self._onion_service.add_to_tor(self._tor._protocol)

        if save_key:
            self._onion_service_key = self._onion_service.private_key

        self._notify_bootstrap('Added Onion Service to Tor')

        returnValue(None)

    @inlineCallbacks
    def _stop_tor(self):
        if self._onion_service:
            self.log.info('Removing Onion Service from Tor')

            yield self._onion_service.remove_from_tor(self._tor._protocol)

            self.log.info('Removed Onion Service from Tor')

    @inlineCallbacks
    def _send_request(self, identity, key):
        if ':' not in identity:
            identity += ':' + str(PORT)
        contact = Contact(identity, key)
        req = self._create_request(contact)

        try:
            connection = yield self._connect(contact.address)
        except Exception as e:
            if Failure(e).check(txtorcon.socks.HostUnreachableError,
                                txtorcon.socks.TtlExpiredError):
                raise errors.OfflinePeerError(title=str(e),
                                              contact=contact.name,
                                              is_request=True)
            else:
                raise
        else:
            conv = req.conversation
            conv.set_active(connection, Conversation.state_out_req)

            yield conv.send_data(str(req.packet))

            self._outbound_requests[contact.identity] = req

            notification = notifications.ContactNotification(
                contact,
                title='Request sent',
                message='{} has received your request'.format(identity))
            returnValue(notification)

    def _prepare_accept_request(self, request, new_name=None):
        conversation = request.conversation

        if new_name:
            contact = conversation.contact
            identity = contact.identity.replace(contact.name, new_name, 1)
            if is_valid_identity(identity):
                contact.identity = identity
            else:
                raise errors.InvalidNameError()

        handshake_keys = pyaxo.generate_keypair()
        self._init_conv(conversation,
                        priv_handshake_key=handshake_keys.priv,
                        other_handshake_key=a2b(
                            request.packet.handshake_packet.handshake_key),
                        other_ratchet_key=a2b(
                            request.packet.handshake_packet.ratchet_key),
                        mode=True)

        return RequestElement(RequestElement.request_accepted), handshake_keys

    def _can_talk(self, conversation):
        for c in self.conversations:
            try:
                if c.untalk_session.is_talking and c is not conversation:
                    return False
            except AttributeError:
                continue
        return True

    def get_contact(self, name):
        return self.get_conversation(name).contact

    def get_conversation(self, name):
        try:
            return self._conversations[name]
        except KeyError:
            raise errors.UnknownContactError(name)

    def copy_onion(self):
        self.copy_to_clipboard(self.address.host)

    def copy_identity(self):
        self.copy_to_clipboard(self.identity)

    def copy_key(self):
        self.copy_to_clipboard(b2a(self.identity_keys.pub))

    def copy_peer(self):
        self.copy_to_clipboard('{} {}'.format(self.identity,
                                              b2a(self.identity_keys.pub)))

    def copy_to_clipboard(self, data):
        try:
            pyperclip.copy(data)
        except pyperclip.exceptions.PyperclipException:
            self._ui.notify_error(errors.UnmessageError(
                title='Clipboard error',
                message='A copy/paste mechanism for your system could not be '
                        'found'))

    @inlineCallbacks
    def start(self, local_server_ip=None,
              local_server_port=None,
              launch_tor=True,
              tor_socks_port=None,
              tor_control_port=None,
              local_mode=False):
        self._notify_bootstrap('Starting peer')

        if local_mode:
            launch_tor = False
            self._local_mode = local_mode

        if local_server_ip:
            self._ip_local_server = local_server_ip
        if local_server_port:
            self._port_local_server = int(local_server_port)
        if tor_socks_port:
            self._port_tor_socks = int(tor_socks_port)
        if tor_control_port:
            self._port_tor_control = int(tor_control_port)

        yield self._start_server(launch_tor)

        self._notify_bootstrap('Peer started')

        self._state = Peer.state_running

        self._send_online_presence()

        # TODO maybe return something useful to the UI?
        returnValue(notifications.UnmessageNotification('Peer started'))

    @inlineCallbacks
    def stop(self):
        self.log.info('Stopping peer')

        if self.has_persistence:
            self._save_peer_info()

        yield self._send_offline_presence()

        self._event_stop.set()

        for c in self.conversations:
            c.close()

        yield self._stop_tor()

        self._state = Peer.state_stopped

    def send_request(self, identity, key):
        try:
            key_bytes = a2b(key)
        except TypeError:
            raise errors.InvalidPublicKeyError()
        else:
            return self._send_request(identity, key_bytes)

    @inlineCallbacks
    def accept_request(self, identity, new_name=None):
        request = self._inbound_requests[identity]
        element, handshake_keys = yield self._prepare_accept_request(request,
                                                                     new_name)
        yield request.conversation._send_element(
            element,
            handshake_key=handshake_keys.pub)
        del self._inbound_requests[identity]
        returnValue(request.conversation._get_established_notification())

    def delete_conversation(self, name):
        self._delete_conversation(self.get_conversation(name))

    def set_presence(self, name, enable=False):
        contact = self.get_contact(name)
        contact.has_presence = enable

    def verify_contact(self, name, key):
        contact = self.get_contact(name)
        if contact.key == a2b(key):
            contact.is_verified = True
        else:
            contact.is_verified = False
            raise errors.VerificationError(name)

    def get_audio_devices(self):
        return untalk.get_audio_devices()


@attr.s
class Introduction(object):
    peer = attr.ib(validator=attr.validators.instance_of(Peer), repr=False)
    connection = attr.ib()

    receive_data_lock = attr.ib(init=False, default=attr.Factory(Lock))

    log = attr.ib(init=False, default=attr.Factory(loggerFor, takes_self=True))

    def __attrs_post_init__(self):
        self.connection.add_manager(self)

    def receive_data(self, data, connection=None):
        with self.receive_data_lock:
            try:
                self._receive_data(data, connection)
            except (errors.MalformedPacketError,
                    errors.CorruptedPacketError,
                    errors.InvalidIdentityError,
                    errors.InvalidPublicKeyError) as e:
                e.title += ' caused by an unknown peer'
                self.log.error(Failure(e).getTraceback())
                self.peer._ui.notify_error(e)
                self.connection.remove_manager()

    def _receive_data(self, data, connection=None):
        self.log.info('Introduction data received')

        packet = packets.IntroductionPacket.build(data)

        self.log.info('IntroductionPacket successfully built')

        for conv in self.peer.conversations:
            keys = conv.keys or conv.request_keys
            iv_hash = pyaxo.hash_(
                a2b(packet.iv) + self.peer.identity_keys.pub +
                keys.iv_hash_key)
            if iv_hash == a2b(packet.iv_hash):
                self.log.debug(
                    'Sender of the IntroductionPacket successfully '
                    'identified: {contact.identity}', contact=conv.contact)

                # the database does have a conversation between the
                # users, so the current connection must be added to the
                # conversation, a manager must be started and then
                # receive the packet using the existing conversation
                if not conv.is_active:
                    conv.set_active(self.connection, Conversation.state_conv)
                conv.receive_data(data, self.connection)
                break
        else:
            self.log.info('Assuming the packet is a RequestPacket')

            # the database does not have a conversation between the
            # users, so a request must be created and the UI
            # notified
            req = self.peer._process_request(data)

            conv = req.conversation
            conv.set_active(self.connection, Conversation.state_in_req)

            contact = req.conversation.contact

            self.log.debug('Sender of the RequestPacket successfully '
                           'identified: {contact.identity}', contact=contact)

            self.peer._inbound_requests[contact.identity] = req
            self.peer._ui.notify_in_request(
                notifications.ContactNotification(
                    contact,
                    title='Request received',
                    message='{} has sent you a '
                            'request'.format(contact.name)))

        self.peer._managers_conv.remove(self)

    def notify_disconnect(self):
        notification = notifications.UnmessageNotification(
            'An unknown peer has disconnected without sending any data')
        self.log.info(str(notification))
        self.peer._ui.notify(notification)


def raise_inactive(f):
    @wraps(f)
    def wrapped_f(self, *args, **kwargs):
        if self.is_active:
            return f(self, *args, **kwargs)
        else:
            raise errors.InactiveConversationError(self.contact.name)
    return wrapped_f


@attr.s
class Conversation(object):
    state_in_req = 'in_req'
    state_out_req = 'out_req'
    state_conv = 'conv'

    peer = attr.ib(validator=attr.validators.instance_of(Peer))
    contact = attr.ib(validator=attr.validators.instance_of(Contact))
    request_keys = attr.ib(default=None)
    keys = attr.ib(default=None)
    axolotl = attr.ib(
        validator=attr.validators.optional(
            attr.validators.instance_of(AxolotlConversation)),
        default=None)
    connection = attr.ib(default=None)

    _paths = attr.ib(init=False)

    axolotl_lock = attr.ib(init=False, default=attr.Factory(Lock))

    ui = attr.ib(init=False, default=attr.Factory(ConversationUi))

    auth_session = attr.ib(init=False, default=None)

    _managers = attr.ib(init=False, default=attr.Factory(dict))

    receive_data_lock = attr.ib(init=False, default=attr.Factory(Lock))
    _receive_data_methods = attr.ib(init=False, default=attr.Factory(
        lambda self: {Conversation.state_out_req: self.receive_reply_data,
                      Conversation.state_conv: self.receive_conversation_data},
        takes_self=True))

    _receive_element_methods = attr.ib(init=False, default=attr.Factory(
        lambda: {FileRequestElement: FileSession.parse_request_element,
                 FileElement: FileSession.parse_file_element,
                 UntalkElement: untalk.UntalkSession.parse_untalk_element,
                 PresenceElement: Conversation.parse_presence_element,
                 MessageElement: Conversation.parse_message_element,
                 AuthenticationElement: AuthSession.parse_auth_element}))

    elements = attr.ib(init=False, default=attr.Factory(dict))
    elements_lock = attr.ib(init=False, default=attr.Factory(Lock))

    is_active = attr.ib(init=False, default=False)

    log = attr.ib(init=False, default=attr.Factory(loggerFor, takes_self=True))

    def __attrs_post_init__(self):
        self._paths = ConversationPaths(self.peer._paths.conversations_dir,
                                        self.contact.name)

    @classmethod
    def parse_presence_element(cls, element, conversation, connection=None):
        notification = notifications.UnmessageNotification(
            '{} is {}'.format(conversation.contact.name, str(element)))
        if str(element) == PresenceElement.status_online:
            conversation.ui.notify_online(notification)
        elif str(element) == PresenceElement.status_offline:
            conversation.close()
            conversation.ui.notify_offline(notification)

    @classmethod
    def parse_message_element(cls, element, conversation, connection=None):
        conversation.ui.notify_message(
            notifications.ElementNotification(element))

    @property
    def has_persistence(self):
        return self.peer.has_persistence

    @property
    def is_authenticated(self):
        try:
            return self.auth_session.is_authenticated
        except AttributeError:
            # the session has not been initialized
            return None

    @property
    def file_session(self):
        return self._get_manager(FileSession.type_)

    @file_session.setter
    def _file_session(self, manager):
        self._set_manager(manager, FileSession.type_)

    @property
    def untalk_session(self):
        return self._get_manager(elements.UntalkElement.type_)

    @untalk_session.setter
    def _untalk_session(self, manager):
        self._set_manager(manager, elements.UntalkElement.type_)

    def _get_manager(self, type_):
        try:
            return self._managers[type_]
        except KeyError:
            return None

    def _set_manager(self, manager, type_):
        self._managers[type_] = manager

    def _get_established_notification(self):
        return notifications.ConversationNotification(
            conversation=self,
            title='Conversation established',
            message='You can now chat with {}'.format(self.contact.name))

    @inlineCallbacks
    def _send_element(self, element, handshake_key=None):
        """Create an ``ElementPacket``, connect (if needed) and send it.

        Return a ``Deferred`` that is fired after the the element is sent using
        the appropriate manager.

        TODO
            - Size invariance should be handled here, before encryption by
              ``_send_packet``
            - Split the element into multiple packets if needed
            - Maybe use a ``DeferredList``
        """
        element.sender = self.peer.name
        element.receiver = self.contact.name

        partial = elements.PartialElement.from_element(element)

        manager = yield self._get_active_manager(element)

        for packet in partial.to_packets():
            yield self._send_packet(packet, manager, handshake_key)

        returnValue((partial, self))

    @inlineCallbacks
    def _get_active_manager(self, element):
        """Get a manager with an active connection to send the element.

        Return a ``Deferred`` that is fired with a conversation manager capable
        of transmitting the element. In case the conversation does not have an
        active connection or it is not a regular element, establish a new
        connection. Otherwise, use the conversation's current active
        connection.
        """
        def connection_failed(failure):
            if failure.check(txtorcon.socks.HostUnreachableError,
                             txtorcon.socks.TtlExpiredError):
                raise Failure(errors.OfflinePeerError(
                    title=failure.getErrorMessage(),
                    contact=self.contact.name))
            else:
                raise Failure(errors.UnmessageError(
                    title='Conversation connection failed',
                    message=str(failure)))

        manager = self

        if not self.is_active:
            try:
                # the peer connects to the other one to resume a conversation
                connection = yield self.peer._connect(self.contact.address)
            except Exception as e:
                connection_failed(Failure(e))
            else:
                self.set_active(connection, Conversation.state_conv)
        elif element.type_ not in elements.REGULAR_ELEMENT_TYPES:
            manager_class = get_manager_class(element)
            manager = self._get_manager(manager_class.type_)

            if not manager.connection:
                try:
                    # the peer makes another connection to the other one to
                    # send this "special" element
                    connection = yield self.peer._connect(self.contact.address)
                except Exception as e:
                    connection_failed(Failure(e))
                else:
                    manager = self.add_connection(connection,
                                                  manager_class.type_)

        returnValue(manager)

    @inlineCallbacks
    def _send_packet(self, packet, manager, handshake_key=None):
        """Encrypt an ``ElementPacket`` as a ``RegularPacket`` and send it.

        Wrap the element packet with the regular encrypted packet and return a
        ``Deferred`` after successfully transmitting it.
        """
        reg_packet = self._encrypt(packet, handshake_key)

        # pack the ``RegularPacket`` into a ``str`` and send it
        yield manager.send_data(str(reg_packet))

        returnValue(reg_packet)

    def _receive_packet(self, packet, connection):
        """Decrypt a ``RegularPacket`` as an ``ElementPacket``.

        Unwrap the element packet with decryption, process it and parse the
        element.
        """
        element_packet = self._decrypt(packet)
        partial = self._process_element_packet(packet=element_packet,
                                               sender=self.contact.name,
                                               receiver=self.peer.name)
        if partial.is_complete:
            # it can be parsed as all parts have been added to the
            # ``PartialElement`` or it is composed of a single part
            return self._receive_element(partial.to_element(), connection)
        else:
            # the ``PartialElement`` has parts yet to be received
            pass

    def _process_element_packet(self, packet, sender, receiver):
        with self.elements_lock:
            try:
                # get the ``PartialElement`` that corresponds to the
                # ``ElementPacket.id_`` in case it is one of the parts of an
                # incomplete element
                element = self.elements.pop(packet.id_)
            except KeyError:
                # create an ``PartialElement`` as there are no incomplete
                # elements with the respective ``ElementPacket.id_``
                element = elements.PartialElement.from_packet(packet,
                                                              sender,
                                                              receiver)
            else:
                # add the part from the packet
                element[packet.part_num] = packet.payload

            if element.is_complete:
                # the ``PartialElement`` does not have to be stored as either
                # it fitted in a single packet or all of its parts have been
                # transmitted (the ``packet`` contained the last remaining
                # part)
                pass
            else:
                # store the ``PartialElement`` in the incomplete elements
                # ``dict`` as it has been split in multiple parts, yet to be
                # transmitted
                self.elements[element.id_] = element
            return element

    def _encrypt(self, packet, handshake_key=None):
        """Encrypt an ``ElementPacket`` and return a ``RegularPacket``."""
        iv = random(packets.IV_LEN)
        plaintext = str(packet)
        if handshake_key:
            keys = self.request_keys
            handshake_key = pyaxo.encrypt_symmetric(keys.handshake_enc_key,
                                                    handshake_key)
        else:
            keys = self.keys
            handshake_key = ''

        with self.axolotl_lock:
            ciphertext = self.axolotl.encrypt(plaintext)
            if self.has_persistence:
                self.axolotl.save()

        if handshake_key:
            packet_type = packets.ReplyPacket
        else:
            packet_type = packets.RegularPacket

        return packet_type(
            b2a(iv),
            b2a(pyaxo.hash_(iv + self.contact.key + keys.iv_hash_key)),
            b2a(keyed_hash(keys.payload_hash_key, handshake_key + ciphertext)),
            b2a(handshake_key),
            b2a(ciphertext))

    def _decrypt(self, packet):
        """Decrypt a ``RegularPacket`` and return an ``ElementPacket``."""
        ciphertext = a2b(packet.payload)
        keys = self.keys or self.request_keys
        payload_hash = keyed_hash(keys.payload_hash_key,
                                  a2b(packet.handshake_key) + ciphertext)

        if payload_hash == a2b(packet.payload_hash):
            with self.axolotl_lock:
                plaintext = self.axolotl.decrypt(ciphertext)
                if self.has_persistence:
                    self.axolotl.save()
            return packets.ElementPacket.build(plaintext)
        else:
            raise errors.CorruptedPacketError()

    def _prepare_message(self, message):
        return MessageElement(message)

    def _prepare_authentication(self, secret):
        # TODO maybe use locks or something to prevent advancing or restarting
        # while the SMP is doing its math
        auth_session = self.auth_session
        if (not auth_session or auth_session.is_waiting or
                auth_session.is_authenticated is not None):
            auth_session = self.init_auth()
        element = AuthenticationElement(
            self.auth_session.start(
                self.keys.auth_secret_key + secret))
        return element, auth_session

    def remove_manager(self, manager):
        manager.stop()
        del self._managers[manager.type_]

    def create_dir(self):
        if not os.path.exists(self._paths.base):
            os.makedirs(self._paths.base)

    def send_data(self, data):
        return fork(self.connection.send, data)

    def receive_data(self, data, connection=None):
        with self.receive_data_lock:
            try:
                method = self._receive_data_methods[self.state]
            except KeyError:
                # the state does not have a "receive" method, which is probably
                # state_in_req because it should be waiting for the request to
                # be accepted (by this user) and meanwhile no more data should
                # be received from the other party who already sent the request
                self.log.warn('Failed to find the receive method for state: '
                              '{state}', state=self.state)
                # TODO maybe disconnect instead of ignoring the data
            else:
                self.log.debug(
                    'Receiving data with {method.__name__} for state: {state}',
                    method=method, state=self.state)

                def errback(failure):
                    error = errors.to_unmessage_error(failure)
                    error.message += ' - caused by {}'.format(
                        self.contact.name)

                    self.log.error('{error.title}: {error.message}',
                                   error=error)
                    self.log.error(failure.getTraceback())
                    self.ui.notify_error(error)

                d = maybeDeferred(method, data, connection)
                d.addErrback(errback)

    def receive_conversation_data(self, data, connection):
        packet = packets.RegularPacket.build(data)
        return self._receive_packet(packet, connection)

    def receive_reply_data(self, data, connection):
        packet = packets.ReplyPacket.build(data)
        req = self.peer._outbound_requests[self.contact.identity]
        enc_handshake_key = a2b(packet.handshake_key)

        payload_hash = keyed_hash(
            req.conversation.request_keys.payload_hash_key,
            enc_handshake_key + a2b(packet.payload))

        if payload_hash == a2b(packet.payload_hash):
            # the reply packet provides a handshake key, making it possible
            # to do a Triple Diffie-Hellman handshake and create an Axolotl
            # state
            try:
                handshake_key = pyaxo.decrypt_symmetric(
                    req.conversation.request_keys.handshake_enc_key,
                    enc_handshake_key)
            except CryptoError:
                e = errors.MalformedPacketError('reply')
                e.message += ' - decryption failed'
                raise e

            self.peer._init_conv(self,
                                 priv_handshake_key=req.handshake_keys.priv,
                                 other_handshake_key=handshake_key,
                                 ratchet_keys=req.ratchet_keys)
            self.peer._ui.notify_conv_established(
                req.conversation._get_established_notification())
        else:
            # TODO maybe disconnect instead of ignoring the data
            pass

    def _receive_element(self, element, connection=None):
        self.log.debug('Parsing element of type: {element.__class__.__name__}',
                       element=element)
        try:
            method = self._receive_element_methods[type(element)]
        except KeyError:
            raise errors.UnknownElementError(element.type_)
        else:
            return method(element, self, connection)

    def set_active(self, connection, state):
        connection.add_manager(self)
        self.connection = connection
        self.state = state
        self.is_active = True

    def add_connection(self, connection, type_):
        manager = self._get_manager(type_)
        manager.connection = connection
        connection.add_manager(manager, type_)
        return manager

    def close(self):
        for m in self._managers.values():
            self.remove_manager(m)
        if self.connection:
            self.connection.remove_manager()
            self.connection = None
        self.auth_session = None
        self.is_active = False

    def notify_disconnect(self):
        if self.is_active:
            self.ui.notify_disconnect(
                notifications.UnmessageNotification(
                    '{} has disconnected'.format(self.contact.name)))
        self.connection = None
        self.close()

    def init_file(self, connection=None):
        self._file_session = FileSession(self)
        if connection:
            self.add_connection(connection, FileSession.type_)
        return self.file_session

    def stop_file(self):
        self.remove_manager(self.file_session)

    def init_untalk(self, connection=None, other_handshake_key=None):
        self._untalk_session = untalk.UntalkSession(self, other_handshake_key)
        if connection:
            self.add_connection(connection, untalk.UntalkSession.type_)
        return self.untalk_session

    def start_untalk(self, other_handshake_key=None):
        self.untalk_session.start(other_handshake_key)

    def stop_untalk(self):
        self.remove_manager(self.untalk_session)

    def init_auth(self, buffer_=None):
        self.auth_session = AuthSession(buffer_)
        return self.auth_session

    @inlineCallbacks
    def send_message(self, plaintext):
        element = self._prepare_message(plaintext)
        yield self._send_element(element)
        notification = notifications.ElementNotification(element)
        returnValue(notification)

    @inlineCallbacks
    def authenticate(self, secret):
        element, auth_session = self._prepare_authentication(secret)
        yield self._send_element(element)
        if self.auth_session.is_waiting:
            notification = notifications.UnmessageNotification(
                title='Authentication started',
                message='Waiting for {} to advance'.format(self.contact.name))
            returnValue(notification)

    @raise_inactive
    @inlineCallbacks
    def untalk(self, input_device=None, output_device=None):
        if self.peer._can_talk(self):
            untalk_session = self.untalk_session or self.init_untalk()
            if untalk_session.is_talking:
                self.stop_untalk()
            else:
                try:
                    untalk_session.configure(input_device, output_device)
                except untalk.AudioDeviceNotFoundError:
                    self.remove_manager(untalk_session)
                    raise
                else:
                    yield self._send_element(
                        UntalkElement(
                            b2a(untalk_session.handshake_keys.pub)))
                    if (untalk_session.state ==
                            untalk.UntalkSession.state_sent):
                        notification = notifications.UntalkNotification(
                            message='Voice conversation request sent '
                                    'to {}'.format(self.contact.name))
                        returnValue(notification)
                    else:
                        # this peer has accepted the request
                        self.start_untalk()
        else:
            raise errors.UntalkError(
                message='You can only make one voice conversation at a '
                        'time')

    @raise_inactive
    def send_file(self, file_path):
        file_session = self.file_session or self.init_file()
        return file_session.send_request(file_path)

    @raise_inactive
    def accept_file(self, checksum, file_path=None):
        return self.file_session.accept_request(checksum, file_path)

    @raise_inactive
    def save_file(self, checksum, file_path=None):
        self.file_session.save_received_file(checksum, file_path)


@attr.s
class ConversationKeys(object):
    handshake_enc_salt = b'\x00'
    iv_hash_salt = b'\x01'
    payload_hash_salt = b'\x02'
    auth_secret_salt = b'\x03'

    key = attr.ib(validator=raise_invalid_shared_key)
    handshake_enc_key = attr.ib(init=False)
    iv_hash_key = attr.ib(init=False)
    payload_hash_key = attr.ib(init=False)
    auth_secret_key = attr.ib(init=False)

    def __attrs_post_init__(self):
        self.handshake_enc_key = pyaxo.kdf(self.key, self.handshake_enc_salt)
        self.iv_hash_key = pyaxo.kdf(self.key, self.iv_hash_salt)
        self.payload_hash_key = pyaxo.kdf(self.key, self.payload_hash_salt)
        self.auth_secret_key = pyaxo.kdf(self.key, self.auth_secret_salt)


@attr.s
class InboundRequest(object):
    conversation = attr.ib(validator=attr.validators.instance_of(Conversation))
    packet = attr.ib(
        validator=attr.validators.instance_of(packets.RequestPacket))


@attr.s
class OutboundRequest(object):
    conversation = attr.ib(
        validator=attr.validators.instance_of(Conversation))
    request_keys = attr.ib(
        validator=attr.validators.optional(
            attr.validators.instance_of(Keypair)),
        default=None)
    handshake_keys = attr.ib(
        validator=attr.validators.optional(
            attr.validators.instance_of(Keypair)),
        default=None)
    ratchet_keys = attr.ib(
        validator=attr.validators.optional(
            attr.validators.instance_of(Keypair)),
        default=None)
    packet = attr.ib(
        validator=attr.validators.optional(
            attr.validators.instance_of(packets.RequestPacket)),
        default=None)


@attr.s
class AuthSession(object):
    buffer_ = attr.ib(default=None)
    smp = attr.ib(init=False, default=None)
    step = attr.ib(init=False)

    def __attrs_post_init__(self):
        if self.buffer_ is None:
            # start from step 1 as the initial buffer still has to be sent to
            # the other party, who will advance the session
            self.step = 1
        else:
            # start from step 2 as the initial buffer was received from the
            # other party, who started the session
            self.step = 2

    @classmethod
    @inlineCallbacks
    def parse_auth_element(cls, element, conversation, connection=None):
        buffer_ = str(element)
        try:
            next_buffer = conversation.auth_session.advance(buffer_)
        except AttributeError:
            conversation.init_auth(buffer_)
            conversation.ui.notify_in_authentication(
                notifications.UnmessageNotification(
                    title='Authentication started',
                    message='{} wishes to authenticate '.format(
                        conversation.contact.name)))
        else:
            if next_buffer:
                yield conversation._send_element(
                    AuthenticationElement(next_buffer))
            if conversation.is_authenticated is None:
                # the authentication is not complete as buffers are still being
                # exchanged
                pass
            else:
                if conversation.is_authenticated:
                    title = 'Authentication successful'
                    message = 'Your conversation with {} is authenticated!'
                else:
                    title = 'Authentication failed'
                    message = 'Your conversation with {} is NOT authenticated!'
                conversation.ui.notify_finished_authentication(
                    notifications.UnmessageNotification(
                        title=title,
                        message=message.format(conversation.contact.name)))

    @property
    def is_authenticated(self):
        if self.step > 5:
            # the session is complete
            return self.smp.match
        else:
            # the session has not started or is incomplete
            return None

    @property
    def is_waiting(self):
        # the session is waiting for the other party to initialize theirs by
        # performing step 2
        return self.step == 3

    def start(self, secret):
        self.smp = SMP(secret)
        return self.advance(self.buffer_)

    def advance(self, buffer_):
        if self.step == 1:
            next_buffer = self.smp.step1()
        else:
            step_method = getattr(self.smp, 'step' + str(self.step))
            next_buffer = step_method(a2b(buffer_))
        # skip the next step because it will be performed by the other party
        self.step += 2
        try:
            return b2a(next_buffer) + '\n'
        except TypeError:
            return None


@attr.s
class FileSession(object):
    type_ = 'file'
    element_classes = [FileRequestElement,
                       FileElement]

    conversation = attr.ib(validator=attr.validators.instance_of(Conversation),
                           repr=False)
    connection = attr.ib(init=False, default=None, repr=False)

    in_requests = attr.ib(init=False, default=attr.Factory(dict))
    in_files = attr.ib(init=False, default=attr.Factory(dict))

    out_requests = attr.ib(init=False, default=attr.Factory(dict))
    out_files = attr.ib(init=False, default=attr.Factory(dict))

    @classmethod
    @inlineCallbacks
    def parse_request_element(cls, element, conversation, connection=None):
        if FileRequestElement.is_valid_request(element):
            manager = (conversation.file_session or
                       conversation.init_file(connection))

            transfer = manager.receive_request(element)
            conversation.ui.notify_in_file_request(
                notifications.FileNotification(
                    '{} wishes to send the file "{}" ({} bytes)'.format(
                        conversation.contact.name,
                        element.content,
                        element.size),
                    transfer))
            returnValue(transfer)
        elif FileRequestElement.is_valid_accept(element):
            manager = conversation.file_session
            if manager:
                transfer = yield manager.send_file(element.checksum)
                conversation.ui.notify_finished_out_file(
                    notifications.FileNotification(
                        'Finished sending "{}" to {}'.format(
                            transfer.element.content,
                            conversation.contact.name),
                        transfer))
                returnValue(transfer)
            else:
                raise errors.UnmessageError(
                    'Unexpected FileRequestElement received, accepting a file '
                    'without an active manager')
        else:
            raise errors.InvalidElementError()

    @classmethod
    def parse_file_element(cls, element, conversation, connection=None):
        raise_if_not(FileElement.is_valid_file,
                     errors.InvalidElementError)(value=element)

        manager = conversation.file_session
        if manager:
            transfer = manager.receive_file(element)
            manager.save_received_file(transfer.element.checksum)
            conversation.ui.notify_finished_in_file(
                notifications.FileNotification(
                    'Finished receiving "{}" from {}, saved at {}'.format(
                        transfer.element.content,
                        conversation.contact.name,
                        transfer.file_path),
                    transfer))
        else:
            raise errors.UnmessageError(
                'Unexpected FileElement received without an active manager')

    @property
    def _paths(self):
        return self.conversation._paths.file_transfer_dir

    def send_data(self, data):
        return fork(self.connection.send, data)

    def receive_data(self, data, connection=None):
        self.conversation.receive_data(data, connection)

    def stop(self):
        if self.connection:
            self.connection.remove_manager()

    def notify_disconnect(self):
        self.connection = None
        self.conversation.remove_manager(self)

    def save_file_bytes(self, file_path, file_bytes):
        with open(file_path, 'wb') as f:
            f.write(file_bytes)

    def create_dir(self):
        self.conversation.create_dir()
        if not os.path.exists(self._paths.base):
            os.makedirs(self._paths.base)

    def get_default_file_path(self, file_name):
        return self._paths.join(file_name)

    @inlineCallbacks
    def send_request(self, file_path):
        element, file_transfer = self.prepare_request(file_path)
        self.out_requests[element.checksum] = file_transfer
        try:
            yield self.conversation._send_element(element)
        except:
            del self.out_requests[element.checksum]
            raise
        returnValue(file_transfer)

    def prepare_request(self, file_path):
        _, file_name = os.path.split(file_path)
        if is_valid_file_name(file_name):
            with open(os.path.expanduser(file_path), 'rb') as f:
                file_ = f.read()
            checksum = b2a(pyaxo.hash_(file_))
            element = FileRequestElement(content=file_name,
                                         size=len(file_),
                                         checksum=checksum)
            file_transfer = FileTransfer(element, b2a(file_))
            return element, file_transfer
        else:
            raise errors.InvalidFileNameError()

    @inlineCallbacks
    def send_file(self, checksum):
        element, transfer = self.prepare_file(checksum)
        del self.out_requests[checksum]
        self.out_files[checksum] = transfer
        try:
            yield self.conversation._send_element(element)
        except:
            self.out_requests[checksum] = transfer
            raise
        else:
            returnValue(transfer)
        finally:
            del self.out_files[checksum]

    def prepare_file(self, checksum):
        transfer = self.out_requests[checksum]
        element = FileElement(transfer.file_)
        return element, transfer

    def receive_request(self, element):
        if is_valid_file_name(element.content):
            file_transfer = FileTransfer(element)
            self.in_requests[element.checksum] = file_transfer
            return file_transfer
        else:
            raise errors.InvalidFileNameError()

    @inlineCallbacks
    def accept_request(self, checksum, file_path=None):
        element, transfer = self.prepare_accept(checksum, file_path)
        self.in_files[checksum] = transfer
        del self.in_requests[checksum]
        try:
            yield self.conversation._send_element(element)
        except:
            self.in_requests[checksum] = transfer
            del self.in_files[checksum]
            raise
        else:
            returnValue(transfer)

    def prepare_accept(self, checksum, file_path=None):
        transfer = self.in_requests[checksum]

        if file_path:
            transfer.file_path = os.path.abspath(os.path.expanduser(file_path))
        else:
            file_name = transfer.element.content
            transfer.file_path = self.get_default_file_path(file_name)
            self.create_dir()
        with open(transfer.file_path, 'wb'):
            # just check if this file can be opened
            pass

        element = FileRequestElement(FileRequestElement.request_accepted,
                                     checksum=checksum)
        return element, transfer

    def receive_file(self, element):
        file_ = element.content
        file_bytes = a2b(file_)
        checksum = b2a(pyaxo.hash_(file_bytes))
        try:
            transfer = self.in_files[checksum]
        except KeyError:
            raise errors.UnmessageError(
                'The received file does not match any of the accepted '
                'checksums')
        else:
            if len(file_bytes) == transfer.element.size:
                transfer.file_ = file_
                return transfer
            else:
                raise errors.UnmessageError(
                    'The size of the received file does not match the one '
                    'that was accepted')

    def save_received_file(self, checksum, file_path=None):
        try:
            transfer = self.in_files[checksum]
        except KeyError:
            raise errors.UnmessageError('Received file not found')
        else:
            if file_path:
                transfer.file_path = os.path.abspath(os.path.expanduser(
                    file_path))
            self.save_file_bytes(transfer.file_path,
                                 file_bytes=a2b(transfer.file_))
            del self.in_files[checksum]


@attr.s
class FileTransfer(object):
    element = attr.ib(
        validator=attr.validators.instance_of(FileRequestElement))
    file_ = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(str)),
        default=None)
    file_path = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(str)),
        default=None)


@attr.s
class _ConversationFactory(Factory, object):
    peer = attr.ib(validator=attr.validators.instance_of(Peer), repr=False)
    connection_made = attr.ib(repr=False)

    log = attr.ib(init=False, default=attr.Factory(loggerFor, takes_self=True))

    def buildProtocol(self, addr):
        return _ConversationProtocol(self, self.connection_made)

    def notify_error(self, error):
        self.log.error(str(error))
        self.peer._ui.notify_error(error)


@attr.s
class _ConversationProtocol(NetstringReceiver, object):
    type_regular = 'reg'
    type_untalk = untalk.UntalkSession.type_
    type_file = FileSession.type_

    factory = attr.ib(
        validator=attr.validators.instance_of(_ConversationFactory))
    connection_made = attr.ib(default=None)
    manager = attr.ib(init=False, default=None)
    type_ = attr.ib(init=False, default=None)

    _lock_send = attr.ib(init=False, default=attr.Factory(Lock))

    log = attr.ib(init=False, default=attr.Factory(loggerFor, takes_self=True))

    def connectionMade(self):
        self.log.info('Connection made')

        if self.connection_made:
            self.log.info('Calling connection made callback: '
                          '{callback.__name__}', callback=self.connection_made)

            self.connection_made(self)

    def add_manager(self, manager, type_=None):
        self.manager = manager
        self.type_ = type_ or _ConversationProtocol.type_regular

        self.log.info('Adding manager of type: {manager.__class__}',
                      manager=manager)

    def remove_manager(self):
        self.log.info('Removing manager')

        self.manager = None
        self.transport.loseConnection()

    def connectionLost(self, reason):
        self.log.info('Connection lost')

        if self.manager:
            # the other party disconnected cleanly without sending a presence
            # element or the connection was actually lost
            # TODO check the different reasons and act accordingly?
            # TODO consider a connection that never had a manager?
            self.log.info('Notifying manager that the other peer disconnected')

            self.manager.notify_disconnect()

    def stringReceived(self, string):
        try:
            if self.type_ in [_ConversationProtocol.type_regular,
                              _ConversationProtocol.type_file]:
                self.manager.receive_data(string, self)
            elif self.type_ == _ConversationProtocol.type_untalk:
                self.manager.receive_data(string)
            else:
                self.factory.notify_error(errors.UnmessageError(
                    message='Connection of unknown type "{}"'.format(
                        str(self.type_))))
        except AttributeError:
            self.factory.notify_error(
                errors.TransportError(
                    message='Packet received without a manager'))

    def send(self, string):
        with self._lock_send:
            if len(string) <= self.MAX_LENGTH:
                self.sendString(string)
            else:
                raise ValueError('A packet with length of {} cannot be send '
                                 '(maximum {})'.format(len(string),
                                                       self.MAX_LENGTH))


MANAGER_CLASSES = [untalk.UntalkSession,
                   FileSession]


def get_manager_class(element):
    try:
        return [manager_class
                for manager_class in MANAGER_CLASSES
                if type(element) in manager_class.element_classes][0]
    except IndexError:
        return errors.ManagerNotFoundError(type(element))


def keyed_hash(key, data):
    return hmac.new(key, data, sha256).digest()


def create_arg_parser(name, add_remote_mode=False):
    return ui.create_arg_parser(description='''{}'''.format(APP_NAME),
                                name=name,
                                local_server_ip=HOST,
                                tor_socks_port=TOR_SOCKS_PORT,
                                tor_control_port=TOR_CONTROL_PORT,
                                add_remote_mode=add_remote_mode)
