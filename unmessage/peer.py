import ConfigParser
import errno
import hmac
import os
import re
import sqlite3
import thread
from hashlib import sha256
from Queue import Queue
from threading import Event, Lock, Thread

import pyaxo
import pyperclip
import txsocksx.errors
import txtorcon
from nacl.utils import random
from nacl.exceptions import CryptoError
from pyaxo import Axolotl, Keypair, a2b, b2a
from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.internet.endpoints import connectProtocol
from twisted.internet.endpoints import TCP4ClientEndpoint, TCP4ServerEndpoint
from twisted.internet.protocol import Factory
from twisted.protocols.basic import NetstringReceiver
from txtorcon import TorClientEndpoint

from . import elements
from . import errors
from . import notifications
from . import packets
from . import requests
from .contact import Contact
from .elements import RequestElement, PresenceElement
from .elements import MessageElement, AuthenticationElement
from .ui import ConversationUi, PeerUi
from .utils import Address
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
PORT = 50000

TOR_PORT = 9054
TOR_CONTROL_PORT = 9055


class _ConversationFactory(Factory):
    def __init__(self, peer, connection_made):
        self.peer = peer
        self.connection_made = connection_made

    def buildProtocol(self, addr):
        return _ConversationProtocol(self, self.connection_made)

    def notify_error(self, error):
        self.peer._ui.notify_error(error)


class _ConversationProtocol(NetstringReceiver):
    def __init__(self, factory, connection_made):
        self.factory = factory
        self.connection_made = connection_made
        self.manager = None

    def connectionMade(self):
        self.connection_made(self)

    def add_manager(self, manager):
        self.manager = manager

    def remove_manager(self):
        self.manager = None
        self.transport.loseConnection()

    def connectionLost(self, reason):
        if self.manager:
            # the other party disconnected cleanly without sending a presence
            # element or the connection was actually lost
            # TODO check the different reasons and act accordingly?
            # TODO consider a connection that never had a manager?
            self.manager.notify_disconnect()

    def stringReceived(self, string):
        try:
            self.manager.queue_in_data.put(string)
        except AttributeError:
            self.factory.notify_error(
                errors.TransportError(
                    message='Packet received without a manager'))

    def send(self, string):
        self.sendString(string)


class Peer(object):
    def __init__(self, name, ui=None):
        if not name:
            raise errors.InvalidNameError()

        self._info = PeerInfo(port_local_server=PORT)
        self._name = name
        self._persistence = Persistence(dbname=self._path_peer_db,
                                        dbpassphrase=None)
        self._axolotl = None
        self._conversations = dict()
        self._inbound_requests = dict()
        self._outbound_requests = dict()
        self._element_parser = ElementParser(self)

        self._port_tor = TOR_PORT
        self._port_tor_control = TOR_CONTROL_PORT

        self._local_mode = False
        self._use_tor_proxy = True

        self._tor_config = None

        self._twisted_reactor = reactor
        self._twisted_server_endpoint = None
        self._twisted_factory = None

        self._managers_conv = list()

        self._presence_convs = list()
        self._presence_event = Event()

        self._event_stop = Event()

        self._ui = ui or PeerUi()

    @property
    def _path_peer_dir(self):
        return os.path.join(APP_DIR, self.name)

    @property
    def _path_peer_db(self):
        return os.path.join(self._path_peer_dir, 'peer.db')

    @property
    def _path_axolotl_db(self):
        return os.path.join(self._path_peer_dir, 'axolotl.db')

    @property
    def _path_tor_dir(self):
        return os.path.join(self._path_peer_dir, 'tor')

    @property
    def _path_tor_data_dir(self):
        return os.path.join(self._path_tor_dir, 'data')

    @property
    def _path_onion_service_dir(self):
        return os.path.join(self._path_tor_dir, 'onion-service')

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
    def address(self):
        try:
            onion_server = open(os.path.join(
                self._path_onion_service_dir, 'hostname'), 'r').read().strip()
        except IOError as e:
            if e.errno == errno.ENOENT:
                onion_server = 'hostname-not-found'
            else:
                raise
        return Address(onion_server, self._port_local_server)

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

    def _create_peer_dir(self):
        if not os.path.exists(self._path_peer_dir):
            os.makedirs(self._path_peer_dir)
        if not os.path.exists(self._path_tor_dir):
            os.makedirs(self._path_tor_dir)

    def _load_peer_info(self):
        if os.path.exists(self._path_peer_db):
            self._info = self._persistence.load_peer_info()

    def _update_config(self):
        if not CONFIG.has_section('unMessage'):
            CONFIG.add_section('unMessage')
        CONFIG.set('unMessage', 'ui', self._ui.__module__)
        CONFIG.set('unMessage', 'name', self.name)

        with open(CONFIG_FILE, 'w') as f:
            CONFIG.write(f)

    def _save_peer_info(self):
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

    def _send_presence(self, offline=False):
        self._presence_convs = list()
        self._presence_event = Event()

        for c in self.conversations:
            if c.contact.has_presence:
                if offline and c.is_active:
                    self._presence_convs.append(c.contact.name)
                    self._send_element(c, PresenceElement.type_,
                                       content=PresenceElement.status_offline)
                elif not offline and not c.is_active:
                    self._send_element(c, PresenceElement.type_,
                                       content=PresenceElement.status_online)

        if self._presence_convs:
            # wait until all conversations are notified
            self._presence_event.wait()

    def _add_intro_manager(self, connection):
        manager = Introduction(self, connection)
        self._managers_conv.append(manager)
        manager.start()
        return manager

    def _connect(self, address, callback, errback):
        if self._use_tor_proxy:
            point = TorClientEndpoint(address.host, address.port,
                                      socks_hostname=HOST,
                                      socks_port=self._port_tor)
        else:
            if self._local_mode:
                host = HOST
            else:
                host = address.host

            point = TCP4ClientEndpoint(self._twisted_reactor,
                                       host=host, port=address.port)

        def connect_from_thread():
            d = connectProtocol(point,
                                _ConversationProtocol(self._twisted_factory,
                                                      callback))
            d.addErrback(errback)

        self._twisted_reactor.callFromThread(connect_from_thread)

    def _create_request(self, contact):
        """Create an ``OutboundRequest`` to be sent to a ``Contact``."""
        iv = random(packets.IV_LEN)

        req = requests.OutboundRequest(Conversation(self, contact))
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
        req_packet = packets.build_request_packet(data)
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

            req_packet.handshake_packet = packets.build_handshake_packet(
                dec_hs_packet)

            contact = Contact(req_packet.handshake_packet.identity,
                              a2b(req_packet.handshake_packet.identity_key))
            conv = Conversation(self, contact, request_keys=request_keys)

            return requests.InboundRequest(
                conversation=conv,
                packet=req_packet)
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
        axolotl.save()

        conv.axolotl = axolotl
        conv.state = Conversation.state_conv
        conv.keys = ConversationKeys(axolotl.id_)

        self._contacts[conv.contact.name] = conv.contact
        self._conversations[conv.contact.name] = conv
        self._ui.notify_conv_established(
            notifications.ConversationNotification(
                conv,
                title='Conversation established',
                message='You can now chat with {}'.format(conv.contact.name)))

    def _delete_conversation(self, conversation):
        conversation.close()
        conversation.axolotl.delete()
        del self._contacts[conversation.contact.name]
        del self._conversations[conversation.contact.name]

    def _send_element(self, conv, type_, content, handshake_key=None):
        """Create an ``ElementPacket`` and add it to the outbout packets queue.

        TODO
            - Size invariance should be handled here, before encryption by
              ``_send_packet``
            - Split the element into multiple packets if needed
        """
        packet = packets.ElementPacket(type_, payload=content)
        conv.queue_out_packets.put([packet, conv, handshake_key])

    def _send_packet(self, packet, conversation, handshake_key=None):
        """Encrypt an ``ElementPacket`` as a ``RegularPacket`` and send it.

        Before proceding, make sure the conversation has a connection. Wrap the
        element packet with the regular encrypted packet and send it. After
        successfully transmitting it, process it and parse the element.
        """
        def element_sent():
            element = self._process_element_packet(
                packet,
                conversation,
                sender=self.name,
                receiver=conversation.contact.name)
            self._element_parser.parse(element, conversation)

        def element_not_sent(failure):
            # TODO handle remaining packets
            conversation.close()

            # TODO handle expected errors and display better messages
            conversation.ui.notify_disconnect(
                notifications.UnmessageNotification(str(failure)))

        def send_with_manager(manager):
            # at this point there is already an existing conversation between
            # the two parties in the database, so a ``RegularPacket`` can be
            # created with ``_encrypt``
            reg_packet = self._encrypt(packet, conversation, handshake_key)

            # pack the ``RegularPacket`` into a ``str`` and send it
            manager.send_data(str(reg_packet),
                              callback=element_sent,
                              errback=element_not_sent)

        if conversation.is_active:
            send_with_manager(conversation)
        else:
            def connection_made(connection):
                conversation.set_active(connection, Conversation.state_conv)
                send_with_manager(conversation)

            def connection_failed(failure):
                if packet.type_ != PresenceElement.type_:
                    if failure.check(txsocksx.errors.HostUnreachable,
                                     txsocksx.errors.TTLExpired):
                        conversation.ui.notify_offline(
                            errors.HostUnreachableError())
                    else:
                        conversation.ui.notify_error(errors.UnmessageError(
                            title='Conversation connection failed',
                            message=str(failure)))

            # the peer connects to the other one to resume a conversation
            self._connect(conversation.contact.address,
                          callback=connection_made,
                          errback=connection_failed)

    def _receive_packet(self, packet, conversation):
        """Decrypt a ``RegularPacket`` as an ``ElementPacket``.

        Unwrap the element packet with decryption, process it and parse the
        element.
        """
        try:
            regular_packet = self._decrypt(packet, conversation)
        except (errors.MalformedPacketError, errors.CorruptedPacketError) as e:
            e.title += ' caused by "{}"'.format(conversation.contact.name)
            self.peer.notify_error(e)
        else:
            element = self._process_element_packet(
                packet=regular_packet,
                conversation=conversation,
                sender=conversation.contact.name,
                receiver=self.name)
            self._element_parser.parse(element, conversation)

    def _process_element_packet(self, packet, conversation, sender, receiver):
        with conversation.elements_lock:
            try:
                # get the ``Element`` that corresponds to the
                # ``ElementPacket.id_`` in case it is one of the parts of an
                # incomplete element
                element = conversation.elements.pop(packet.id_)
            except KeyError:
                # create an ``Element`` as there are no incomplete elements
                # with the respective ``ElementPacket.id_``
                element = elements.Element(sender,
                                           receiver,
                                           type_=packet.type_,
                                           id_=packet.id_,
                                           part_len=packet.part_len)

            # add the part from the packet
            element[packet.part_num] = packet.payload

            if element.is_complete:
                # the ``Element`` does not have to be stored as either it
                # fitted in a single packet or all of its parts have been
                # transmitted (the ``packet`` contained the last remaining
                # part)
                pass
            else:
                # store the ``Element`` in the incomplete elements ``dict`` as
                # it has been split in multiple parts, yet to be transmitted
                conversation.elements[element.id_] = element
            return element

    def _encrypt(self, packet, conversation, handshake_key=None):
        """Encrypt an ``ElementPacket`` and return a ``RegularPacket``."""
        iv = random(packets.IV_LEN)
        plaintext = str(packet)
        if handshake_key:
            keys = conversation.request_keys
            handshake_key = pyaxo.encrypt_symmetric(keys.handshake_enc_key,
                                                    handshake_key)
        else:
            keys = conversation.keys
            handshake_key = ''

        ciphertext = conversation.axolotl.encrypt(plaintext)
        conversation.axolotl.save()

        return packets.RegularPacket(
            b2a(iv),
            b2a(pyaxo.hash_(iv + conversation.contact.key + keys.iv_hash_key)),
            b2a(keyed_hash(keys.payload_hash_key, handshake_key + ciphertext)),
            b2a(handshake_key),
            b2a(ciphertext))

    def _decrypt(self, packet, conversation):
        """Decrypt a ``RegularPacket`` and return an ``ElementPacket``."""
        ciphertext = a2b(packet.payload)
        keys = conversation.keys or conversation.request_keys
        payload_hash = keyed_hash(keys.payload_hash_key,
                                  a2b(packet.handshake_key) + ciphertext)

        if payload_hash == a2b(packet.payload_hash):
            plaintext = conversation.axolotl.decrypt(ciphertext)
            conversation.axolotl.save()
            return packets.build_element_packet(plaintext)
        else:
            raise errors.CorruptedPacketError()

    def _start_server(self, start_tor_socks, start_onion_server):
        self._ui.notify_bootstrap(
            notifications.UnmessageNotification('Configuring local server'))

        endpoint = TCP4ServerEndpoint(self._twisted_reactor,
                                      self._port_local_server,
                                      interface=HOST)
        self._twisted_server_endpoint = endpoint

        d = Deferred()

        def endpoint_listening(port):
            self._ui.notify_bootstrap(
                notifications.UnmessageNotification('Running local server'))

            d_tor = self._config_tor(start_tor_socks, start_onion_server)
            if d_tor:
                d_tor.addCallbacks(d.callback, d.errback)
            else:
                d.callback(port)

        self._twisted_factory = _ConversationFactory(
            peer=self,
            connection_made=self._add_intro_manager)

        d_server = endpoint.listen(self._twisted_factory)
        d_server.addCallbacks(endpoint_listening, d.errback)

        def run_reactor():
            self._ui.notify_bootstrap(
                notifications.UnmessageNotification('Running reactor'))

            # TODO improve the way the reactor is run
            self._twisted_reactor.run(installSignalHandlers=0)
        thread.start_new_thread(run_reactor, ())

        return d

    def _config_tor(self, start_tor_socks, start_onion_server):
        if start_tor_socks or start_onion_server:
            self._ui.notify_bootstrap(
                notifications.UnmessageNotification('Configuring Tor'))

            config = txtorcon.TorConfig()
            config.DataDirectory = self._path_tor_data_dir
            config.ControlPort = self._port_tor_control

            if start_tor_socks:
                self._ui.notify_bootstrap(
                    notifications.UnmessageNotification(
                        'Configuring Tor SOCKS port'))

                config.SocksPort = self._port_tor
            else:
                self._ui.notify_bootstrap(
                    notifications.UnmessageNotification(
                        "Using the system's Tor SOCKS port"))

            if start_onion_server:
                self._ui.notify_bootstrap(
                    notifications.UnmessageNotification(
                        'Configuring Onion Service'))

                config.HiddenServices = [
                    txtorcon.HiddenService(
                        config,
                        self._path_onion_service_dir,
                        ['{} {}:{}'.format(self._port_local_server,
                                           HOST,
                                           self._port_local_server)]
                    )
                ]
            else:
                self._ui.notify_bootstrap(
                    notifications.UnmessageNotification(
                        "Using the system's Onion Service"))

            config.save()

            self._tor_config = config

            def display_bootstrap_lines(prog, tag, summary):
                self._ui.notify_bootstrap(
                    notifications.UnmessageNotification(
                        '{}%: {}'.format(prog, summary)))

            return txtorcon.launch_tor(
                config, self._twisted_reactor,
                progress_updates=display_bootstrap_lines)
        else:
            self._ui.notify_bootstrap(
                notifications.UnmessageNotification(
                    "Using the system's Tor SOCKS port and Onion Service"))
            return None

    def _send_request(self, identity, key):
        result = re.match(r'[^@]+@[^:]+(:(\d+))?$', identity)
        port = result.group(2)
        if not port:
            identity += ':' + str(PORT)

        contact = Contact(identity, key)
        req = self._create_request(contact)

        def connection_made(connection):
            def request_sent():
                self._outbound_requests[contact.identity] = req
                self._ui.notify_out_request(
                    notifications.ContactNotification(
                        contact,
                        title='Request sent',
                        message='{} has received your request'.format(
                            identity)))

            def request_failed(failure):
                # TODO handle expected errors and display better messages
                self._ui.notify_error(errors.UnmessageError(
                    title='Request packet failed',
                    message=str(failure)))

            conv = req.conversation
            conv.start()
            conv.set_active(connection, Conversation.state_out_req)

            # pack the ``RequestPacket`` into a ``str`` and send it to the
            # other peer
            conv.send_data(str(req.packet),
                           callback=request_sent,
                           errback=request_failed)

        def connection_failed(failure):
            if failure.check(txsocksx.errors.HostUnreachable,
                             txsocksx.errors.TTLExpired):
                self._ui.notify_error(errors.HostUnreachableError())
            else:
                self._ui.notify_error(errors.UnmessageError(
                    title='Request connection failed',
                    message=str(failure)))

        self._connect(contact.address,
                      callback=connection_made,
                      errback=connection_failed)

    def _accept_request(self, request, new_name):
        conv = request.conversation

        if new_name:
            address = re.match(r'[^@]+(@[^:]+:\d+)', conv.contact.identity)
            conv.contact.identity = new_name + address.group(1)

        handshake_keys = pyaxo.generate_keypair()
        self._init_conv(
            conv,
            priv_handshake_key=handshake_keys.priv,
            other_handshake_key=a2b(
                request.packet.handshake_packet.handshake_key),
            other_ratchet_key=a2b(
                request.packet.handshake_packet.ratchet_key),
            mode=True)

        self._send_element(conv,
                           RequestElement.type_,
                           content=RequestElement.request_accepted,
                           handshake_key=handshake_keys.pub)

    def _send_message(self, conversation, plaintext):
        self._send_element(conversation,
                           MessageElement.type_,
                           content=plaintext)

    def _authenticate(self, conversation, secret):
        auth_session = conversation.auth_session
        if not auth_session or auth_session.is_waiting or \
                auth_session.is_authenticated is not None:
            auth_session = conversation.init_auth()
        # TODO maybe use locks or something to prevent advancing or restarting
        # while the SMP is doing its math
        self._send_element(conversation,
                           AuthenticationElement.type_,
                           content=auth_session.start(
                               conversation.keys.auth_secret_key + secret))

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

    def start(self, local_server_port=None,
              start_tor_socks=True,
              use_tor_proxy=True,
              tor_port=None,
              start_onion_server=True,
              tor_control_port=None,
              local_mode=False):
        if local_mode:
            start_tor_socks = False
            use_tor_proxy = False
            start_onion_server = False
            self._local_mode = local_mode
        self._ui.notify_bootstrap(
            notifications.UnmessageNotification('Starting peer'))

        self._create_peer_dir()
        self._load_peer_info()
        self._update_config()

        if local_server_port:
            self._port_local_server = int(local_server_port)
        self._use_tor_proxy = use_tor_proxy
        if tor_port:
            self._port_tor = int(tor_port)
        if tor_control_port:
            self._port_tor_control = int(tor_control_port)

        def peer_started(result):
            self._ui.notify_bootstrap(
                notifications.UnmessageNotification('Peer started'))

            self._axolotl = Axolotl(name=self.name,
                                    dbname=self._path_axolotl_db,
                                    dbpassphrase=None,
                                    nonthreaded_sql=False)
            if not self.identity_keys:
                self._identity_keys = pyaxo.generate_keypair()

            self._conversations = self._load_conversations()
            for c in self.conversations:
                c.start()

            self._send_presence()

            # TODO maybe return something useful to the UI?
            self._ui.notify_peer_started(
                notifications.UnmessageNotification(title='Peer started',
                                                    message=str(result)))

        def peer_failed(reason):
            self._ui.notify_bootstrap(
                notifications.UnmessageNotification('Peer failed'))

            self._ui.notify_peer_failed(
                notifications.UnmessageNotification(title='Peer failed',
                                                    message=str(reason)))

        def errback(reason):
            self._ui.notify_error(errors.UnmessageError(str(reason)))

        d = self._start_server(start_tor_socks, start_onion_server)
        d.addCallbacks(peer_started, peer_failed)
        d.addErrback(errback)

    def stop(self):
        self._save_peer_info()

        self._send_presence(offline=True)

        self._event_stop.set()

        for c in self.conversations:
            c.close()

        self._twisted_reactor.callFromThread(self._twisted_reactor.stop)

    def send_request(self, identity, key):
        t = Thread(target=self._send_request, args=(identity, a2b(key),))
        t.daemon = True
        t.start()

    def accept_request(self, identity, new_name=None):
        request = self._inbound_requests.pop(identity)

        t = Thread(target=self._accept_request, args=(request, new_name,))
        t.daemon = True
        t.start()

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

    def send_message(self, name, plaintext):
        t = Thread(target=self._send_message,
                   args=(self.get_conversation(name), plaintext,))
        t.daemon = True
        t.start()

    def authenticate(self, name, secret):
        t = Thread(target=self._authenticate,
                   args=(self.get_conversation(name), secret,))
        t.daemon = True
        t.start()


class Introduction(Thread):
    def __init__(self, peer, connection):
        super(Introduction, self).__init__()
        self.daemon = True

        self.queue_in_data = Queue()

        self.peer = peer
        self.connection = connection

        self.connection.add_manager(self)

    def run(self):
        data = self.queue_in_data.get()
        try:
            self.handle_introduction_data(data)
        except (errors.MalformedPacketError, errors.CorruptedPacketError) as e:
            e.title += ' caused by an unknown peer'
            self.peer._ui.notify_error(e)
            self.connection.remove_manager()

    def handle_introduction_data(self, data):
        packet = packets.build_intro_packet(data)

        for conv in self.peer.conversations:
            keys = conv.keys or conv.request_keys
            iv_hash = pyaxo.hash_(
                a2b(packet.iv) + self.peer.identity_keys.pub +
                keys.iv_hash_key)
            if iv_hash == a2b(packet.iv_hash):
                # the database does have a conversation between the
                # users, so the current connection must be added to the
                # conversation, a manager must be started and then
                # receive the packet using the existing conversation
                conv.set_active(self.connection, Conversation.state_conv)
                conv.queue_in_data.put(data)
                break
        else:
            # the database does not have a conversation between the
            # users, so a request must be created and the UI
            # notified
            req = self.peer._process_request(data)

            conv = req.conversation
            conv.start()
            conv.set_active(self.connection, Conversation.state_in_req)

            contact = req.conversation.contact
            self.peer._inbound_requests[contact.identity] = req
            self.peer._ui.notify_in_request(
                notifications.ContactNotification(
                    contact,
                    title='Request received',
                    message='{} has sent you a '
                            'request'.format(contact.name)))

        self.peer._managers_conv.remove(self)

    def notify_disconnect(self):
        self.peer._ui.notify(notifications.UnmessageNotification(
            'An unknown peer has disconnected without sending any data'))


class Conversation(object):
    state_in_req = 'in_req'
    state_out_req = 'out_req'
    state_conv = 'conv'

    def __init__(self, peer, contact,
                 request_keys=None, keys=None, axolotl=None, connection=None):
        self.peer = peer
        self.ui = ConversationUi()

        self.contact = contact
        self.request_keys = request_keys
        self.keys = keys
        self.axolotl = axolotl
        self.auth_session = None

        self.connection = connection
        self.queue_in_data = Queue()
        self.queue_out_data = Queue()
        self.queue_in_packets = Queue()
        self.queue_out_packets = Queue()

        self.elements = dict()
        self.elements_lock = Lock()

        self.is_active = False

        self.thread_in_data = Thread(target=self.check_in_data)
        self.thread_in_data.daemon = True
        self.thread_out_data = Thread(target=self.check_out_data)
        self.thread_out_data.daemon = True
        self.thread_in_packets = Thread(target=self.check_in_packets)
        self.thread_in_packets.daemon = True
        self.thread_out_packets = Thread(target=self.check_out_packets)
        self.thread_out_packets.daemon = True

    def start(self):
        self.thread_in_data.start()
        self.thread_out_data.start()
        self.thread_in_packets.start()
        self.thread_out_packets.start()

    @property
    def is_authenticated(self):
        try:
            return self.auth_session.is_authenticated
        except AttributeError:
            # the session has not been initialized
            return None

    def check_in_data(self):
        while True:
            data = self.queue_in_data.get()
            try:
                method = getattr(self, 'handle_{}_data'.format(self.state))
                method(data)
            except AttributeError:
                # the state does not have a "handle" method, which currently is
                # state_in_req because it should be waiting for the request to
                # be accepted (by the user) and meanwhile no more data should
                # be received from the other party
                # TODO maybe disconnect instead of ignoring the data
                pass
            except (errors.MalformedPacketError,
                    errors.CorruptedPacketError) as e:
                e.title += ' caused by "{}"'.format(self.contact.name)
                self.peer._ui.notify_error(e)

    def check_out_data(self):
        while True:
            data, callback, errback = self.queue_out_data.get()
            try:
                self.connection.send(data)
            except Exception as e:
                errback(errors.UnmessageError(title=type(e),
                                              message=e.message))
            else:
                callback()

    def check_in_packets(self):
        while True:
            args = self.queue_in_packets.get()
            self.peer._receive_packet(*args)

    def check_out_packets(self):
        while True:
            args = self.queue_out_packets.get()
            self.peer._send_packet(*args)

    def send_data(self, data, callback, errback):
        self.queue_out_data.put([data, callback, errback])

    def handle_conv_data(self, data):
        packet = packets.build_regular_packet(data)
        self.queue_in_packets.put([packet, self])

    def handle_out_req_data(self, data):
        packet = packets.build_reply_packet(data)
        req = self.peer._outbound_requests[self.contact.identity]
        enc_handshake_key = a2b(packet.handshake_key)

        payload_hash = keyed_hash(
            req.conversation.request_keys.payload_hash_key,
            enc_handshake_key + a2b(packet.payload))

        if payload_hash == a2b(packet.payload_hash):
            # the regular packet provides a handshake key, making it possible
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

            self.peer._init_conv(
                self,
                priv_handshake_key=req.handshake_keys.priv,
                other_handshake_key=handshake_key,
                ratchet_keys=req.ratchet_keys)
        else:
            # TODO maybe disconnect instead of ignoring the data
            pass

    def set_active(self, connection, state):
        connection.add_manager(self)
        self.connection = connection
        self.state = state
        self.is_active = True

    def close(self):
        if self.connection:
            self.connection.remove_manager()
            self.connection = None
        self.auth_session = None
        self.is_active = False

    def notify_disconnect(self):
        self.connection = None
        self.auth_session = None
        if self.is_active:
            self.ui.notify_disconnect(
                notifications.UnmessageNotification(
                    '{} has disconnected'.format(self.contact.name)))
            self.is_active = False

    def init_auth(self, buffer_=None):
        self.auth_session = AuthSession(buffer_)
        return self.auth_session


class ConversationKeys:
    handshake_enc_salt = b'\x00'

    iv_hash_salt = b'\x01'
    payload_hash_salt = b'\x02'

    auth_secret_salt = b'\x03'

    def __init__(self, key):
        self.key = key

        self.handshake_enc_key = pyaxo.kdf(key, self.handshake_enc_salt)

        self.iv_hash_key = pyaxo.kdf(key, self.iv_hash_salt)
        self.payload_hash_key = pyaxo.kdf(key, self.payload_hash_salt)

        self.auth_secret_key = pyaxo.kdf(key, self.auth_secret_salt)


class AuthSession:
    def __init__(self, buffer_=None):
        self.smp = None
        self.buffer_ = buffer_
        if self.buffer_:
            # start from step 2 as the initial buffer was received from the
            # other party, who started the session
            self.step = 2
        else:
            # start from step 1 as the initial buffer still has to be sent to
            # the other party, who will advance the session
            self.step = 1

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


class ElementParser:
    def __init__(self, peer):
        self.peer = peer

    def _parse_pres_element(self, element, conversation):
        if str(element) == PresenceElement.status_online:
            conversation.ui.notify_online(
                notifications.UnmessageNotification(
                    '{} is online'.format(conversation.contact.name)))
        elif str(element) == PresenceElement.status_offline:
            if element.sender == self.peer.name:
                # remove the name from the list of pending presence packets and
                # set the event if it was the last one
                self.peer._presence_convs.remove(element.receiver)
                if not self.peer._presence_convs:
                    self.peer._presence_event.set()
            else:
                conversation.close()
                conversation.ui.notify_offline(
                    notifications.UnmessageNotification(
                        '{} is offline'.format(conversation.contact.name)))

    def _parse_msg_element(self, element, conversation):
        conversation.ui.notify_message(
            notifications.ElementNotification(element))

    def _parse_auth_element(self, element, conversation):
        if element.sender == self.peer.name:
            if conversation.auth_session.is_waiting:
                conversation.ui.notify_out_authentication(
                    notifications.UnmessageNotification(
                        title='Authentication started',
                        message='Waiting for {} to advance'.format(
                            conversation.contact.name)))
        else:
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
                    self.peer._send_element(conversation,
                                            type_=AuthenticationElement.type_,
                                            content=next_buffer)
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
                        message=message.format(
                            conversation.contact.name)))

    def parse(self, element, conversation):
        if element.is_complete:
            # it can be parsed as all parts have been added to the ``Element``
            # or it is composed of a single part
            try:
                method = getattr(self,
                                 '_parse_{}_element'.format(element.type_))
            except AttributeError:
                # TODO handle elements with unknown types
                pass
            else:
                method(element, conversation)
        else:
            # the ``Element`` has parts yet to be transmitted (sent/received)
            pass


class PeerInfo:
    def __init__(self, name=None, port_local_server=None, identity_keys=None,
                 contacts=None):
        self.name = name
        self.port_local_server = port_local_server
        self.identity_keys = identity_keys
        self.contacts = contacts or dict()


class Persistence:
    def __init__(self, dbname, dbpassphrase):
        self.dbname = dbname
        self.dbpassphrase = dbpassphrase
        self.db = self._open_db()

    def _open_db(self):
        db = sqlite3.connect(':memory:', check_same_thread=False)
        db.row_factory = sqlite3.Row

        with db:
            try:
                with open(self.dbname, 'r') as f:
                    sql = f.read()
                    db.cursor().executescript(sql)
            except IOError as e:
                if e.errno == errno.ENOENT:
                    self._create_db(db)
                else:
                    raise
        return db

    def _create_db(self, db):
        db.execute('''
            CREATE TABLE IF NOT EXISTS
                peer (
                    name TEXT,
                    port_local_server INTEGER,
                    priv_identity_key TEXT,
                    pub_identity_key TEXT)''')
        db.execute('''
            CREATE UNIQUE INDEX IF NOT EXISTS
                peer_name
            ON
                peer (name)''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS
                contacts (
                    identity TEXT,
                    key TEXT,
                    is_verified INTEGER,
                    has_presence INTEGER)''')
        db.execute('''
            CREATE UNIQUE INDEX IF NOT EXISTS
                contact_identity
            ON
                contacts (identity)''')

    def _write_db(self):
        with self.db as db:
            sql = bytes('\n'.join(db.iterdump()))
            with open(self.dbname, 'w') as f:
                f.write(sql)

    def load_peer_info(self):
        with self.db as db:
            cur = db.cursor()
            cur.execute('''
                SELECT
                    *
                FROM
                    peer''')
            row = cur.fetchone()
        if row:
            identity_keys = Keypair(a2b(row['priv_identity_key']),
                                    a2b(row['pub_identity_key']))
            port_local_server = int(row['port_local_server'])
            name = str(row['name'])
        else:
            identity_keys = None
            port_local_server = None
            name = None

        with self.db as db:
            rows = db.execute('''
                SELECT
                    *
                FROM
                    contacts''')
        contacts = dict()
        for row in rows:
            c = Contact(str(row['identity']),
                        a2b(row['key']),
                        bool(row['is_verified']),
                        bool(row['has_presence']))
            contacts[c.name] = c

        return PeerInfo(name, port_local_server, identity_keys, contacts)

    def save_peer_info(self, peer_info):
        with self.db as db:
            db.execute('''
                DELETE FROM
                    peer''')
            if peer_info.identity_keys:
                db.execute('''
                    INSERT INTO
                        peer (
                            name,
                            port_local_server,
                            priv_identity_key,
                            pub_identity_key)
                    VALUES (?, ?, ?, ?)''', (
                        peer_info.name,
                        peer_info.port_local_server,
                        b2a(peer_info.identity_keys.priv),
                        b2a(peer_info.identity_keys.pub)))
            db.execute('''
                DELETE FROM
                    contacts''')
            for c in peer_info.contacts.values():
                db.execute('''
                    INSERT INTO
                        contacts (
                            identity,
                            key,
                            is_verified,
                            has_presence)
                    VALUES (?, ?, ?, ?)''', (
                        c.identity,
                        b2a(c.key),
                        int(c.is_verified),
                        int(c.has_presence)))

        self._write_db()


def keyed_hash(key, data):
    return hmac.new(key, data, sha256).digest()
