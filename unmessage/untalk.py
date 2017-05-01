from contextlib import contextmanager
from ctypes import CFUNCTYPE, cdll, c_char_p, c_int
from Queue import Queue
from threading import Thread
from time import time

import pyaudio
import pyaxo
from nacl.secret import SecretBox
from opuslib.api import constants as opus_constants
from opuslib.api import ctl as opus_ctl
from opuslib.api import decoder as opus_decoder
from opuslib.api import encoder as opus_encoder

from . import errors
from . import notifications
from .elements import UntalkElement


FORMAT = pyaudio.paInt16
CHANNELS = 1  # mono
SAMPLE_SIZE = 2  # 16 bits as bytes
SAMPLE_RATE = 48000  # max rate
FRAME_SIZE = 960  # 20 ms at 48000
LOSS_PERCENTAGE = 2

DEFAULT_DEVICE = 'default'
INPUT_DEVICE = DEFAULT_DEVICE
OUTPUT_DEVICE = 'pulse'

DECODE_FEC = False

MAC_SIZE = 16


class UntalkSession(object):
    type_ = UntalkElement.type_
    state_sent = 'sent'
    state_received = 'rcv'
    state_talking = 'talk'
    state_stopped = 'stop'

    def __init__(self, conversation, other_handshake_key=None):
        self.conversation = conversation
        self.other_handshake_key = other_handshake_key
        self.connection = None
        self.handshake_keys = pyaxo.generate_keypair()
        if other_handshake_key:
            self.state = UntalkSession.state_received
        else:
            self.state = UntalkSession.state_sent
        self.shared_key = None

        self.thread_listen = Thread(target=self.listen)
        self.thread_listen.daemon = True
        self.thread_speak = Thread(target=self.speak)
        self.thread_speak.daemon = True

        self.jitter_buffer = None
        self.codec = None
        with suppress_alsa_errors():
            self.audio_listen = pyaudio.PyAudio()
            self.audio_speak = pyaudio.PyAudio()
        self.stream_in = None
        self.stream_out = None

        self.input_device = None
        self.output_device = None
        self.frame_size = FRAME_SIZE
        self.loss_percentage = LOSS_PERCENTAGE
        self.decode_fec = DECODE_FEC

    @property
    def is_talking(self):
        return self.state == UntalkSession.state_talking

    @property
    def packet_length(self):
        return float(self.frame_size) / SAMPLE_RATE * 1000

    @property
    def decoded_size(self):
        return SAMPLE_SIZE * self.frame_size * CHANNELS

    @property
    def encoded_size(self):
        return self.decoded_size / 15

    @property
    def encrypted_size(self):
        return SecretBox.NONCE_SIZE + MAC_SIZE + self.encoded_size

    def configure(self, input_device=None, output_device=None,
                  frame_size=None, loss_percentage=None,
                  decode_fec=None):
        devices = get_audio_devices()
        if not devices:
            raise NoAudioDevicesAvailableError()

        if input_device is None:
            try:
                self.input_device = devices[INPUT_DEVICE]
            except KeyError:
                raise DefaultAudioDeviceNotFoundError(direction='input')
        else:
            self.input_device = int(input_device)

        if output_device is None:
            try:
                self.output_device = devices[OUTPUT_DEVICE]
            except KeyError:
                try:
                    self.output_device = devices[DEFAULT_DEVICE]
                except KeyError:
                    raise DefaultAudioDeviceNotFoundError(direction='output')
        else:
            self.output_device = int(output_device)

        if self.input_device not in devices.values():
            raise AudioDeviceNotFoundError(direction='input',
                                           index=self.input_device)
        if self.output_device not in devices.values():
            raise AudioDeviceNotFoundError(direction='output',
                                           index=self.output_device)

        if frame_size:
            self.frame_size = int(frame_size)
        if loss_percentage is not None:
            self.loss_percentage = int(loss_percentage)
        if decode_fec is not None:
            self.decode_fec = int(decode_fec)

        self.jitter_buffer = Queue()
        self.codec = OpusCodec(self)

    def start(self, other_handshake_key=None):
        if other_handshake_key:
            self.other_handshake_key = other_handshake_key

            # the handshake key was passed because the other peer accepted the
            # request, sent their key and are ready to receive audio
            speak_first = True
        else:
            # the handshake key was not passed because it was previously
            # received along with the request, which means this peer is already
            # able to derive the shared key and start listening, but cannot
            # speak until the other peer receives the confirmation with the key
            speak_first = False

        self.shared_key = pyaxo.generate_3dh(
            self.conversation.peer.identity_keys.priv,
            self.handshake_keys.priv,
            self.conversation.contact.key,
            self.other_handshake_key,
            mode=self.state == UntalkSession.state_received)

        # configure adaptive jitter buffer (AJB)
        self.oldtime = time() * 1000.
        self.jitter = 0
        self.beta = 1. / 8.
        self.qsize = 10

        self.state = UntalkSession.state_talking

        self.thread_listen.start()
        if speak_first:
            self.thread_speak.start()

        self.conversation.ui.notify(notifications.UntalkNotification(
            'conversation with {} has started'.format(
                self.conversation.contact.name)))

    def stop(self):
        if self.connection:
            self.connection.remove_manager()
        self.state = UntalkSession.state_stopped

        self.conversation.ui.notify(notifications.UntalkNotification(
            'conversation with {} has ended'.format(
                self.conversation.contact.name)))

    def notify_disconnect(self):
        self.connection = None
        self.conversation.remove_manager(self)

    def receive_data(self, data):
        if self.is_talking:
            # the handshake is complete and the peer is already listening

            if not self.thread_speak.is_alive():
                # if the peer was not speaking already, now they are allowed to
                # do so because the other peer has completed the handshake as
                # well, is currently sending audio and therefore is also ready
                # to receive audio
                self.thread_speak.start()

            # lostcount += 1
            try:
                cipheraudio = data
                assert len(cipheraudio) == self.encrypted_size
                plainaudio = pyaxo.decrypt_symmetric(self.shared_key,
                                                     cipheraudio)
                audio = self.codec.decode(plainaudio)
                if self.jitter_buffer.qsize() < self.qsize:
                    self.jitter_buffer.put_nowait(audio)
                self.newtime = time() * 1000.
                self.jitter = (
                    (1. - self.beta)*self.jitter +
                    (abs(self.newtime - self.oldtime - self.packet_length) -
                     self.jitter)*self.beta)
                if self.jitter * 0.75 >= self.qsize and self.qsize < 35:
                    self.qsize += 1
                elif self.jitter * 0.25 < self.qsize and self.qsize > 10:
                    self.qsize -= 1
                self.oldtime = self.newtime
            except Exception as e:
                self.conversation.peer._ui.notify_error(
                    errors.UntalkError(
                        message='{}: {}'.format(str(type(e)), e.message)))
        else:
            # the handshake still has to be completed using the handshake key
            # within this data and is processed as a regular packet
            self.conversation.queue_in_data.put([data, self.connection])

    def send_data(self, data, callback, errback):
        try:
            self.connection.send(data)
        except Exception as e:
            self.conversation.peer._ui.notify_error(
                errors.UntalkError(
                    message='{}: {}'.format(str(type(e)), e.message)))
        else:
            callback()

    def listen(self):
        try:
            self.stream_out = self.audio_listen.open(
                format=FORMAT,
                channels=CHANNELS,
                rate=SAMPLE_RATE,
                output=True,
                output_device_index=self.output_device)

            with suppress_alsa_errors():
                while self.is_talking:
                    audio = self.jitter_buffer.get()
                    self.stream_out.write(audio)
        except Exception as e:
            self.conversation.peer._ui.notify_error(
                errors.UntalkError(
                    message='{}: {}'.format(str(type(e)), e.message)))
            self.stop()
        self.audio_listen.terminate()

    def speak(self):
        try:
            self.stream_in = self.audio_speak.open(
                format=FORMAT,
                channels=CHANNELS,
                rate=SAMPLE_RATE,
                input=True,
                input_device_index=self.input_device,
                frames_per_buffer=self.frame_size)
            self.stream_in.stop_stream()
            self.stream_in.start_stream()

            with suppress_alsa_errors():
                while self.is_talking:
                    audio = self.stream_in.read(self.frame_size,
                                                exception_on_overflow=False)
                    assert len(audio) == self.decoded_size
                    plainaudio = self.codec.encode(audio)
                    assert len(plainaudio) == self.encoded_size
                    cipheraudio = pyaxo.encrypt_symmetric(self.shared_key,
                                                          plainaudio)
                    assert len(cipheraudio) == self.encrypted_size
                    try:
                        self.connection.send(cipheraudio)
                    except AttributeError:
                        # the peer has disconnected
                        break
        except Exception as e:
            self.conversation.peer._ui.notify_error(
                errors.UntalkError(
                    message='{}: {}'.format(str(type(e)), e.message)))
            self.stop()
        self.audio_speak.terminate()


class OpusCodec:
    """
    opuslib from:
    https://github.com/OnBeep/opuslib
    OpusCodec class modified from:
    https://stackoverflow.com/questions/17728706/python-portaudio-opus-encoding-decoding
    """
    def __init__(self, untalk):
        self.untalk = untalk
        self.encoder = opus_encoder.create(SAMPLE_RATE,
                                           CHANNELS,
                                           opus_constants.APPLICATION_VOIP)
        self.decoder = opus_decoder.create(SAMPLE_RATE,
                                           CHANNELS)

        # disable variable bitrate (VBR)
        opus_encoder.ctl(self.encoder,
                         opus_ctl.set_vbr,
                         0)

        # configure expected jitter loss
        opus_encoder.ctl(self.encoder,
                         opus_ctl.set_packet_loss_perc,
                         self.untalk.loss_percentage)

        # configure forward error correction (FEC)
        opus_encoder.ctl(self.encoder,
                         opus_ctl.set_inband_fec,
                         self.untalk.decode_fec)

    def encode(self, data):
        return opus_encoder.encode(self.encoder,
                                   pcm=data,
                                   frame_size=self.untalk.frame_size,
                                   max_data_bytes=len(data))

    def decode(self, data):
        return opus_decoder.decode(self.decoder,
                                   data,
                                   length=len(data),
                                   frame_size=self.untalk.frame_size,
                                   decode_fec=self.untalk.decode_fec,
                                   channels=CHANNELS)


class AudioDeviceNotFoundError(errors.UntalkError):
    def __init__(self, direction, index):
        super(AudioDeviceNotFoundError, self).__init__(
            message='The {} device at index {} could not be '
                    'found'.format(direction, index))


class DefaultAudioDeviceNotFoundError(errors.UntalkError):
    def __init__(self, direction):
        super(DefaultAudioDeviceNotFoundError, self).__init__(
            message='The {} device could not be found automatically - you '
                    'must provide its index manually'.format(direction))


class NoAudioDevicesAvailableError(errors.UntalkError):
    def __init__(self):
        super(NoAudioDevicesAvailableError, self).__init__(
            message='There are no audio devices available')


def get_audio_devices():
    devices = dict()
    with suppress_alsa_errors():
        audio = pyaudio.PyAudio()
    for i in range(audio.get_device_count()):
        d = audio.get_device_info_by_index(i)
        devices[d['name']] = d['index']
    return devices


"""
Workaround functions to suppress ALSA error messages, taken from
https://stackoverflow.com/a/17673011
"""


def handle_error(filename, line, function, err, fmt):
    pass


ERROR_HANDLER_FUNC = CFUNCTYPE(None,
                               c_char_p, c_int, c_char_p, c_int, c_char_p)
C_ERROR_HANDLER = ERROR_HANDLER_FUNC(handle_error)


@contextmanager
def suppress_alsa_errors():
    asound = cdll.LoadLibrary('libasound.so')
    asound.snd_lib_error_set_handler(C_ERROR_HANDLER)
    yield
    asound.snd_lib_error_set_handler(None)
