#!/usr/bin/env python
import ConfigParser
import sys

from .cli import Cli
from .gui import Gui
from .log import Logger
from .peer import CONFIG, create_arg_parser


log = Logger()


def launch_cli(name=None, from_own_entry_point=True):
    if from_own_entry_point:
        log.debug('Launching unMessage from the `unmessage-cli` entry point')

    def create_ui(reactor):
        return Cli(reactor)

    launch(create_ui, name, add_remote_mode=True)


def launch_gui(name=None, from_own_entry_point=True):
    if from_own_entry_point:
        log.debug('Launching unMessage from the `unmessage-gui` entry point')

    def create_ui(reactor):
        from twisted.internet import tksupport

        gui = Gui(reactor)
        tksupport.install(gui)
        return gui

    launch(create_ui, name, add_remote_mode=False)


def launch(create_ui, name=None, add_remote_mode=False):
    from twisted.internet import reactor

    parser = create_arg_parser(name, add_remote_mode)
    args = parser.parse_args()
    ui = create_ui(reactor)

    log.debug('Launching the {ui} ', ui=type(ui).__name__)

    ui.start(args.name,
             args.local_server_ip,
             args.local_server_port,
             args.connect_to_tor,
             args.tor_socks_port,
             args.tor_control_port,
             args.local_mode,
             args.remote_mode if add_remote_mode else False)
    reactor.run()


UIS = {Cli.__name__: launch_cli,
       Gui.__name__: launch_gui}


def main():
    log.debug('Launching unMessage from the `unmessage` entry point')
    try:
        ui_class = CONFIG.get('unMessage', 'ui')
        launch_ui = UIS[ui_class]
    except (ConfigParser.NoSectionError, KeyError):
        log.debug('A valid previously launched UI was not found')
        launch_ui = launch_gui
    else:
        log.debug('A previously launched UI was found')
    try:
        name = CONFIG.get('unMessage', 'name')
    except ConfigParser.NoSectionError:
        name = None
    launch_ui(name, from_own_entry_point=False)


if __name__ == '__main__':
    sys.exit(main())
