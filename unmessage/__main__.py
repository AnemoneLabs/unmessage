#!/usr/bin/env python
import ConfigParser
import sys

from . import cli
from . import gui
from .log import Logger
from .peer import CONFIG


UIS = {cli.Cli.__name__: cli,
       gui.Gui.__name__: gui}


log = Logger()


def main():
    log.debug('Launching unMessage from the `unmessage` entry point')
    try:
        ui_class = CONFIG.get('unMessage', 'ui')
        ui = UIS[ui_class]
    except (ConfigParser.NoSectionError, KeyError):
        log.debug('Using the {gui} when a valid previous UI is not found',
                  gui=gui.Gui.__name__)
        gui.main()
    else:
        log.debug('Using the {ui} based on a previous launch',
                  ui=ui_class.__name__)
        name = CONFIG.get('unMessage', 'name')
        ui.main(name)


if __name__ == '__main__':
    sys.exit(main())
