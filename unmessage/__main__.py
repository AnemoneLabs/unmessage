#!/usr/bin/env python
import ConfigParser
import sys

from . import cli
from . import gui
from .log import Logger
from .peer import CONFIG


UIS = {cli.__name__: cli,
       gui.__name__: gui}


log = Logger()


def main():
    log.debug('Launching unMessage from the `unmessage` entry point')
    try:
        ui_module = CONFIG.get('unMessage', 'ui')
        ui = UIS[ui_module]
    except (ConfigParser.NoSectionError, KeyError):
        log.debug('Using the {gui} when a valid previous UI is not found',
                  gui=gui.__name__)
        gui.main()
    else:
        log.debug('Using the {ui} based on a previous launch',
                  ui=ui.__name__)
        name = CONFIG.get('unMessage', 'name')
        ui.main(name)


if __name__ == '__main__':
    sys.exit(main())
