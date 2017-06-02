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
    except ConfigParser.NoSectionError:
        log.debug('Using the {gui} by default in the first launch',
                  gui=gui.__name__)
        gui.main()
    else:
        ui = UIS[ui_module]
        log.debug('Using the {ui} based on a previous launch',
                  ui=ui_module)
        name = CONFIG.get('unMessage', 'name')
        ui.main(name)


if __name__ == '__main__':
    sys.exit(main())
