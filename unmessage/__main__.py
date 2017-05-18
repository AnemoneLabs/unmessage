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
    try:
        ui = UIS[CONFIG.get('unMessage', 'ui')]
    except ConfigParser.NoSectionError:
        # use the GUI by default when unMessage is first launched
        gui.main()
    else:
        name = CONFIG.get('unMessage', 'name')
        ui.main(name)


if __name__ == '__main__':
    sys.exit(main())
