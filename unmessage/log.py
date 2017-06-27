import io
import logging

from twisted.logger import globalLogBeginner, Logger
from twisted.logger import _loggerFor as loggerFor
from twisted.logger import FilteringLogObserver, ILogFilterPredicate
from twisted.logger import LogLevelFilterPredicate, LogLevel, PredicateResult
from twisted.logger import STDLibLogObserver, textFileLogObserver
from twisted.python.compat import _PY3
from zope.interface import provider


LOG_LEVEL = LogLevel.warn

NAMESPACES = [
    'unmessage.__main__',
    'unmessage.peer',
]


@provider(ILogFilterPredicate)
def filter_unmessage_event(event):
    if (event['log_level'] >= LogLevel.warn or
            event['log_namespace'] in NAMESPACES):
        return PredicateResult.yes
    else:
        return PredicateResult.no


def get_filtering_observer(observer, log_level):
    return FilteringLogObserver(observer,
                                predicates=[LogLevelFilterPredicate(log_level),
                                            filter_unmessage_event])


# Mappings to Python's logging module
toStdlibLogLevelMapping = {
    LogLevel.debug: logging.DEBUG,
    LogLevel.info: logging.INFO,
    LogLevel.warn: logging.WARNING,
    LogLevel.error: logging.ERROR,
    LogLevel.critical: logging.CRITICAL,
}


class StdLibLogObserver(STDLibLogObserver):
    def __init__(self, name, formatEvent):
        super(StdLibLogObserver, self).__init__(name)

        if _PY3:
            self.formatEvent = formatEvent
        else:
            self.formatEvent = lambda event: formatEvent(event).encode('utf-8')

        logging.basicConfig(level=logging.DEBUG, format='%(message)s')

    def __call__(self, event):
        text = self.formatEvent(event).strip()

        if text:
            level = event.get('log_level', LogLevel.info)
            stdlibLevel = toStdlibLogLevelMapping.get(level, logging.INFO)

            failure = event.get('log_failure')
            if failure is None:
                excInfo = None
            else:
                excInfo = (failure.type,
                           failure.value,
                           failure.getTracebackObject())

            self.logger.log(stdlibLevel, text, exc_info=excInfo)


def get_std_observer(name, format_event):
    return StdLibLogObserver(name, format_event)


def get_file_observer(filepath):
    return textFileLogObserver(io.open(filepath, 'a'))


def begin_logging_to_std(name, log_level=LOG_LEVEL):
    logging.basicConfig(level=logging.DEBUG)
    observer = get_filtering_observer(get_std_observer(name), log_level)

    globalLogBeginner.beginLoggingTo([observer])


def begin_logging_to_file(filepath, log_level=LOG_LEVEL):
    observer = get_filtering_observer(get_file_observer(filepath), log_level)

    globalLogBeginner.beginLoggingTo([observer])


def begin_logging(filepath, log_level=LOG_LEVEL, begin_std=False):
    file_observer = get_file_observer(filepath)
    observers = [get_filtering_observer(file_observer, log_level)]

    if begin_std:
        stdlib_observer = get_std_observer('unmessage',
                                           file_observer.formatEvent)
        observers.append(get_filtering_observer(stdlib_observer, log_level))

    globalLogBeginner.beginLoggingTo(observers)
