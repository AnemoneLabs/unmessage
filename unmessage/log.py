import io
import logging

from twisted.logger import globalLogBeginner, Logger
from twisted.logger import FilteringLogObserver, ILogFilterPredicate
from twisted.logger import LogLevelFilterPredicate, LogLevel, PredicateResult
from twisted.logger import ILogObserver, STDLibLogObserver, textFileLogObserver
from zope.interface import implementer, provider


@provider(ILogFilterPredicate)
def filter_unmessage_event(event):
    if event['log_namespace'].startswith('unmessage'):
        return PredicateResult.yes
    else:
        return PredicateResult.no


def get_filtering_observer(observer, log_level):
    return FilteringLogObserver(observer,
                                predicates=[LogLevelFilterPredicate(log_level),
                                            filter_unmessage_event])


@implementer(ILogObserver)
class PrintObserver(object):
    def __init__(self, format_event):
        self.format_event = format_event

    def __call__(self, event):
        print self.format_event(event),


def get_std_observer(name):
    return STDLibLogObserver(name)


def get_file_observer(filepath):
    return textFileLogObserver(io.open(filepath, 'a'))


def begin_logging_to_std(name, log_level=LogLevel.info):
    logging.basicConfig(level=logging.DEBUG)
    observer = get_filtering_observer(get_std_observer(name), log_level)

    globalLogBeginner.beginLoggingTo([observer])


def begin_logging_to_file(filepath, log_level=LogLevel.info):
    observer = get_filtering_observer(get_file_observer(filepath), log_level)

    globalLogBeginner.beginLoggingTo([observer])


def begin_logging(filepath, log_level=LogLevel.info, begin_std=False):
    file_observer = get_file_observer(filepath)
    observers = [get_filtering_observer(file_observer, log_level)]

    if begin_std:
        #print_observer = PrintObserver(file_observer.formatEvent)

        logging.basicConfig(level=logging.DEBUG)
        print_observer = get_std_observer('unmessage')

        observers.append(get_filtering_observer(print_observer, log_level))

    globalLogBeginner.beginLoggingTo(observers)
