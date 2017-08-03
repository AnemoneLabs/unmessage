import pytest

from .utils import slow_option


def skipif_option(option):
    return pytest.mark.skipif(not pytest.config.getoption(option),
                              reason='need {} option to run'.format(option))


slow = skipif_option(slow_option)
