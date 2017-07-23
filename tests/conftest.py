import pytest


@pytest.fixture(scope='session')
def reactor():
    from twisted.internet import reactor as _reactor
    return _reactor
