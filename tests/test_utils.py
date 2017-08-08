from os.path import join

from unmessage.utils import Paths


def test_paths_base():
    head = 'head'
    tail = 'tail'
    paths = Paths(head, tail)
    assert paths.base == str(paths)
    assert paths.base == join(head, tail)


def test_logger_fixture(log):
    info = 'test_utils.py::test_logger_fixture'
    log.info(info)
    with open('/tmp/unmessage.log', 'r') as f:
        last_log = f.readlines()[-1].strip()
    assert last_log.endswith(info)
