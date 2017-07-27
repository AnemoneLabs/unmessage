from os.path import join

from unmessage.utils import Paths


def test_paths_base():
    head = 'head'
    tail = 'tail'
    paths = Paths(head, tail)
    assert paths.base == str(paths)
    assert paths.base == join(head, tail)
