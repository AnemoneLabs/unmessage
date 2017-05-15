from ._version import get_versions
from ._metadata import __author__, __contact__, __url__
from ._metadata import __license__, __copyright__


__version__ = get_versions()['version']

del get_versions
