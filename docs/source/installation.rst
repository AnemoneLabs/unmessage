============
Installation
============
Install the following requirements via package manager::

    # If using Debian/Ubuntu
    $ sudo apt-get install build-essential gcc libffi-dev libopus0 \
      libsodium-dev libssl-dev portaudio19-dev python-dev python-tk

    # If using Fedora
    $ sudo dnf install gcc libffi-devel libsodium-devel \
      openssl-devel opus portaudio-devel python-devel \
      redhat-rpm-config tkinter

If you have **tor** installed, make sure its version is at least
``0.2.7.1``::

    $ tor --version

If you must update it or do not have it installed, check the version
provided by the package manager::

    # If using Debian/Ubuntu
    $ apt-cache show tor

    # If using Fedora
    $ dnf info tor

If the version to be provided is not at least ``0.2.7.1``, you will
have to `set up Tor's package repository`_. Once you have a repository
which can provide an updated **tor**, install it::

    # If using Debian/Ubuntu
    $ sudo apt-get install tor

    # If using Fedora
    $ sudo dnf install tor

Installing
----------
Finally, if you use `pip`_ and `setuptools`_ (probably installed
automatically with *pip*), you can easily install unMessage with::

    $ sudo pip install unmessage

Launch unMessage with any of the commands::

    $ unmessage-gui # graphical user interface (GUI)
    $ unmessage-cli # command-line interface (CLI)
    $ unmessage # last interface used

Updating
--------
If you installed unMessage with *pip*, you can also use it for
updates::

    $ sudo pip install --upgrade unmessage

Usage
-----
unMessage offers usage instructions for both interfaces:
:ref:`sec-gui` and :ref:`sec-cli`.

Persistence
-----------
All files used by unMessage are saved in ``~/.config/unMessage/``

.. _`cryptully`: https://github.com/shanet/Cryptully
.. _`curses`: https://docs.python.org/2/library/curses.html
.. _`pip`: https://pypi.python.org/pypi/pip
.. _`pyaxo`: https://github.com/rxcomm/pyaxo
.. _`set up tor's package repository`: https://www.torproject.org/docs/debian.html.en#ubuntu
.. _`setuptools`: https://pypi.python.org/pypi/setuptools
.. _`tkinter`: https://docs.python.org/2/library/tkinter.html
.. _`tor onion services`: https://www.torproject.org/docs/hidden-services.html
.. _`twisted`: https://twistedmatrix.com
.. _`txtorcon`: https://github.com/meejah/txtorcon
