unMessage
---------
unMessage is a peer-to-peer instant messaging application designed
to enhance privacy and anonymity.

Warning
'''''''
unMessage is **alpha** software. While every effort has been made
to make sure unMessage operates in a secure and bug-free fashion,
the code has **not** been audited. Please do not use unMessage for
any activity that your life depends upon.

Features
--------
- Transport makes use of `Twisted`_, `Tor Onion Services`_ and
  `txtorcon`_

- Encryption is performed using the `Double Ratchet Algorithm`_
  implemented in `pyaxo`_ (using `PyNaCl`_)

- Authentication makes use of the `Socialist Millionaire Protocol`_
  implemented in `Cryptully`_

- Transport metadata is minimized by *Tor* and application metadata by
  the `unMessage protocol`_

- User interfaces are created with `Tkinter`_ (graphical) and
  `curses`_ (command-line)

Quick Start
-----------
Install the following requirements via package manager::

    # If using Debian/Ubuntu
    $ sudo apt-get install build-essential gcc libffi-dev python-dev tor python-tk

    # If using Fedora
    $ sudo yum install gcc libffi-devel python-devel redhat-rpm-config tor tkinter


If you use `pip`_ and `setuptools`_ (probably installed automatically
with *pip*), you can easily install unMessage with::

    $ sudo pip install unmessage

Launch unMessage with any of the commands::

    $ unmessage-gui # graphical user interface (GUI)
    $ unmessage-cli # command-line interface (CLI)
    $ unmessage # last interface used

Updating
''''''''
If you installed unMessage with *pip*, you can also use it for
updates::

    $ sudo pip install --upgrade unmessage

Documentation
-------------
You can find `installation`_ and usage instructions (for the `GUI`_
and the `CLI`_) on the `documentation`_.

Feedback
--------
Please join us on **#unMessage:anemone.me** or **#anemone:anemone.me**
with `Matrix`_, **#anemone** at `OFTC`_, or use the
`GitHub issue tracker`_ to leave suggestions, bug reports, complaints
or anything you feel will contribute to this application.

.. _`cli`: https://unmessage.readthedocs.io/en/latest/cli/cli.html
.. _`cryptully`: https://github.com/shanet/Cryptully
.. _`curses`: https://docs.python.org/2/library/curses.html
.. _`double ratchet algorithm`: https://whispersystems.org/docs/specifications/doubleratchet
.. _`documentation`: https://unmessage.readthedocs.io
.. _`github issue tracker`: https://github.com/AnemoneLabs/unmessage/issues
.. _`gui`: https://unmessage.readthedocs.io/en/latest/gui/gui.html
.. _`installation`: https://unmessage.readthedocs.io/en/latest/installation.html
.. _`matrix`: https://matrix.org
.. _`oftc`: https://oftc.net
.. _`pip`: https://pypi.python.org/pypi/pip
.. _`pyaxo`: https://github.com/anemonelabs/pyaxo
.. _`pynacl`: https://github.com/pyca/pynacl
.. _`setuptools`: https://pypi.python.org/pypi/setuptools
.. _`socialist millionaire protocol`: https://en.wikipedia.org/wiki/Socialist_millionaire
.. _`tkinter`: https://docs.python.org/2/library/tkinter.html
.. _`tor onion services`: https://www.torproject.org/docs/hidden-services.html
.. _`twisted`: https://twistedmatrix.com
.. _`txtorcon`: https://github.com/meejah/txtorcon
.. _`unmessage protocol`: https://unmessage.readthedocs.io/en/latest/protocol.html
