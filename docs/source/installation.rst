============
Installation
============
Make sure that you have the following::

    # If using Debian/Ubuntu
    $ sudo apt-get install build-essential gcc libffi-dev python-dev tor tkinter

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
.. _`pyaxo`: https://github.com/anemonelabs/pyaxo
.. _`setuptools`: https://pypi.python.org/pypi/setuptools
.. _`tkinter`: https://docs.python.org/2/library/tkinter.html
.. _`tor onion services`: https://www.torproject.org/docs/hidden-services.html
.. _`twisted`: https://twistedmatrix.com
.. _`txtorcon`: https://github.com/meejah/txtorcon
