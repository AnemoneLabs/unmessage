========
Overview
========
unMessage is a peer-to-peer instant messaging application designed
to enhance privacy and anonymity.

.. warning::

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
  the :ref:`sec-protocol`

- User interfaces are created with `Tkinter`_ (graphical) and
  `curses`_ (command-line)

.. _`cryptully`: https://github.com/shanet/Cryptully
.. _`curses`: https://docs.python.org/2/library/curses.html
.. _`double ratchet algorithm`: https://whispersystems.org/docs/specifications/doubleratchet
.. _`pyaxo`: https://github.com/rxcomm/pyaxo
.. _`pynacl`: https://github.com/pyca/pynacl
.. _`socialist millionaire protocol`: https://en.wikipedia.org/wiki/Socialist_millionaire
.. _`tkinter`: https://docs.python.org/2/library/tkinter.html
.. _`tor onion services`: https://www.torproject.org/docs/hidden-services.html
.. _`twisted`: https://twistedmatrix.com
.. _`txtorcon`: https://github.com/meejah/txtorcon
