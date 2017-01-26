########
Backends
########

**********
pyme3/pyme
**********

`pyme3 <https://pypi.python.org/pypi/pyme3>`_ and `pyme
<https://pypi.python.org/pypi/pyme>`_ are the official Python bindings for
`gpgme <https://www.gnupg.org/(es)/related_software/gpgme/>`_.
:py:class:`gpgliblib.pyme.PymeBackend` provides an almost complete implementation of the
:doc:`gpgliblib API <api>`. It works with GnuPG 1.x and 2.x.

**Limitations:** Due to inadequacies in **pyme**, this backend currently cannot be used to set key
trusts.

Installation requires swig and python, gpgme and libgpg-error development
headers. On Debian/Ubuntu do::

   apt-get install python3-dev libgpg-error-dev libgpgme-dev

.. seealso::

   * `Announcement for pyme3 <https://www.gnupg.org/blog/20160921-python-bindings-for-gpgme.html>`_
   * `Official homepage (from 2008) <http://pyme.sourceforge.net/>`_
   * `Bitbucket repository <https://bitbucket.org/malb/pyme>`_ (There are many repos that look like
     the official repo, this one is the most recently updated one at the time of writing)
   * `Official gpgme documentation <http://pyme.sourceforge.net/doc/gpgme/>`_

.. autoclass:: gpgliblib.pyme.PymeBackend
   :members:

*****
gpgme
*****

`pygpgme <https://pypi.python.org/pypi/pygpgme/>`_ are another library that provides Python
bindings for `gpgme <https://www.gnupg.org/(es)/related_software/gpgme/>`_.
:py:class:`gpgliblib.gpgme.GpgMeBackend` provides a complete implementation of the :doc:`gpgliblib
API <api>`. It works with GnuPG 1.x and 2.x.

Installation requires swig and python, and gpgme development headers. On Debian/Ubuntu do::

   apt-get install python3-dev libgpgme-dev

You can install ``pygpgme`` simply by doing::

   pip install pygpgme

.. seealso::
   
   * `Launchpad page <https://launchpad.net/pygpgme>`_
   * `Unofficial (and incomplete) documentation
     <https://pygpgme.readthedocs.io/en/latest/api.html>`_

.. autoclass:: gpgliblib.gpgme.GpgMeBackend
   :members:

************
python-gnupg
************

`python-gnupg <https://pypi.python.org/pypi/python-gnupg>`_ uses the command line to call GnuPG via
subprocess invocations. It has no external dependencies other then GnuPG itself. 

You can install ``python-gnupg`` simply by doing::

   pip install python-gnupg

.. seealso::

   * `Documenation <https://pythonhosted.org/python-gnupg/>`_
   * `Bitbucket repository <https://bitbucket.org/vinay.sajip/python-gnupg/overview>`_
   * `GitHub mirror <https://github.com/vsajip/python-gnupg>`_

.. NOTE::

   If you use GnuPG >= 2.1, you need at least version 0.4.0 of ``python-gnupg``. At the time of
   writing (2017-01-20) 0.4.0 is not yet released, but the hg-checkout works. Even then, removing
   secret keys currently fails.

.. autoclass:: gpgliblib.python_gnupg.PythonGnupgBackend
   :members:
