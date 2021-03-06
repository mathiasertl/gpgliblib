#########
ChangeLog
#########

**********************
0.2.0 (to be released)
**********************

* Rename ``gpgliblib.gnupg.GnuPGBackend`` to
  :py:class:`gpgliblib.python_gnupg.PythonGnupgBackend` for consistency and to
  avoid confusion with its fork, `gnupg <http://pythonhosted.org/gnupg/>`_.
* New backend for `pyme <https://pypi.python.org/pypi/pyme3>`_,
  :py:class:`gpgliblib.pyme.PymeBackend`.
* Backends now support the ``gnupg_version`` parameter to manually override the
  version of gnupg being used.
* Support for exporting keys via :py:func:`gpgliblib.base.GpgKey.export`.
* Support for deleting keys via :py:func:`gpgliblib.base.GpgKey.delete`.
* Add new attributes for GPG keys:

  * :py:attr:`gpgliblib.base.GpgKey.has_secret_key`
  * :py:attr:`gpgliblib.base.GpgKey.keyid` and
    :py:attr:`gpgliblib.base.GpgKey.long_keyid`

* Support for generating testcoverage reports via ``fab coverage``.

****************
0.1 (2017-01-08)
****************

* Initial release.
