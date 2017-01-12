#########
ChangeLog
#########

**********************
0.2.0 (to be released)
**********************

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
