###########
Development
###########

To develop your own backend, simply subclass :py:class:`~gpgmime.base.GpgBackendBase`
and implement these functions:

* :py:func:`~gpgmime.base.GpgBackendBase.sign`
* :py:func:`~gpgmime.base.GpgBackendBase.encrypt`
* :py:func:`~gpgmime.base.GpgBackendBase.sign_encrypt`
* :py:func:`~gpgmime.base.GpgBackendBase.import_key`
* :py:func:`~gpgmime.base.GpgBackendBase.import_private_key`
* :py:func:`~gpgmime.base.GpgBackendBase.expires`

The constructor should take at least the same parameters as GpgBackendBase. Remember that any
function may pass ``**kwargs`` to override any option passed to the constructor. For example,
multiple invocations of :py:class:`~gpgmime.base.GpgBackendBase.sign` might use different home
directories::

   >>> from gpgmime.gpgme import GpgMeBackend
   >>> backend = GpgMeBackend(home='/usr/local/default-keyring')

   # This should use the keyring from constructor
   >>> backend.sign(b'foo', ['0x1234...'])

   # This should use the other keyring
   >>> backend.sign(b'bar', ['0x1234...'], home='/usr/local/other-keyring')
