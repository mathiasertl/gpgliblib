#####
Usage
#####

The basic idea of **gpgliblib** is that you use an instance of a backend class that implements
various functions using the specific GPG library and thus provides a well-documented and pythonic
interface abstracting away the quirks and problems of each library used. Because every backend
provides the same interface, you can use a different library by simply using a different backend
class.

A full list of backends and their options is available at :doc:`backends`. In most cases, you can
simply instantiate a backend class by calling it without parameters::

   >>> from gpgliblib import gpgme
   >>> backend = gpgme.GpgMeBackend(home=gnupg_home)

.. NOTE::

   In this document, we pass the ``home`` parameter to every backend constructor. This is because
   the testsuite of **gpgliblib** executes the examples in this document with a temporary keyring
   to make sure that all examples are actually correct.

   You do not have to pass this parameter, the default is usually the current users default
   keyring.

**************
Key management
**************

The library offers only very basic key management. You can fetch keys from keyservers, import
public and private keys, manage trust and query a keys expiry::

   >>> from gpgliblib import gpgme
   >>> from gpgliblib.base import VALIDITY_FULL
   >>> from gpgliblib.base import VALIDITY_UNKNOWN
   
   >>> backend = gpgme.GpgMeBackend(home=gnupg_home)
   >>> fingerprint = '4C443E9B262ECB73835730DAA9711516C8D705FC'
   
   >>> raw_key_data = backend.fetch_key('0x%s' % fingerprint)
   >>> key = backend.import_key(raw_key_data)[0]
   >>> key.fingerprint
   '4C443E9B262ECB73835730DAA9711516C8D705FC'
   >>> key.trust == VALIDITY_UNKNOWN
   True
   >>> key.trust = VALIDITY_FULL
   >>> key.trust == VALIDITY_FULL
   True
   >>> key.expires
   datetime.datetime(2046, 8, 12, 7, 53, 29)

   # This is a key that does not expire:
   >>> fingerprint = 'CC9F343794DBB20E13DE097EE53338B91AA9A0AC'
   >>> raw_key_data = backend.fetch_key('0x%s' % fingerprint)
   >>> key = backend.import_key(raw_key_data)[0]
   >>> key.expires is None
   True

******************
Signing/Encrypting
******************

Signing and/or encrypting is straight forward::

   >>> from gpgliblib import gpgme
   >>> backend = gpgme.GpgMeBackend(home=gnupg_home, default_trust=True)
   >>> fingerprint = 'CC9F343794DBB20E13DE097EE53338B91AA9A0AC'

   # import the private key so we can sign
   >>> key = backend.import_private_key(user1_priv)[0]
   >>> testdata = b'testdata, any byte string'
   
   >>> sig = backend.sign(testdata, signer=key)
   >>> enc = backend.encrypt(testdata, recipients=[key])
   >>> both = backend.sign_encrypt(testdata, recipients=[key], signer=key)

   # You can also pass the fingerprint whenever you pass a key
   >>> sig2 = backend.sign(b'data to sign', signer=fingerprint)
   
   # Verify signature/encrypted text
   >>> backend.verify(testdata, sig).fingerprint
   'CC9F343794DBB20E13DE097EE53338B91AA9A0AC'
   >>> backend.decrypt(enc) == testdata
   True
   >>> backend.decrypt_verify(both) == (testdata, fingerprint)
   True

***************
Custom settings
***************

You can temporarily override any parameter passed to the backend by using the
:py:meth:`~gpgliblib.base.GpgBackendBase.settings` context manager::

   >>> from gpgliblib import gpgme
   >>> backend = gpgme.GpgMeBackend(home=gnupg_home, default_trust=False)  # False is the default
   >>> backend.encrypt(b'data', recipients=[fingerprint])
   Traceback (most recent call last):
       ...
   gpgliblib.base.GpgUntrustedKeyError: Key not trusted.
   >>> with backend.settings(default_trust=True) as temp_backend:
   ...     # Use the temporary backend instance for a different default trust
   ...     enc = temp_backend.encrypt(b'data', recipients=[fingerprint])

One common usecase is to use a temporary GPG keyring that is automatically discarded after use. GPG
is not very compatible with a multi-processing environment (e.g. when used in context of a
webserver), so it's a lot safer to use a temporary keyring for every operation.
