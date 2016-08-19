#################
API documentation
#################

***************************
gpgmime.base.GpgBackendBase
***************************

.. autoclass:: gpgmime.base.GpgBackendBase
   :members:

**********
Exceptions
**********

Backends catch the most common exceptions and wrap them in common error messages
for convenience.

.. autoexception:: gpgmime.base.GpgMimeError
   :members:

.. autoexception:: gpgmime.base.GpgKeyNotFoundError
   :members:

.. autoexception:: gpgmime.base.GpgUntrustedKeyError
   :members:


******************
Django integration
******************

.. autodata:: gpgmime.django.gpg_backends
   :annotation:

.. autodata:: gpgmime.django.gpg_backend
   :annotation:

.. autoclass:: gpgmime.django.GpgEmailMessage
   :members:

