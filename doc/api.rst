#################
API documentation
#################

*****************************
gpgliblib.base.GpgBackendBase
*****************************

.. autoclass:: gpgliblib.base.GpgBackendBase
   :members:

*********************
gpgliblib.base.GpgKey
*********************

An instance of a subclass of :py:class:`~gpgliblib.base.GpgKey` is returned by various keyhandling
functions of backend implementations.

.. autoclass:: gpgliblib.base.GpgKey
   :members:

.. _api-constants:

*********
Constants
*********

.. autodata:: gpgliblib.base.MODE_ARMOR

.. autodata:: gpgliblib.base.MODE_BINARY

.. autodata:: gpgliblib.base.VALIDITY_UNKNOWN

.. autodata:: gpgliblib.base.VALIDITY_NEVER

.. autodata:: gpgliblib.base.VALIDITY_MARGINAL

.. autodata:: gpgliblib.base.VALIDITY_FULL

.. autodata:: gpgliblib.base.VALIDITY_ULTIMATE

**********
Exceptions
**********

Backends catch the most common exceptions and wrap them in common error messages
for convenience.

.. autoexception:: gpgliblib.base.GpgMimeError
   :members:

.. autoexception:: gpgliblib.base.GpgKeyNotFoundError
   :members:

.. autoexception:: gpgliblib.base.GpgUntrustedKeyError
   :members:

.. autoexception:: gpgliblib.base.GpgBadSignature
   :members:


******************
Django integration
******************

.. autodata:: gpgliblib.django.gpg_backends
   :annotation:

.. autodata:: gpgliblib.django.gpg_backend
   :annotation:

.. autoclass:: gpgliblib.django.GpgEmailMessage
   :members:

