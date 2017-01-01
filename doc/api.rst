#################
API documentation
#################

*****************************
gpgliblib.base.GpgBackendBase
*****************************

.. autoclass:: gpgliblib.base.GpgBackendBase
   :members:

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


******************
Django integration
******************

.. autodata:: gpgliblib.django.gpg_backends
   :annotation:

.. autodata:: gpgliblib.django.gpg_backend
   :annotation:

.. autoclass:: gpgliblib.django.GpgEmailMessage
   :members:

