###########
Development
###########

To develop your own backend, simply subclass :py:class:`~gpgliblib.base.GpgBackendBase`
and implement these functions:

* :py:func:`~gpgliblib.base.GpgBackendBase.sign`
* :py:func:`~gpgliblib.base.GpgBackendBase.encrypt`
* :py:func:`~gpgliblib.base.GpgBackendBase.sign_encrypt`
* :py:func:`~gpgliblib.base.GpgBackendBase.import_key`
* :py:func:`~gpgliblib.base.GpgBackendBase.import_private_key`
* :py:func:`~gpgliblib.base.GpgBackendBase.expires`

The constructor should take at least the same parameters as GpgBackendBase. If
you provide additional keyword arguments, also be sure to override
:py:func:`~gpgliblib.base.GpgBackendBase.get_settings` to make sure the
:py:class:`~gpgliblib.base.GpgBackendBase.settings` context manager works
correctly. For example::

   class MyBackend(GpgBackendBase):
       def __init__(self, my_setting, **kwargs):
           super(MyBackend, self).__init__(**kwargs)
           self.my_setting = my_setting

       def get_settings(self):
           settings = super(MyBackend, self).get_settings()
           settings['my_setting'] = self.my_setting
           return settings
*********
Testsuite
*********

There is an automated testsuite to test the functions that should be
implemented by a GPG backend (signing, encrypting, ...). Simply run::

   fab test

The testsuite tests key handling, encryption and signing. You can also test just
one backend by giving the ``backend`` parameter::

   fab test:backend=gpgliblib.gpgme.GpgMeBackend

To run an individual test (for debugging a particular failed test), you can give
the ``name`` parameter::

   fab test:name=tests.tests.ListKeysTests.test_empty_keyring

Test GPG/MIME
=============

Since there isn't any existing library for creating GPG/MIME messages, there is
a fabfile target that creates messages that you can then check in your
mailclient::

   fab test_mime_messages

The files are created in ``build/test_backends/``.

Django integration
==================

In ``testproject``, run::

   python manage.py testmail

to test Django integration. You need to configure an SMTP backend. To do that,
create ``testproject/testproject/localsettings.py`` (in the same directory as
``settings.py``) and adapt to your needs::

   # Print emails to stdout
   #EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

   # Send them via SMTP:
   EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
   EMAIL_HOST = 'smtp.example.com'
   #EMAIL_PORT = 587
   #EMAIL_HOST_USER = '...'
   #EMAIL_HOST_PASSWORD = '...'
   #EMAIL_USE_TLS = True

Coverage report
===============

You can also create a coverage report via

   fab coverage

The coverage report will go to ``build/coverage``.
