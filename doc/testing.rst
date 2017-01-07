#######
Testing
#######

There is an automated testsuite to test the functions that should be
implemented by a GPG backend (signing, encrypting, ...). Simply run::

   fab test

The testsuite tests key handling, encryption and signing.

*************
Test GPG/MIME
*************

Since there isn't any existing library for creating GPG/MIME messages, there is
a fabfile target that creates messages that you can then check in your
mailclient::

   fab test_mime_messages

The files are created in ``build/test_backends/``.

******************
Django integration
******************

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
