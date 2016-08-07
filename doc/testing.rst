#######
Testing
#######

Since there isn't any way to automatically test PGP/MIME messages, there is no
automated test-suite. You can create sample data and manually test them with an
email client.

************
Raw backends
************

Run::

   python setup.py test_backends

to create test messages in ``build/test_backends``.

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
