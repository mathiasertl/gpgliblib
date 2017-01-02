##################
Django integration
##################

Since everyone (including me) seems to use `Django <https://www.djangoproject.com/>`_ nowadays,
this library also integrates with Django.

You can configure caches in settings very similar to how caches are configured::

   GPG_BACKENDS = {
       'default': {
           'BACKEND': 'gpgliblib.gpgme.GpgMeBackend',
           # Optional settings:
           #'HOME': '/home/...',  # Keyring directory
           #'PATH': '/home/...',  # Path to 'gpg' binary
           #'ALWAYS_TRUST': True,   # Ignore trust in all operations
           #'OPTIONS': {...},  # Any custom options for the specific backend implementation
       },
   }

Just like with django caches, you can access configured GPG backends::

   >>> from gpgliblib.django import gpg_backends
   >>> gpg_backends['default']
   <gpgliblib.gpgme.GpgMeBackend at 0x...>
   >>> gpg_backend
   <gpgliblib.django.DefaultGPGProxy at 0x...>

Use :py:class:`~gpgliblib.django.GpgEmailMessage` instead of
`EmailMessage <https://docs.djangoproject.com/en/dev/topics/email/#emailmessage-objects>`_
objects::

   >>> from gpgliblib import gpgme
   >>> from gpgliblib.django import GpgEmailMessage

   >>> backend = gpgme.GpgMeBackend()
   >>> fingerprint = 'E8172F2940EA9F709842290870BD9664FA3947CD'

   >>> msg = GpgEmailMessage(subject='subject', ...,
   ...     gpg_recipients=[fingerprint], gpg_signer=fingerprint)
   >>> msg.send()
