#################
GPG/MIME messages
#################

If you are *creating* basic MIME messages (from pythons `email.mime
<https://docs.python.org/3.4/library/email.mime.html>`_ module), use the
:py:func:`~gpgliblib.base.GpgBackendBase.sign_message` and
:py:func:`~gpgliblib.base.GpgBackendBase.encrypt_message` functions::

   >>> from gpgliblib import gpgme
   >>> from six.moves.email_mime_text import MIMEText
   >>> from six.moves.email_mime_multipart import MIMEMultipart

   # create backend
   >>> backend = gpgme.GpgMeBackend()

   # create message
   >>> plain = MIMEText('foobar')
   >>> html = MIMEText('html', _subtype='html')
   >>> multi = MIMEMultipart(_subparts=[plain, html])

   # get signed/encrypted/signed and encrypted message
   >>> msg = backend.sign_message(multi, signer='your-fingerprint')
   >>> msg = backend.encrypt_message(multi, recipients=['other-fingerprint'])
   >>> msg = backend.encrypt_message(multi, signer='your-fingerprint',
                                     recipients=['your-fingerprint'])

   # add various headers...
   >>> msg.add_header('From', 'user@example.com')

The backends do not yet provide any functions for processing received GPG/MIME messages.

All functions also allow you to override parameters (usually passed to the constructor) on a
per-function call basis. E.g. If you want to use a different keyring for an already configured
backend, you could do::

   >>> backend.sign_message(..., home='/home/other-dir'/)
