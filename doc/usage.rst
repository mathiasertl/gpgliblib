#####
Usage
#####

This library supports creating basic GPG/Mime messages as well as basic key handling functions. It
was designed for a website that allows users to add GPG keys in order to receive GPG encrypted
emails from the website.

The common interface abstracts from different libraries, making them interchangeable. The following
example thus works with any implementation::

   >>> from gpgmime import gpgme
   >>> from six.moves.email_mime_text import MIMEText
   >>> from six.moves.email_mime_multipart import MIMEMultipart

   # create backend
   >>> backend = gpgme.GpgMeBackend()

   # create message
   >>> plain = MIMEText('foobar')
   >>> html = MIMEText('html', _subtype='html')
   >>> multi = MIMEMultipart(_subparts=[plain, html])

   # get signed/encrypted/signed and encrypted message
   >>> msg = backend.sign_message(multi, signers=['your-fingerprint'])
   >>> msg = backend.encrypt_message(multi, recipients=['other-fingerprint'])
   >>> msg = backend.encrypt_message(multi, signers=['your-fingerprint'],
                                     recipients=['your-fingerprint'])

   # add various headers...
   >>> msg.add_header('From', 'user@example.com')

The interface also offers some *basic* key management::

   >>> foo
