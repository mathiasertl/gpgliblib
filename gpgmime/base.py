# -*- coding: utf-8 -*-
#
# This file is part of gpg-mime (https://github.com/mathiasertl/gpg-mime).
#
# gpg-mime is free software: you can redistribute it and/or modify it under the terms of the
# GNU General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# gpg-mime is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with gpg-mime. If
# not, see <http://www.gnu.org/licenses/>.

from __future__ import unicode_literals, absolute_import

from email.encoders import encode_noop
from email.mime.application import MIMEApplication

import six

from six.moves.email_mime_base import MIMEBase
from six.moves.email_mime_multipart import MIMEMultipart
from six.moves.email_mime_text import MIMEText
from six.moves.urllib.parse import urlencode
from six.moves.urllib.request import urlopen


class GpgBackendBase(object):
    """Base class for all backends.

    The parameters to the constructor supported by the base class are also supported by any
    implementing subclasses. Any custom parameters are documented in the backends.

    Parameters
    ----------

    home : str, optional
        The GPG home directory. This is equivalent to the ``GNUPGHOME`` environment variable for
        the ``gpg`` command line utility.
    path : str, optional
        Path to the ``gpg`` binary. The default is whatever the library uses (usually the first
        instance found in your PATH) and may be ignored on backends that do not use the binary
        directly.
    always_trust : bool, optional
        Wether to always trust keys when encrypting. The default is ``False``.
    """

    def __init__(self, home=None, path=None, always_trust=False):
        self._home = home
        self._path = path
        self._always_trust = always_trust

    def fetch_key(self, search, keyserver='http://pool.sks-keyservers.net:11371', **kwargs):
        """Fetch a key from the given keyserver.

        Parameters
        ----------
        search : str
            The search string. If this is a fingerprint, it must start with ``"0x"``.
        keyserver : str, optional
            URL of the keyserver, the default is ``"http://pool.sks-keyservers.net:11371"``.
        **kwargs
            All kwargs are passed to :py:func:`urllib.request.urlopen`. The ``timeout`` parameter
            defaults to three seconds this function (``urlopen`` is a blocking function and thus
            makes long timeouts unsuitable for e.g. a webserver setup).

        Returns
        -------

        key : bytes
            The requested key as bytes.

        Raises
        ------

        urllib.error.URLError
            If the keyserver cannot be reached.
        urllib.error.HTTPError
            If the keyserver does not respond with http 200, e.g. if the key is not found.
        """
        kwargs.setdefault('timeout', 3)
        params = {
            'search': search,
            'options': 'mr',
            'op': 'get',
        }
        url = '%s/pks/lookup?%s' % (keyserver, urlencode(params))
        response = urlopen(url, **kwargs)
        return response.read().strip()

    ##############
    # Encrypting #
    ##############

    def get_control_message(self):
        """Get a control message for encrypted messages, as descripted in RFC 3156, chapter 4."""

        msg = MIMEApplication(_data='Version: 1\n', _subtype='pgp-encrypted', _encoder=encode_noop)
        msg.add_header('Content-Description', 'PGP/MIME version identification')
        return msg

    def get_encrypted_message(self, message):
        """Get the encrypted message from the passed payload message.

        Parameters
        ----------

        message : MIMEBase
            The message to encrypt (e.g. as created by :py:func:`get_octed_stream`.
        """

        control = self.get_control_message()
        msg = MIMEMultipart(_subtype='encrypted', _subparts=[control, message])
        msg.set_param('protocol', 'application/pgp-encrypted')
        return msg

    def get_octet_stream(self, message, recipients, signers=None, **kwargs):
        """Get encrypted message from the passt message (helper function).

        This function returns the encrypted payload message. The parameters are the same as in
        :py:func:`encrypt_message`.
        """
        if signers is None:
            encrypted = self.encrypt(message.as_bytes(), recipients, **kwargs)
        else:
            encrypted = self.sign_encrypt(message.as_bytes(), recipients, signers, **kwargs)

        msg = MIMEApplication(_data=encrypted, _subtype='octet-stream', name='encrypted.asc',
                              _encoder=encode_noop)
        msg.add_header('Content-Description', 'OpenPGP encrypted message')
        msg.add_header('Content-Disposition', 'inline; filename="encrypted.asc"')
        return msg

    def encrypt_message(self, message, recipients, signers=None, **kwargs):
        """Get an encrypted MIME message from the passed message or str.

        This function returns a fully encrypted MIME message including a control message and the
        encrypted payload message.

        Parameters
        ----------

        message : MIMEBase or str
            Message to encrypt.
        recipients : list of key ids
            List of key ids to encrypt to.
        signers : list of key ids, optional
            List of key ids to sign the mssage with.
        **kwargs
            Any additional parameters to the GPG backend.
        """
        if isinstance(message, six.string_types):
            message = MIMEText(message)

        msg = self.get_octet_stream(message, recipients, signers, **kwargs)
        return self.get_encrypted_message(msg)

    ###########
    # Signing #
    ###########

    def get_mime_signature(self, signature):
        """Get a signature MIME message from the passed signature.

        Parameters
        ----------

        signature : bytes
            A gpg signature.
        """
        msg = MIMEBase(_maintype='application', _subtype='pgp-signature', name='signature.asc')
        msg.set_payload(signature)
        msg.add_header('Content-Description', 'OpenPGP digital signature')
        msg.add_header('Content-Disposition', 'attachment; filename="signature.asc"')
        del msg['MIME-Version']
        del msg['Content-Transfer-Encoding']
        return msg

    def get_signed_message(self, message, signature):
        """Get a signed MIME message from the passed message and signature messages.

        Parameters
        ----------

        message : MIMEBase
            MIME message that is signed by the signature.
        signature : MIMEBase
            MIME message containing the signature.
        **kwargs
            Any additional parameters to the GPG backend.
        """

        msg = MIMEMultipart(_subtype='signed', _subparts=[message, signature])
        msg.set_param('protocol', 'application/pgp-signature')
        msg.set_param('micalg', 'pgp-sha256')  # TODO: Just the current default
        return msg

    def sign_message(self, message, signers, add_cr=True, **kwargs):
        """
        message : MIMEBase or str
            Message to encrypt.
        recipients : list of key ids
            List of key ids to encrypt to.
        signers : list of key ids
            A list of key identifiers to sign the message with.
        add_cr : bool, optional
            Wether or not to replace newlines (``\\n``) with carriage-return/newlines (``\\r\\n``).
            E-Mail messages generally use ``\\r\\n``, so the default is True.
        **kwargs
            Any additional parameters to the GPG backend.
        """
        if isinstance(message, six.string_types):
            message = MIMEText(message)
            del message['MIME-Version']

        data = message.as_bytes()
        if add_cr is True:
            data = data.replace(b'\n', b'\r\n')

        # get the gpg signature
        signature = self.sign(data, signers, **kwargs)
        signature_msg = self.get_mime_signature(signature)
        return self.get_signed_message(message, signature_msg)

    def sign(self, data, signers, **kwargs):
        """Sign passed data with the given keys.

        Parameters
        ----------

        data : bytes
            The data to sign.
        signers : list of str
            A list of key identifiers to sign the message with.
        **kwargs
            Any additional parameters to the GPG backend.
        """
        raise NotImplementedError

    def encrypt(self, data, recipients, **kwargs):
        """Encrypt passed data with the given keys.

        Parameters
        ----------

        data : bytes
            The data to sign.
        recipients : list of str
            A list of key identifiers to encrypt the message to.
        **kwargs
            Any additional parameters to the GPG backend.
        """
        raise NotImplementedError

    def sign_encrypt(self, data, recipients, signers, **kwargs):
        """Sign and encrypt passed data with the given keys.

        Parameters
        ----------

        data : bytes
            The data to sign.
        recipients : list of str
            A list of key identifiers to encrypt the message to.
        signers : list of str
            A list of key identifiers to sign the message with.
        **kwargs 
            Any additional parameters to the GPG backend.
        """
        raise NotImplementedError
