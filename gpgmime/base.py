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


class GpgBackendBase(object):
    def __init__(self, home=None, path=None, always_trust=False):
        self._home = home
        self._path = path
        self._always_trust = always_trust

    def fetch_key(self, keyserver='http://pool.sks-keyservers.net:11371'):
        pass

    ##############
    # Encrypting #
    ##############

    def get_control_message(self):
        """Get a control information message as descripted in RFC 3156, chapter 4."""

        msg = MIMEApplication(_data='Version: 1\n', _subtype='pgp-encrypted', _encoder=encode_noop)
        msg.add_header('Content-Description', 'PGP/MIME version identification')
        return msg

    def get_encrypted_message(self, message):
        control = self.get_control_message()
        msg = MIMEMultipart(_subtype='encrypted', _subparts=[control, message])
        msg.set_param('protocol', 'application/pgp-encrypted')
        return msg

    def encrypt_message(self, message, recipients, signers=None, **kwargs):
        if isinstance(message, six.string_types):
            message = MIMEText(message)

        if signers is None:
            encrypted = self.encrypt(message.as_bytes(), recipients, **kwargs)
        else:
            encrypted = self.sign_encrypt(message.as_bytes(), recipients, signers, **kwargs)

        msg = MIMEApplication(_data=encrypted, _subtype='octet-stream', name='encrypted.asc',
                              _encoder=encode_noop)
        msg.add_header('Content-Description', 'OpenPGP encrypted message')
        msg.add_header('Content-Disposition', 'inline; filename="encrypted.asc"')
        return self.get_encrypted_message(msg)

    ###########
    # Signing #
    ###########

    def get_mime_signature(self, signature):
        msg = MIMEBase(_maintype='application', _subtype='pgp-signature', name='signature.asc')
        msg.set_payload(signature)
        msg.add_header('Content-Description', 'OpenPGP digital signature')
        msg.add_header('Content-Disposition', 'attachment; filename="signature.asc"')
        del msg['MIME-Version']
        del msg['Content-Transfer-Encoding']
        return msg

    def get_signed_message(self, message, signature):
        msg = MIMEMultipart(_subtype='signed', _subparts=[message, signature])
        msg.set_param('protocol', 'application/pgp-signature')
        msg.set_param('micalg', 'pgp-sha256')  # TODO: Just the current default
        return msg

    def sign_message(self, message, signers, add_cr=True, **kwargs):
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
        raise NotImplementedError

    def encrypt(self, data, recipients, **kwargs):
        raise NotImplementedError

    def sign_encrypt(self, data, recipients, signers, **kwargs):
        raise NotImplementedError
