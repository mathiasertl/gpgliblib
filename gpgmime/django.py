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

from django.core.mail import EmailMultiAlternatives
from django.core.mail import SafeMIMEMultipart
from django.core.mail import SafeMIMEText


class GPGEmailMessage(EmailMultiAlternatives):
    def __init__(self, *args, **kwargs):
        self.gpg_signers = kwargs.pop('gpg_signers', None)
        self.gpg_recipients = kwargs.pop('gpg_recipients', None)
        self.gpg_backend = kwargs.pop('gpg_backend', None)
        self.gpg_home = kwargs.pop('gpg_home', None)
        self.gpg_path = kwargs.pop('gpg_path', None)
        self.gpg_always_trust = kwargs.pop('gpg_always_trust', None)

        if self.encrypted:
            self.protocol = 'application/pgp-encrypted'
            self.mixed_subtype = 'encrypted'
            self.alternative_subtype = 'encrypted'
        elif self.signed:
            self.protocol = 'application/pgp-signature'
            self.mixed_subtype = 'signed'
            self.alternative_subtype = 'signed'

        super(GPGEmailMessage, self).__init__(*args, **kwargs)

    def get_backend(self):
        return self.gpg_backend

    def get_base_message(self, message):
        payload = message.get_payload()

        if isinstance(message, SafeMIMEMultipart):
            # If this is a multipart message, we encrypt all its parts.
            # We create a new SafeMIMEMultipart instance, the original message contains all
            # headers (From, To, ...) which we shouldn't sign/encrypt.
            base = SafeMIMEMultipart(_subtype='alternative', _subparts=payload)
        else:
            # If it is a non-multipart message (-> plain-text email), we just encrypt the payload
            base = SafeMIMEText(payload)

            # TODO: Is it possible to influence the main content type of the message? If yes, we
            #       need to copy it here.

        del base['MIME-Version']
        return base

    def encrypt_message(self, message):
        to_encrypt = self.get_base_message(message)
        backend = self.get_backend()

        control_msg = backend.get_control_message()
        encrypted_msg = backend.get_octet_stream(to_encrypt, recipients=self.gpg_recipients,
                                                 signers=self.gpg_signers)

        if isinstance(message, SafeMIMEMultipart):
            message.set_payload([control_msg, encrypted_msg])
            message.set_param('protocol', self.protocol)
            return message

        gpg_msg = SafeMIMEMultipart(_subtype=self.alternative_subtype, encoding=message.encoding)
        gpg_msg.attach(control_msg)
        gpg_msg.attach(encrypted_msg)

        # copy headers
        for key, value in message.items():
            if key.lower() in ['Content-Type', 'Content-Transfer-Encoding']:
                continue
            gpg_msg[key] = value

        gpg_msg.set_param('protocol', self.protocol)
        return gpg_msg

    def sign_message(self, message, **kwargs):
        to_sign = self.get_base_message(message)
        backend = self.get_backend()

        if isinstance(message, SafeMIMEMultipart):
            # We have to adjust the policy because Django SOMEHOW adjusts the line-length of
            # multipart messages. This means a line-break in the Content-Type header of to_sign
            # gets removed, and this breaks the signature.
            to_sign.policy = to_sign.policy.clone(max_line_length=0)

        # get the gpg signature
        signature = backend.sign(to_sign.as_bytes(linesep='\r\n'), self.gpg_signers, add_cr=False,
                                 **kwargs)
        signature_msg = backend.get_mime_signature(signature)

        if isinstance(message, SafeMIMEMultipart):
            message.set_payload([to_sign, signature_msg])
            message.set_param('protocol', self.protocol)
            message.set_param('micalg', 'pgp-sha256')
            return message

        gpg_msg = SafeMIMEMultipart(_subtype=self.alternative_subtype, encoding=message.encoding)
        gpg_msg.attach(to_sign)
        gpg_msg.attach(signature_msg)

        # copy headers
        for key, value in message.items():
            if key.lower() in ['Content-Type', 'Content-Transfer-Encoding']:
                continue
            gpg_msg[key] = value

        gpg_msg.set_param('protocol', self.protocol)
        gpg_msg.set_param('micalg', 'pgp-sha256')
        return gpg_msg

    def message(self):
        orig_msg = super(GPGEmailMessage, self).message()

        if self.encrypted:
            return self.encrypt_message(orig_msg)
        elif self.signed:
            return self.sign_message(orig_msg)
        else:
            # If neither encryption nor signing was request, we just return the normal message
            return orig_msg

    @property
    def signed(self):
        return bool(self.gpg_signers or (self.gpg_context and self.gpg_context.signers))

    @property
    def encrypted(self):
        return bool(self.gpg_recipients)

