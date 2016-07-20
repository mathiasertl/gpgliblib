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

    def encrypt_message(self, message):
        payload = message.get_payload()

        if isinstance(message, SafeMIMEMultipart):
            # If this is a multipart message, we encrypt all its parts.
            # We create a new SafeMIMEMultipart instance, the original message contains all
            # headers (From, To, ...) which we shouldn't sign/encrypt.
            to_encrypt = SafeMIMEMultipart(_subtype='alternative', _subparts=payload)
        else:
            # If it is a non-multipart message (-> plain-text email), we just encrypt the payload
            to_encrypt = SafeMIMEText(payload)

            # TODO: Is it possible to influence the main content type of the message? If yes, we
            #       need to copy it here.

        print(to_encrypt, type(to_encrypt))

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

    def sign_message(self, message):
        pass

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


