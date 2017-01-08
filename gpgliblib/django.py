# -*- coding: utf-8 -*-
#
# This file is part of gpgliblib (https://github.com/mathiasertl/gpgliblib).
#
# gpgliblib is free software: you can redistribute it and/or modify it under the terms of the
# GNU General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# gpgliblib is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with gpgliblib. If
# not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import
from __future__ import unicode_literals

from threading import local

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.mail import EmailMultiAlternatives
from django.core.mail import SafeMIMEMultipart
from django.core.mail import SafeMIMEText
from django.utils.module_loading import import_string

DEFAULT_BACKEND_ALIAS = 'default'


def _create_backend(backend, **kwargs):
    try:
        # Try to get the GPG_BACKENDS entry for the given backend name first
        try:
            conf = settings.GPG_BACKENDS[backend]
        except (KeyError, AttributeError) as e:
            raise ImproperlyConfigured("Could not find backend '%s': %s" % (backend, e))
        else:
            params = conf.copy()
            params.update(kwargs)
            backend = params.pop('BACKEND')

            kwargs = params.pop('OPTIONS', {})
            if 'HOME' in params:
                kwargs['home'] = params['HOME']
            if 'PATH' in params:
                kwargs['path'] = params['PATH']
            if 'DEFAULT_TRUST' in params:
                kwargs['default_trust'] = params['DEFAULT_TRUST']

        backend_cls = import_string(backend)
    except ImportError as e:
        raise ImproperlyConfigured("Could not find backend '%s': %s" % (backend, e))
    return backend_cls(**kwargs)


class GPGHandler(object):
    """A GPG Handler to manage access to GPGBackend instances.

    Ensures only one instance of each alias exists per thread.
    """
    def __init__(self):
        self._backends = local()

    def __getitem__(self, alias):
        try:
            return self._backends.backends[alias]
        except AttributeError:
            self._backends.backends = {}
        except KeyError:
            pass

        if alias not in settings.GPG_BACKENDS:
            raise ImproperlyConfigured(
                "Could not find config for '%s' in settings.GPG_BACKENDS" % alias)

        backend = _create_backend(alias)
        self._backends.backends[alias] = backend
        return backend

    def all(self):
        return getattr(self._backends, 'backends', {}).values()

#: You can access the backends configured in the GPG_BACKENDS setting through this dict-like
#: object. This works just like `django.core.cache.caches
#: <https://docs.djangoproject.com/en/dev/topics/cache/#accessing-the-cache>`_.
gpg_backends = GPGHandler()


class DefaultGPGProxy(object):
    """Proxy access to the default Cache object's attributes.

    This allows the `gpg_backend` object to be thread-safe using the ``gpg_backends`` API.
    """
    def __getattr__(self, name):
        return getattr(gpg_backends[DEFAULT_BACKEND_ALIAS], name)

    def __setattr__(self, name, value):
        return setattr(gpg_backends[DEFAULT_BACKEND_ALIAS], name, value)

    def __delattr__(self, name):
        return delattr(gpg_backends[DEFAULT_BACKEND_ALIAS], name)

    def __contains__(self, key):
        return key in gpg_backends[DEFAULT_BACKEND_ALIAS]

    def __eq__(self, other):
        return gpg_backends[DEFAULT_BACKEND_ALIAS] == other

    def __ne__(self, other):
        return gpg_backends[DEFAULT_BACKEND_ALIAS] != other


#: A shortcut to access the default cache.
gpg_backend = DefaultGPGProxy()


class GpgEmailMessage(EmailMultiAlternatives):
    """Email message that allows you to sign/encrypt messages upon calling ``send()``.

    All parameters are optional. if neither ``gpg_signer`` nor ``gpg_recipients`` is passed, the
    message will be sent unchanged.

    Parameters
    ----------

    gpg_signer : str
        Fingerprints to sign the message with.
    gpg_recipients : list of str, optional
        List of fingerprints to encrypt the message to.
    gpg_backend : :py:class:`gpgmime.base.GpgBackendBase`, optional
        Use a different GPG backend. The default is :py:data:`gpgmime.django.gpg_backend`.
    gpg_home : str, optional
        Override the path to the keyring used.
    gpg_path : str, optional
        Override the path to the ``gpg`` binary used.
    gpg_always_trust : bool
        Pass to ``True`` to trust all keys.
    """

    def __init__(self, *args, **kwargs):
        self.gpg_signer = kwargs.pop('gpg_signer', None)
        self.gpg_recipients = kwargs.pop('gpg_recipients', None)
        self.gpg_backend = kwargs.pop('gpg_backend', None)
        self.gpg_home = kwargs.pop('gpg_home', None)
        self.gpg_path = kwargs.pop('gpg_path', None)
        self.gpg_always_trust = kwargs.pop('gpg_always_trust', None)

        if self.encrypted:
            self.protocol = 'application/pgp-encrypted'
        elif self.signed:
            self.protocol = 'application/pgp-signature'

        super(GpgEmailMessage, self).__init__(*args, **kwargs)

    def get_backend(self):
        if self.gpg_backend is None:
            return gpg_backend
        return self.gpg_backend

    def get_base_message(self, message):
        payload = message.get_payload()

        if isinstance(message, SafeMIMEMultipart):
            # If this is a multipart message, we encrypt all its parts.
            # We create a new SafeMIMEMultipart instance, the original message contains all
            # headers (From, To, ...) which we shouldn't sign/encrypt.
            subtype = message.get_content_subtype()
            base = SafeMIMEMultipart(_subtype=subtype, _subparts=payload)
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
                                                 signer=self.gpg_signer)

        if isinstance(message, SafeMIMEMultipart):
            message.set_payload([control_msg, encrypted_msg])
            message.set_param('protocol', self.protocol)
            message.set_type('multipart/encrypted')
            return message

        gpg_msg = SafeMIMEMultipart(_subtype='encrypted', encoding=message.encoding)
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
        signature = backend.sign(to_sign.as_bytes(linesep='\r\n'), self.gpg_signer)
        signature_msg = backend.get_mime_signature(signature)

        if isinstance(message, SafeMIMEMultipart):
            message.set_payload([to_sign, signature_msg])
            message.set_param('protocol', self.protocol)
            message.set_param('micalg', 'pgp-sha256')
            message.set_type('multipart/signed')
            return message

        gpg_msg = SafeMIMEMultipart(_subtype='signed', encoding=message.encoding)
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
        orig_msg = super(GpgEmailMessage, self).message()

        if self.encrypted:
            return self.encrypt_message(orig_msg)
        elif self.signed:
            return self.sign_message(orig_msg)
        else:
            # If neither encryption nor signing was request, we just return the normal message
            return orig_msg

    @property
    def signed(self):
        """True if this message will be signed."""

        return bool(self.gpg_signer)

    @property
    def encrypted(self):
        """True if this message will be encrypted."""

        return bool(self.gpg_recipients)
