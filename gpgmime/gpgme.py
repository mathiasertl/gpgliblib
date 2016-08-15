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

from datetime import datetime

import gpgme
import gpgme.editutil
import six

from .base import GpgBackendBase
from .base import GpgUntrustedKeyError
from .base import GpgKeyNotFoundError
from .base import VALIDITY_UNKNOWN
from .base import VALIDITY_NEVER
from .base import VALIDITY_MARGINAL
from .base import VALIDITY_FULL
from .base import VALIDITY_ULTIMATE


class GpgMeBackend(GpgBackendBase):
    """A backend using `pygpgme <https://pypi.python.org/pypi/pygpgme/>`_.

    All ``kwargs`` for the constructor are passed to :py:class:`~gpgmime.base.GpgBackendBase`.

    This backend requires that you install ``pygpgme``::

        pip install pygpgme

    Note that there is also `unofficial (and incomplete) documentation
    <https://pygpgme.readthedocs.io/en/latest/api.html>`_ for pygpgme.

    Parameters
    ----------

    context : gpgme.Context, optional
        A default context to use. If not passed, a new context with no parameters will be used.
    """

    def __init__(self, context=None, **kwargs):
        self._context = context
        super(GpgMeBackend, self).__init__(**kwargs)

    def get_context(self, **kwargs):
        if kwargs.get('context'):
            return kwargs['context']

        if self._context is None:
            context = gpgme.Context()
        else:
            context = self._context

        context.armor = True

        # Set home and path for this context, if requested
        path = kwargs.get('path', self._path)
        home = kwargs.get('home', self._home)
        if path or home:
            context.set_engine_info(gpgme.PROTOCOL_OpenPGP, path, home)

        return context

    def _encrypt_flags(self, always_trust=True, **kwargs):
        flags = 0
        if always_trust is True:
            flags |= gpgme.ENCRYPT_ALWAYS_TRUST
        return flags

    def _encrypt(self, data, recipients, context, always_trust):
        try:
            recipients = [context.get_key(k.upper()) for k in recipients]
        except gpgme.GpgmeError as e:
            if e.source == gpgme.ERR_SOURCE_GPGME and e.code == gpgme.ERR_EOF:
                raise GpgKeyNotFoundError("Key not found.")

            raise

        output_bytes = six.BytesIO()
        flags = self._encrypt_flags(always_trust=always_trust)
        try:
            if context.signers:
                context.encrypt_sign(recipients, flags, six.BytesIO(data), output_bytes)
            else:
                context.encrypt(recipients, flags, six.BytesIO(data), output_bytes)
        except gpgme.GpgmeError as e:
            if e.source == gpgme.ERR_SOURCE_UNKNOWN and e.code == gpgme.ERR_GENERAL:
                raise GpgUntrustedKeyError("Key not trusted.")

            raise

        output_bytes.seek(0)
        return output_bytes.getvalue()

    def sign(self, data, signers, **kwargs):
        context = self.get_context(**kwargs)
        signers = [context.get_key(k.upper()) for k in signers]
        context.signers = signers

        output_bytes = six.BytesIO()
        context.sign(six.BytesIO(data), output_bytes, gpgme.SIG_MODE_DETACH)
        output_bytes.seek(0)
        return output_bytes.getvalue()

    def encrypt(self, data, recipients, **kwargs):
        always_trust = kwargs.pop('always_trust', self._always_trust)
        context = self.get_context(**kwargs)
        return self._encrypt(data, recipients, context, always_trust)

    def sign_encrypt(self, data, recipients, signers, **kwargs):
        always_trust = kwargs.pop('always_trust', self._always_trust)
        context = self.get_context(**kwargs)
        signers = [context.get_key(k.upper()) for k in signers]
        context.signers = signers

        return self._encrypt(data, recipients, context, always_trust)

    def verify(self, data, signature, **kwargs):
        context = self.get_context(**kwargs)
        signatures = context.verify(six.BytesIO(signature), six.BytesIO(data), None)

        errors = list(filter(lambda s: s.status is not None, signatures))
        if not errors:
            return [s.fpr for  s in signatures]

    def decrypt(self, data, **kwargs):
        context = self.get_context(**kwargs)
        output = six.BytesIO()
        context.decrypt(six.BytesIO(data), output)
        return output.getvalue()

    def decrypt_verify(self, data, **kwargs):
        context = self.get_context(**kwargs)
        output = six.BytesIO()
        signatures = context.decrypt_verify(six.BytesIO(data), output)

        errors = list(filter(lambda s: s.status is not None, signatures))
        if not errors:
            return output.getvalue(), [s.fpr for  s in signatures]

    def import_key(self, data, **kwargs):
        context = self.get_context(**kwargs)
        result = context.import_(six.BytesIO(data))
        if len(result.imports) >= 1:
            return result.imports[0][0]

    def import_private_key(self, data, **kwargs):
        context = self.get_context(**kwargs)
        result = context.import_(six.BytesIO(data))
        if len(result.imports) >= 1:
            return result.imports[0][0]

    def set_trust(self, fingerprint, trust, **kwargs):
        context = self.get_context(**kwargs)
        key = context.get_key(fingerprint.upper())

        if trust == VALIDITY_NEVER:
            trust = gpgme.VALIDITY_NEVER
        elif trust == VALIDITY_MARGINAL:
            trust = gpgme.VALIDITY_MARGINAL
        elif trust == VALIDITY_FULL:
            trust = gpgme.VALIDITY_FULL
        elif trust == VALIDITY_ULTIMATE:
            trust = gpgme.VALIDITY_ULTIMATE
        else:
            raise ValueError("Unknown trust passed.")

        gpgme.editutil.edit_trust(context, key, trust)

    def get_trust(self, fingerprint, **kwargs):
        context = self.get_context(**kwargs)
        key = context.get_key(fingerprint.upper())

        if key.owner_trust == gpgme.VALIDITY_UNKNOWN:
            return VALIDITY_UNKNOWN
        elif key.owner_trust == gpgme.VALIDITY_NEVER:
            return VALIDITY_NEVER
        elif key.owner_trust == gpgme.VALIDITY_MARGINAL:
            return VALIDITY_MARGINAL
        elif key.owner_trust == gpgme.VALIDITY_FULL:
            return VALIDITY_FULL
        elif key.owner_trust == gpgme.VALIDITY_ULTIMATE:
            return VALIDITY_ULTIMATE
        else:
            return VALIDITY_UNKNOWN

    def expires(self, fingerprint, **kwargs):
        context = self.get_context(**kwargs)
        key = context.get_key(fingerprint.upper())
        expires = lambda i: datetime.fromtimestamp(i) if i else None
        subkeys = {sk.fpr: expires(sk.expires) for sk in key.subkeys}
        return subkeys[fingerprint]
