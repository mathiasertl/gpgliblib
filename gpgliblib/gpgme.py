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

from datetime import datetime
from threading import local

import gpgme
import gpgme.editutil
import six

from .base import VALIDITY_FULL
from .base import VALIDITY_MARGINAL
from .base import VALIDITY_NEVER
from .base import GpgBackendBase
from .base import GpgBadSignature
from .base import GpgKey
from .base import GpgKeyNotFoundError
from .base import GpgUntrustedKeyError
from .base import VALIDITY_ULTIMATE
from .base import VALIDITY_UNKNOWN


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
        super(GpgMeBackend, self).__init__(**kwargs)
        self._local = local()

    @property
    def context(self):
        if hasattr(self._local, 'context') is False:
            context = gpgme.Context()
            context.armor = True

            if self._path or self._home:
                context.set_engine_info(gpgme.PROTOCOL_OpenPGP, self._path, self._home)
            self._local.context = context

        return self._local.context

    def get_key(self, fingerprint):
        return GpgMeKey(self, fingerprint)

    def _get_gpgme_key(self, obj):
        if isinstance(obj, six.string_types):
            return GpgMeKey(self, obj)._key
        return obj._key

    def _encrypt_flags(self, always_trust=True, **kwargs):
        flags = 0
        if always_trust is True:
            flags |= gpgme.ENCRYPT_ALWAYS_TRUST
        return flags

    def _encrypt(self, data, recipients, always_trust):
        recipients = [self._get_gpgme_key(r) for r in recipients]

        output_bytes = six.BytesIO()
        flags = self._encrypt_flags(always_trust=always_trust)
        try:
            if self.context.signers:
                self.context.encrypt_sign(recipients, flags, six.BytesIO(data), output_bytes)
            else:
                self.context.encrypt(recipients, flags, six.BytesIO(data), output_bytes)
        except gpgme.GpgmeError as e:
            if e.source == gpgme.ERR_SOURCE_UNKNOWN and e.code == gpgme.ERR_GENERAL:
                raise GpgUntrustedKeyError("Key not trusted.")

            raise

        output_bytes.seek(0)
        return output_bytes.getvalue()

    def sign(self, data, signer):
        output_bytes = six.BytesIO()

        self.context.signers = [self._get_gpgme_key(signer)]
        try:
            self.context.sign(six.BytesIO(data), output_bytes, gpgme.SIG_MODE_DETACH)
        finally:
            self.context.signers = []
        output_bytes.seek(0)
        return output_bytes.getvalue()

    def encrypt(self, data, recipients, **kwargs):
        always_trust = kwargs.get('always_trust', self._default_trust)
        return self._encrypt(data, recipients, always_trust)

    def sign_encrypt(self, data, recipients, signer, **kwargs):
        always_trust = kwargs.get('always_trust', self._default_trust)
        self.context.signers = [self._get_gpgme_key(signer)]

        try:
            return self._encrypt(data, recipients, always_trust)
        finally:
            self.context.signers = []

    def verify(self, data, signature):
        signatures = self.context.verify(six.BytesIO(signature), six.BytesIO(data), None)

        errors = list(filter(lambda s: s.status is not None, signatures))
        if not errors:
            return signatures[0].fpr
        raise GpgBadSignature("Bad signature", errors=errors)

    def decrypt(self, data):
        output = six.BytesIO()
        self.context.decrypt(six.BytesIO(data), output)
        return output.getvalue()

    def decrypt_verify(self, data):
        output = six.BytesIO()
        signatures = self.context.decrypt_verify(six.BytesIO(data), output)

        errors = list(filter(lambda s: s.status is not None, signatures))
        if not errors:
            return output.getvalue(), signatures[0].fpr

    def import_key(self, data):
        if six.PY3 and isinstance(data, str):
            data = data.encode('utf-8')

        result = self.context.import_(six.BytesIO(data))
        return [GpgMeKey(self, r[0]) for r in result.imports]

    def import_private_key(self, data):
        if six.PY3 and isinstance(data, str):
            data = data.encode('utf-8')

        result = self.context.import_(six.BytesIO(data))
        return list(set([GpgMeKey(self, r[0]) for r in result.imports]))

    def list_keys(self, query=None, secret_keys=False):
        return [GpgMeKey(self, key=k) for k in self.context.keylist(query, secret_keys)]


class GpgMeKey(GpgKey):
    _loaded_key = None

    def __init__(self, backend, fingerprint=None, key=None):
        if not fingerprint and not key:
            raise ValueError("Must pass either fingerprint or key.")
        elif not fingerprint:
            fingerprint = key.subkeys[0].fpr

        super(GpgMeKey, self).__init__(backend, fingerprint)
        self._loaded_key = key

    @property
    def _key(self):
        if self._loaded_key is None:
            try:
                self._loaded_key = self.backend.context.get_key(self.fingerprint.upper())
            except gpgme.GpgmeError as e:
                if e.source == gpgme.ERR_SOURCE_GPGME and e.code == gpgme.ERR_EOF:
                    raise GpgKeyNotFoundError("%s: key not found." % self.fingerprint)
                raise
        return self._loaded_key

    def refresh(self):
        self._loaded_key = None

    @property
    def name(self):
        return self._key.uids[0].name

    @property
    def comment(self):
        comment = self._key.uids[0].comment
        if comment:
            return comment

    @property
    def email(self):
        return self._key.uids[0].email

    @property
    def trust(self):
        if self._key.owner_trust == gpgme.VALIDITY_UNKNOWN:
            return VALIDITY_UNKNOWN
        elif self._key.owner_trust == gpgme.VALIDITY_NEVER:
            return VALIDITY_NEVER
        elif self._key.owner_trust == gpgme.VALIDITY_MARGINAL:
            return VALIDITY_MARGINAL
        elif self._key.owner_trust == gpgme.VALIDITY_FULL:
            return VALIDITY_FULL
        elif self._key.owner_trust == gpgme.VALIDITY_ULTIMATE:
            return VALIDITY_ULTIMATE
        else:
            return VALIDITY_UNKNOWN

    @trust.setter
    def trust(self, value):
        if value == VALIDITY_NEVER:
            value = gpgme.VALIDITY_NEVER
        elif value == VALIDITY_MARGINAL:
            value = gpgme.VALIDITY_MARGINAL
        elif value == VALIDITY_FULL:
            value = gpgme.VALIDITY_FULL
        elif value == VALIDITY_ULTIMATE:
            value = gpgme.VALIDITY_ULTIMATE
        else:
            raise ValueError("Unknown value passed.")

        gpgme.editutil.edit_trust(self.backend.context, self._key, value)
        self.refresh()  # TODO: can we avoid reloading?

    @property
    def expires(self):
        expires = lambda i: datetime.fromtimestamp(i) if i else None
        subkeys = {sk.fpr: expires(sk.expires) for sk in self._key.subkeys}
        return subkeys[self.fingerprint]

    @property
    def revoked(self):
        return self._key.revoked
