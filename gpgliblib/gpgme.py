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

from contextlib import contextmanager
from datetime import datetime
from threading import local

import gpgme
import gpgme.editutil
import six
from gpgme import ERR_EOF
from gpgme import ERR_GENERAL
from gpgme import ERR_SOURCE_GPGME
from gpgme import ERR_SOURCE_UNKNOWN
from gpgme import ERR_UNUSABLE_PUBKEY

from .base import GpgBackendBase
from .base import GpgBadSignature
from .base import GpgDecryptionFailed
from .base import GpgKey
from .base import GpgKeyNotFoundError
from .base import GpgSecretKeyPresent
from .base import GpgUntrustedKeyError
from .base import MODE_ARMOR
from .base import UnknownGpgliblibError
from .base import VALIDITY_FULL
from .base import VALIDITY_MARGINAL
from .base import VALIDITY_NEVER
from .base import VALIDITY_ULTIMATE
from .base import VALIDITY_UNKNOWN
from .utils import get_version


class GpgMeBackend(GpgBackendBase):
    """A gpgliblib backend using `pygpgme <https://pypi.python.org/pypi/pygpgme/>`_.

    ``pygpgme`` cannot get the GnuPG version used by itself, and setting key trust works different
    depending on what version is used. This backend thus requires the ``gnupg_version`` parameter
    to be passed if you want to set the trust of keys.
    """

    def __init__(self, **kwargs):
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

    @contextmanager
    def _attrs(self, signers=None, armor=None):
        context = self.context

        if signers is not None:
            old_signers = context.signers
            context.signers = signers
        if armor is not None:
            old_armor = context.armor
            context.armor = armor

        try:
            yield context
        finally:
            if signers is not None:
                context.signers = old_signers
            if armor is not None:
                context.armor = old_armor

    @property
    def gnupg_version(self):
        if self._gnupg_version is None:
            self._gnupg_version = get_version()

        return self._gnupg_version

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
            if e.source == ERR_SOURCE_UNKNOWN and e.code == ERR_GENERAL:  # pragma: gpg1
                raise GpgUntrustedKeyError("Key not trusted.")

            if e.source == ERR_SOURCE_GPGME and e.code == ERR_UNUSABLE_PUBKEY:  # pragma: gpg2
                raise GpgUntrustedKeyError("Key not trusted.")

            raise UnknownGpgliblibError(e.strerror)  # pragma: no cover

        output_bytes.seek(0)
        return output_bytes.getvalue()

    def sign(self, data, signer):
        output_bytes = six.BytesIO()

        with self._attrs(signers=[self._get_gpgme_key(signer)]) as context:
            context.sign(six.BytesIO(data), output_bytes, gpgme.SIG_MODE_DETACH)

        output_bytes.seek(0)
        return output_bytes.getvalue()

    def encrypt(self, data, recipients, **kwargs):
        always_trust = kwargs.get('always_trust', self._default_trust)
        return self._encrypt(data, recipients, always_trust)

    def sign_encrypt(self, data, recipients, signer, **kwargs):
        always_trust = kwargs.get('always_trust', self._default_trust)
        with self._attrs(signers=[self._get_gpgme_key(signer)]):
            return self._encrypt(data, recipients, always_trust)

    def verify(self, data, signature):
        signatures = self.context.verify(six.BytesIO(signature), six.BytesIO(data), None)

        errors = list(filter(lambda s: s.status is not None, signatures))
        if not errors:
            return signatures[0].fpr
        raise GpgBadSignature("Bad signature", errors=errors)

    def decrypt(self, data):
        output = six.BytesIO()
        try:
            self.context.decrypt(six.BytesIO(data), output)
        except gpgme.GpgmeError as e:
            if e.source == gpgme.ERR_SOURCE_GPGME and e.code == gpgme.ERR_DECRYPT_FAILED:
                raise GpgDecryptionFailed(e.strerror)
            raise UnknownGpgliblibError(e.strerror)  # pragma: no cover

        return output.getvalue()

    def decrypt_verify(self, data):
        output = six.BytesIO()
        signatures = self.context.decrypt_verify(six.BytesIO(data), output)

        errors = list(filter(lambda s: s.status is not None, signatures))
        if not errors:
            if signatures:
                return output.getvalue(), signatures[0].fpr
            else:
                return output.getvalue(), None

    def import_key(self, data):
        if six.PY3 and isinstance(data, str):  # pragma: py3
            data = data.encode('utf-8')
        elif six.PY2 is True and isinstance(data, unicode):  # pragma: py2
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
    _loaded_secret_key = None

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
                self._loaded_key = self.backend.context.get_key(self.fingerprint)
            except gpgme.GpgmeError as e:
                if e.source == ERR_SOURCE_GPGME and e.code == ERR_EOF:
                    raise GpgKeyNotFoundError(self.fingerprint)

                raise UnknownGpgliblibError(e.strerror)  # pragma: no cover
        return self._loaded_key

    @property
    def _secret_key(self):
        if self._loaded_secret_key is None:
            try:
                self._loaded_secret_key = self.backend.context.get_key(self.fingerprint, True)
            except gpgme.GpgmeError:
                self._loaded_secret_key = False
        return self._loaded_secret_key

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
    def has_secret_key(self):
        return self._secret_key is not False

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
        else:  # pragma: no cover
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

        if self.backend.gnupg_version >= (2, ):  # pragma: gpg2

            @gpgme.editutil.key_editor
            def _edit_trust_gnupg2(ctx, key, trust):
                """Copy of gpgme.editutil.edit_trust fixed for gpg2."""
                if trust not in (gpgme.VALIDITY_UNDEFINED,
                                 gpgme.VALIDITY_NEVER,
                                 gpgme.VALIDITY_MARGINAL,
                                 gpgme.VALIDITY_FULL,
                                 gpgme.VALIDITY_ULTIMATE):
                    raise ValueError('Bad trust value %d' % trust)

                status, args = yield None

                # we need to yield an additional None in gpg2.
                status, args = yield None

                assert args == 'keyedit.prompt'
                status, args = yield 'trust\n'

                assert args == 'edit_ownertrust.value'
                status, args = yield '%d\n' % trust

                if args == 'edit_ownertrust.set_ultimate.okay':
                    status, args = yield 'Y\n'

                assert args == 'keyedit.prompt'
                status, args = yield 'quit\n'

                assert args == 'keyedit.save.okay'
                status, args = yield 'Y\n'

            _edit_trust_gnupg2(self.backend.context, self._key, value)
        else:
            gpgme.editutil.edit_trust(self.backend.context, self._key, value)
        self.refresh()

    @property
    def expires(self):
        expires = lambda i: datetime.fromtimestamp(i) if i else None
        subkeys = {sk.fpr: expires(sk.expires) for sk in self._key.subkeys}
        return subkeys[self.fingerprint]

    @property
    def revoked(self):
        return self._key.revoked

    def export(self, mode=MODE_ARMOR, output=None):
        if output is None:
            buf = six.BytesIO()
        else:
            buf = output

        if mode == MODE_ARMOR:
            args = {'armor': True}
        else:
            args = {'armor': False}

        with self.backend._attrs(**args) as context:
            context.export(self.fingerprint, buf)

        if output is None:
            value = buf.getvalue()
            if mode == MODE_ARMOR:
                return value.decode('utf-8')
            return value

    def delete(self, secret_key=False):
        if self.has_secret_key and not secret_key:
            raise GpgSecretKeyPresent('Secret key is present.')

        # NOTE: unlike the unofficial docs, this function does not take any keyword arguments
        self.backend.context.delete(self._key, secret_key)
