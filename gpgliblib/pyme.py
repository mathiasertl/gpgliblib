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

import shutil
from contextlib import contextmanager
from datetime import datetime
from threading import local

import six
from pyme import core
from pyme import constants
from pyme import errors
from pyme.errors import GPGMEError

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

if six.PY3:  # pragma: py3
    from pyme.errors import CONFLICT
    from pyme.errors import DECRYPT_FAILED
    from pyme.errors import EOF as END_OF_FILE
    from pyme.errors import SOURCE_GPGME
    from pyme.errors import SOURCE_UNKNOWN
    from pyme.errors import UNUSABLE_PUBKEY
else:  # pragma: py2
    # The python2 version does not define these constants.
    CONFLICT = 70
    DECRYPT_FAILED = 152
    END_OF_FILE = 16383
    SOURCE_GPGME = 7
    SOURCE_UNKNOWN = 0


class PymeBackend(GpgBackendBase):
    """A gpgliblib backend using `pyme3 <https://pypi.python.org/pypi/pyme3>`_.

    .. versionadded:: 0.2.0
    """

    def __init__(self, home=None, path=None, default_trust=False):
        super(PymeBackend, self).__init__(home=home, path=path, default_trust=default_trust)
        self._local = local()

    @property
    def context(self):
        core.check_version()  # pyme fails otherwise *facepalm*

        if hasattr(self._local, 'context') is False:
            context = core.Context()
            context.set_armor(True)

            if self._path or self._home:
                context.set_engine_info(constants.PROTOCOL_OpenPGP, self._path, self._home)

            self._local.context = context

        return self._local.context

    @contextmanager
    def _attrs(self, armor=None, signer=None):
        context = self.context

        if armor is not None:
            old_armor = context.get_armor()
            context.set_armor(armor)
        if signer is not None:
            context.signers_add(self._get_gpgme_key(signer))

        try:
            yield context
        finally:
            if armor is not None:
                context.set_armor(old_armor)
            if signer is not None:
                context.signers_clear()

    @property
    def gnupg_version(self):
        if self._gnupg_version is None:
            engines = self.context.get_engine_info()
            engine = [e for e in engines if e.protocol == constants.PROTOCOL_OpenPGP][0]
            self._gnupg_version = tuple([int(r) for r in engine.version.split('.')])

        return self._gnupg_version

    def get_key(self, fingerprint):
        return PymeKey(self, fingerprint)

    def _get_gpgme_key(self, obj):
        if isinstance(obj, six.string_types):
            if six.PY2 and isinstance(obj, unicode):
                obj = obj.encode('utf-8')

            return PymeKey(self, obj)._key
        return obj._key

    def import_key(self, data):
        if six.PY2 and isinstance(data, unicode):
            data = data.encode('utf-8')

        newkey = core.Data(data)
        self.context.op_import(newkey)
        result = self.context.op_import_result()
        return list(set([PymeKey(self, r.fpr) for r in result.imports]))

    def import_private_key(self, data):
        return self.import_key(data)

    def list_keys(self, query=None, secret_keys=False):
        if six.PY2 and isinstance(query, unicode):
            query = query.encode('utf-8')

        keys = self.context.op_keylist_all(query, secret_keys)
        return [PymeKey(self, key=k) for k in keys]

    def sign(self, data, signer):
        data = core.Data(data)
        sig = core.Data()

        with self._attrs(signer=signer) as context:
            context.op_sign(data, sig, constants.SIG_MODE_DETACH)

        sig.seek(0, 0)
        return sig.read()

    def _encrypt(self, data, recipients, sign=False, **kwargs):
        always_trust = kwargs.get('always_trust', self._default_trust)

        flags = 0
        if always_trust is True:
            flags |= constants.ENCRYPT_ALWAYS_TRUST

        data = core.Data(data)
        cipher = core.Data()
        keys = [self._get_gpgme_key(r) for r in recipients]

        try:
            if sign is True:
                self.context.op_encrypt_sign(keys, flags, data, cipher)
            else:
                self.context.op_encrypt(keys, flags, data, cipher)
        except GPGMEError as e:
            code = e.getcode()
            source = e.getsource()

            if code == 1 and source == SOURCE_UNKNOWN:  # pragma: gpg1
                raise GpgUntrustedKeyError('Key not trusted.')

            elif code == UNUSABLE_PUBKEY and source == SOURCE_GPGME:  # pragma: gpg2
                raise GpgUntrustedKeyError('Key not trusted.')

            raise UnknownGpgliblibError(e.getstring())  # pragma: no cover
        cipher.seek(0, 0)
        return cipher.read()

    def encrypt(self, data, recipients, **kwargs):
        return self._encrypt(data, recipients, **kwargs)

    def sign_encrypt(self, data, recipients, signer, **kwargs):
        with self._attrs(signer=signer):
            return self.encrypt(data, recipients, sign=True, **kwargs)

    def verify(self, data, signature):
        data = core.Data(data)
        signature = core.Data(signature)
        self.context.op_verify(signature, data, None)
        result = self.context.op_verify_result()
        signatures = result.signatures
        errors = list(filter(lambda s: s.status != 0, signatures))
        if not errors:
            return result.signatures[0].fpr
        raise GpgBadSignature("Bad signature", errors=errors)

    def decrypt(self, data):
        cipher = core.Data(data)
        output = core.Data()

        try:
            self.context.op_decrypt(cipher, output)
        except GPGMEError as e:
            code = e.getcode()
            source = e.getsource()

            if code == DECRYPT_FAILED and source == SOURCE_GPGME:
                raise GpgDecryptionFailed(e.getstring())

            raise UnknownGpgliblibError(e.getstring())  # pragma: no cover

        output.seek(0, 0)
        return output.read()

    def decrypt_verify(self, data):
        cipher = core.Data(data)
        output = core.Data()
        data = self.context.op_decrypt_verify(cipher, output)
        output.seek(0, 0)
        result = self.context.op_verify_result()
        if result.signatures:
            return output.read(), result.signatures[0].fpr
        else:
            return output.read(), None


class PymeKey(GpgKey):
    _loaded_key = None
    _loaded_secret_key = None

    def __init__(self, backend, fingerprint=None, key=None):
        if not fingerprint and not key:
            raise ValueError("Must pass either fingerprint or key.")
        elif not fingerprint:
            fingerprint = key.subkeys[0].fpr

        super(PymeKey, self).__init__(backend, fingerprint)
        self._loaded_key = key

    def refresh(self):
        """Reset any in-memory data used by this key."""
        self._loaded_key = None

    @property
    def _key(self):
        if self._loaded_key is None:
            fingerprint = self.fingerprint
            if six.PY2 is True and isinstance(fingerprint, unicode):
                fingerprint = fingerprint.encode('utf-8')

            try:
                self._loaded_key = self.backend.context.get_key(fingerprint, False)
            except GPGMEError as e:
                # pyme3 has convenient bindings for that
                if six.PY3 and isinstance(e, errors.KeyNotFound):  # pragma: py3
                    raise GpgKeyNotFoundError(e.keystr)

                code = e.getcode()
                source = e.getsource()
                if code == END_OF_FILE and source == SOURCE_GPGME:
                    raise GpgKeyNotFoundError(self.fingerprint)
                raise UnknownGpgliblibError(e.getstring())  # pragma: no cover

        return self._loaded_key

    @property
    def _secret_key(self):
        if self._loaded_secret_key is None:
            fingerprint = self.fingerprint
            if six.PY2 is True and isinstance(fingerprint, unicode):
                fingerprint = fingerprint.encode('utf-8')

            try:
                self._loaded_secret_key = self.backend.context.get_key(fingerprint, True)
            except GPGMEError:
                self._loaded_secret_key = False

        return self._loaded_secret_key

    @property
    def name(self):
        return self._key.uids[0].name

    @property
    def comment(self):
        return self._key.uids[0].comment or None

    @property
    def email(self):
        return self._key.uids[0].email

    @property
    def has_secret_key(self):
        """``True`` if there is a secret key present for this key, ``False`` otherwise."""

        return self._secret_key is not False

    @property
    def trust(self):
        """The current trust for this key.

        The value is one of the ``VALIDITY_*`` :ref:`constants <api-constants>` and can also be
        used to set the trust of a key.
        """

        if self._key.owner_trust == constants.VALIDITY_UNKNOWN:
            return VALIDITY_UNKNOWN
        elif self._key.owner_trust == constants.VALIDITY_NEVER:
            return VALIDITY_NEVER
        elif self._key.owner_trust == constants.VALIDITY_MARGINAL:
            return VALIDITY_MARGINAL
        elif self._key.owner_trust == constants.VALIDITY_FULL:
            return VALIDITY_FULL
        elif self._key.owner_trust == constants.VALIDITY_ULTIMATE:
            return VALIDITY_ULTIMATE
        else:  # pragma: no cover
            return VALIDITY_UNKNOWN

    @trust.setter
    def trust(self, value):
        raise NotImplementedError

    @property
    def expires(self):
        expires = lambda i: datetime.fromtimestamp(i) if i else None
        subkeys = {sk.fpr: expires(sk.expires) for sk in self._key.subkeys}
        return subkeys[self.fingerprint]

    @property
    def revoked(self):
        return self._key.revoked == 1

    def export(self, mode=MODE_ARMOR, output=None):
        exp = core.Data()
        with self.backend._attrs(armor=mode == MODE_ARMOR) as context:
            context.op_export(self.fingerprint, 0, exp)

        if output is None:
            exp.seek(0, 0)
            value = exp.read()
            if mode == MODE_ARMOR:
                return value.decode('utf-8')
            return value
        else:
            exp.seek(0, 0)
            shutil.copyfileobj(exp, output)

    def delete(self, secret_key=False):
        try:
            self.backend.context.op_delete(self._key, secret_key)
        except GPGMEError as e:
            code = e.getcode()
            source = e.getsource()
            if code == CONFLICT and source == SOURCE_GPGME:  # pragma: gpg1
                raise GpgSecretKeyPresent('Secret key is present.')
            elif code == END_OF_FILE and source == SOURCE_GPGME:  # pragma: gpg2
                raise GpgKeyNotFoundError(self.fingerprint)
            raise UnknownGpgliblibError(e.getstring())  # pragma: no cover
