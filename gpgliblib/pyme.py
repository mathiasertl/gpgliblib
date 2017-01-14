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

import six
from pyme import core
from pyme.constants import PROTOCOL_OpenPGP
from pyme.errors import GPGMEError

from .base import GpgBackendBase
from .base import GpgKey
from .base import MODE_ARMOR


class PymeBackend(GpgBackendBase):
    # https://bitbucket.org/malb/pyme/src/790795b0ad11/examples/?at=master
    # http://pyme.sourceforge.net/

    def __init__(self, home=None, path=None, default_trust=False):
        self._home = home
        self._path = path
        self._default_trust = default_trust
        self._local = local()

    @property
    def context(self):
        core.check_version()  # pyme fails otherwise *facepalm*

        if hasattr(self._local, 'context') is False:
            context = core.Context()
            context.set_armor(True)

            if self._path or self._home:
                context.set_engine_info(PROTOCOL_OpenPGP, self._path, self._home)

            self._local.context = context

        return self._local.context

    def get_key(self, fingerprint):
        return PymeKey(self, fingerprint)

    def _get_gpgme_key(self, obj):
        if isinstance(obj, six.string_types):
            if six.PY2 and isinstance(obj, unicode):
                obj = obj.encode('utf-8')

            return PymeKey(self, obj)._key
        return obj._key

    def import_key(self, data):
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

    def encrypt(self, data, recipients, **kwargs):
        data = core.Data(data)
        cipher = core.Data()
        keys = [self._get_gpgme_key(r) for r in recipients]
        self.context.op_encrypt(keys, 1, data, cipher)
        cipher.seek(0, 0)
        return cipher.read()

    def sign_encrypt(self, data, recipients, signer, **kwargs):
        raise NotImplementedError

    def verify(self, data, signature):
        raise NotImplementedError

    def decrypt(self, data):
        cipher = core.Data(data)
        output = core.Data()
        self.context.op_decrypt(cipher, output)
        output.seek(0, 0)
        return output.read()

    def decrypt_verify(self, data):
        """Decrypt data and verify the embedded signature.

        Parameters
        ----------

        data : bytes
            The signed and encrypted data.

        Returns
        -------

        (bytes, str)
            The decrypted data and the fingerprint of the key used in the signature.

        Raises
        ------

        GpgBadSignature
            If the signature is invalid.
        """
        raise NotImplementedError

    def sign(self, data, signer):
        """Sign passed data with the given keys.

        Parameters
        ----------

        data : bytes
            The data to sign.
        signer : str
            Key id to sign the message with.
        """
        raise NotImplementedError


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
            self._loaded_key = self.backend.context.get_key(self.fingerprint, False)

        return self._loaded_key

    @property
    def _secret_key(self):
        if self._loaded_secret_key is None:
            try:
                self._loaded_secret_key = self.backend.context.get_key(self.fingerprint, True)
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

        raise NotImplementedError

    @trust.setter
    def trust(self, value):
        raise NotImplementedError

    @property
    def expires(self):
        """If and when a key expires.

        This is a datetime for when the key expires, or ``None`` if it does not expire.
        """
        raise NotImplementedError

    @property
    def revoked(self):
        return self._key.revoked == 1

    def export(self, mode=MODE_ARMOR, output=None):
        """Export the current public key.

        The ``mode`` parameter controls the output format of the signature. If
        :py:data:`~gpgliblib.base.MODE_ARMOR` is passed (which is the default), the key is in ASCII
        armored format (as ``str``). If :py:data:`~gpgliblib.base.MODE_BINARY` is passed, the key
        is returned in binary format (as ``binary``).

        You can also pass the ``output`` parameter to directly write the key to a file-like
        object. The file must be opened in binary mode (``"w+b"``). If output is passed, the
        function does not return the key. Note that depending on the backend, the key may still be
        read entirely into memory and only then written to the file.

        .. versionadded:: 0.2.0

        Parameters
        ----------

        mode : {``MODE_ARMOR``, ``MODE_BINARY``}, optional
            One of the ``MODE_*`` constants.
        output : file-like object, optional
            If passed, the signature will be written directly to the file-like object.

        Returns
        -------

        str, bytes or None
            The key in the specified format or ``None`` if ``output`` is passed.
        """
        raise NotImplementedError

    def delete(self, secret_key=False):
        """Delete the key from the keyring.

        .. versionadded:: 0.2.0

        Parameters
        ----------

        secret_key : bool, optional
            If ``True``, also remove secret keys. If a secret key is present and ``secret_key`` is
            ``False`` (the default), the function will raise
            :py:class:`~gpgliblib.base.GpgSecretKeyPresent`.

        Raises
        ------

        GpgSecretKeyPresent
            If ``secret_key`` is ``False`` and a secret key is present.
        """
        raise NotImplementedError

    def __str__(self):
        return '<%s: %s>' % (self.__class__.__name__, self.fingerprint)

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return self.backend == other.backend and self.fingerprint == other.fingerprint

    def __ne__(self, other):
        return self.backend != other.backend or self.fingerprint != other.fingerprint

    def __hash__(self):
        return hash((self.backend, self.fingerprint))
