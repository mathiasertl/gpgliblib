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

from pyme import core
from pyme.errors import GPGMEError

from .base import GpgBackendBase
from .base import GpgKey
from .base import MODE_ARMOR


class PymeBackend(GpgBackendBase):
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
    default_trust : bool, optional
        If ``True``, the backend will trust all keys by default.
    """

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
            # TODO: We cannot set path or home yet

            self._local.context = context

        return self._local.context

    def import_key(self, data):
        newkey = core.Data(data)
        self.context.op_import(newkey)
        result = self.context.op_import_result()
        return [PymeKey(self, r.fpr) for r in result.imports]

    def import_private_key(self, data):
        """Import a private key.

        Parameters
        ----------

        data : str or bytes
            The private key data. Can be in binary or in ASCII armored format.
        **kwargs
            Any additional parameters to the GPG backend.

        Returns
        -------

        list of GpgKey
            A list of GpgKey instances that were imported.
        """
        raise NotImplementedError

    def list_keys(self, query=None, secret_keys=False):
        """List keys in the keyring.

        Parameters
        ----------

        query : str, optional
            Only list keys matching the given query.
        secret_keys : bool, optional
            Only return keys with a secret key.

        Returns
        -------

        list of GpgKey
            A list of GpgKey instances representing the keys that were found.
        """
        raise NotImplementedError

    ################
    # Cryptography #
    ################

    def encrypt(self, data, recipients, **kwargs):
        """Encrypt passed data with the given keys.

        Parameters
        ----------

        data : bytes
            The data to sign.
        recipients : list of str
            A list of full GPG fingerprints (without a ``"0x"`` prefix) to encrypt the message to.
        always_trust : bool, optional
            If ``True``, always trust all keys, if ``False`` is passed, do not. The default value
            is what is passed to the constructor as ``default_trust``.
        """
        raise NotImplementedError

    def sign_encrypt(self, data, recipients, signer, **kwargs):
        """Sign and encrypt passed data with the given keys.

        Parameters
        ----------

        data : bytes
            The data to sign.
        recipients : list of str
            A list of full GPG fingerprints (without a ``"0x"`` prefix) to encrypt the message to.
        signer : str
            Key id to sign the message with.
        always_trust : bool, optional
            If ``True``, always trust all keys, if ``False`` is passed, do not. The default value
            is what is passed to the constructor as ``default_trust``.
        """
        raise NotImplementedError

    def verify(self, data, signature):
        """Verify the data with the given (detached) signature.

        Parameters
        ----------

        data : bytes
            The data that was signed with the given signature.
        signature : bytes
            The detached signature.

        Returns
        -------

        fingerprint : str
            The fingerprint of the signature that was used to sign the data.

        Raises
        ------

        GpgBadSignature
            If the signature is invalid.
        """
        raise NotImplementedError

    def decrypt(self, data):
        """Decrypt the passed data.

        Parameters
        ----------

        data : bytes
            The encrypted data.

        Returns
        -------

        bytes
            The decrypted data.
        """
        raise NotImplementedError

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

    def __init__(self, backend, fingerprint):
        self.backend = backend
        self.fingerprint = fingerprint.upper()
        self.refresh()

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
