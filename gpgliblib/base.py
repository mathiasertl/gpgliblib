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
from email.encoders import encode_noop
from email.mime.application import MIMEApplication
import shutil
import tempfile

import six

from six.moves.email_mime_base import MIMEBase
from six.moves.email_mime_multipart import MIMEMultipart
from six.moves.email_mime_text import MIMEText
from six.moves.urllib.parse import urlencode
from six.moves.urllib.request import urlopen

# Constants
#: A key has unknown trust.
VALIDITY_UNKNOWN = 0

#: A key marked as "never trusted".
VALIDITY_NEVER = 1

#: A key is marked with "marginal trust".
VALIDITY_MARGINAL = 2

#: A key is marked with "full trust".
VALIDITY_FULL = 3

#: A key is marked with "ultimate trust".
VALIDITY_ULTIMATE = 4


class GpgMimeError(Exception):
    """Base class for all exceptions."""

    pass


class GpgKeyNotFoundError(GpgMimeError):
    """Thrown when a key was not found."""

    pass


class GpgUntrustedKeyError(GpgMimeError):
    """Thrown when a given key was not trusted."""

    pass


class GpgBadSignature(GpgMimeError):
    """Thrown when a signature is invalid."""

    #: Errors returned by the library in use.
    errors = None

    def __init__(self, *args, **kwargs):
        self.errors = kwargs.pop('errors', [])
        super(GpgBadSignature, self).__init__(*args, **kwargs)


class GpgBackendBase(object):
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

    def get_settings(self):
        return {
            'home': self._home,
            'path': self._path,
            'default_trust': self._default_trust,
        }

    @contextmanager
    def settings(self, **kwargs):
        """Context manager yielding a temporary backend with different settings.

        The context manager passes all ``kwargs`` to the constructor of its own class and should
        thus take the same parameters. For example, to temporary set the default trust to
        ``True``, do::

            with backend.settings(default_trust=True) as temp_backend:
                # temp_backend will have a different default trust
        """
        my_settings = self.get_settings()
        my_settings.update(kwargs)
        yield self.__class__(**my_settings)

    @contextmanager
    def temp_keyring(self, **kwargs):
        """Context manager with a temporary home directory.

        This context manager is a shortcut for :py:func:`~gpgliblib.base.GpgBackendBase.settings`
        that uses a temporary keyring directory. All other ``kwargs`` are passed to
        :py:func:`~gpgliblib.base.GpgBackendBase.settings`. It is equivalent to::

            with tempfile.TemporaryDirectory() as home, backend.settings(home=home) as backend:
                yield backend
        """
        with self._tempdir() as home, self.settings(home=home, **kwargs) as backend:
            yield backend

    ##################
    # Key management #
    ##################

    def fetch_key(self, search, keyserver='http://pool.sks-keyservers.net:11371', **kwargs):
        """Fetch a key from the given keyserver.

        Parameters
        ----------
        search : str
            The search string. If this is a fingerprint, it must start with ``"0x"``.
        keyserver : str, optional
            URL of the keyserver, the default is ``"http://pool.sks-keyservers.net:11371"``.
        **kwargs
            All kwargs are passed to :py:func:`urllib.request.urlopen`. The ``timeout`` parameter
            defaults to three seconds this function (``urlopen`` is a blocking function and thus
            makes long timeouts unsuitable for e.g. a webserver setup).

        Returns
        -------

        key : bytes
            The requested key as bytes.

        Raises
        ------

        urllib.error.URLError
            If the keyserver cannot be reached.
        urllib.error.HTTPError
            If the keyserver does not respond with http 200, e.g. if the key is not found.
        """
        kwargs.setdefault('timeout', 3)
        params = {
            'search': search,
            'options': 'mr',
            'op': 'get',
        }
        url = '%s/pks/lookup?%s' % (keyserver, urlencode(params))
        response = urlopen(url, **kwargs)
        return response.read().strip()

    def import_key(self, data):
        """Import a public key.

        Parameters
        ----------

        data : str or bytes
            The public key data. Can be in binary or in ASCII armored format.

        Returns
        -------

        list of GpgKey
            A list of GpgKey instances that were imported.
        """
        raise NotImplementedError

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

    ########################
    # GPG/MIME: Encrypting #
    ########################

    def get_control_message(self):
        """Get a control message for encrypted messages, as descripted in RFC 3156, chapter 4."""

        msg = MIMEApplication(_data='Version: 1\n', _subtype='pgp-encrypted', _encoder=encode_noop)
        msg.add_header('Content-Description', 'PGP/MIME version identification')
        return msg

    def get_encrypted_message(self, message):
        """Get the encrypted message from the passed payload message.

        Parameters
        ----------

        message : MIMEBase
            The message to encrypt (e.g. as created by :py:func:`get_octed_stream`.
        """

        control = self.get_control_message()
        msg = MIMEMultipart(_subtype='encrypted', _subparts=[control, message])
        msg.set_param('protocol', 'application/pgp-encrypted')
        return msg

    def get_octet_stream(self, message, recipients, signer=None, **kwargs):
        """Get encrypted message from the passt message (helper function).

        This function returns the encrypted payload message. The parameters are the same as in
        :py:func:`encrypt_message`.
        """
        if signer is None:
            encrypted = self.encrypt(message.as_bytes(), recipients, **kwargs)
        else:
            encrypted = self.sign_encrypt(message.as_bytes(), recipients, signer, **kwargs)

        msg = MIMEApplication(_data=encrypted, _subtype='octet-stream', name='encrypted.asc',
                              _encoder=encode_noop)
        msg.add_header('Content-Description', 'OpenPGP encrypted message')
        msg.add_header('Content-Disposition', 'inline; filename="encrypted.asc"')
        return msg

    def encrypt_message(self, message, recipients, signer=None, **kwargs):
        """Get an encrypted MIME message from the passed message or str.

        This function returns a fully encrypted MIME message including a control message and the
        encrypted payload message.

        Parameters
        ----------

        message : MIMEBase or str
            Message to encrypt.
        recipients : list of key ids
            List of key ids to encrypt to.
        signer : str
            Key id to sign the message with.
        **kwargs
            Any additional parameters to the GPG backend.
        """
        if isinstance(message, six.string_types):
            message = MIMEText(message)

        msg = self.get_octet_stream(message, recipients, signer, **kwargs)
        return self.get_encrypted_message(msg)

    #####################
    # GPG/MIME: Signing #
    #####################

    def get_mime_signature(self, signature):
        """Get a signature MIME message from the passed signature.

        Parameters
        ----------

        signature : bytes
            A gpg signature.
        """
        msg = MIMEBase(_maintype='application', _subtype='pgp-signature', name='signature.asc')
        msg.set_payload(signature)
        msg.add_header('Content-Description', 'OpenPGP digital signature')
        msg.add_header('Content-Disposition', 'attachment; filename="signature.asc"')
        del msg['MIME-Version']
        del msg['Content-Transfer-Encoding']
        return msg

    def get_signed_message(self, message, signature):
        """Get a signed MIME message from the passed message and signature messages.

        Parameters
        ----------

        message : MIMEBase
            MIME message that is signed by the signature.
        signature : MIMEBase
            MIME message containing the signature.
        """

        msg = MIMEMultipart(_subtype='signed', _subparts=[message, signature])
        msg.set_param('protocol', 'application/pgp-signature')
        msg.set_param('micalg', 'pgp-sha256')  # TODO: Just the current default
        return msg

    def sign_message(self, message, signer, add_cr=True):
        """
        message : MIMEBase or str
            Message to encrypt.
        recipients : list of key ids
            List of key ids to encrypt to.
        signer : str
            Key id to sign the message with.
        add_cr : bool, optional
            Wether or not to replace newlines (``\\n``) with carriage-return/newlines (``\\r\\n``).
            E-Mail messages generally use ``\\r\\n``, so the default is True.
        """
        if isinstance(message, six.string_types):
            message = MIMEText(message)
            del message['MIME-Version']

        data = message.as_bytes()
        if add_cr is True:
            data = data.replace(b'\n', b'\r\n')

        # get the gpg signature
        signature = self.sign(data, signer)
        signature_msg = self.get_mime_signature(signature)
        return self.get_signed_message(message, signature_msg)

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

    ##########
    # Helper #
    ##########

    if six.PY3:
        _tempdir = tempfile.TemporaryDirectory
    else:
        # python2-compatible version
        @contextmanager
        def _tempdir(self):
            path = tempfile.mkdtemp()

            try:
                yield path
            finally:
                shutil.rmtree(path)


class GpgKey(object):
    """Base class for all GPG Keys.

    Instances of this class are usually created by the backend in use and not by a user of this
    library.

    Parameters
    ----------

    backend : :py:class:`~gpgliblib.base.GpgBackendBase`
        Any backend instance.
    fingerprint : str
        The fingerprint of the key.
    """

    def __init__(self, backend, fingerprint):
        self.backend = backend
        self.fingerprint = fingerprint
        self.refresh()

    def refresh(self):
        """Reset any in-memory data used by this key."""
        pass

    @property
    def name(self):
        """Name for this key."""
        raise NotImplementedError

    @property
    def comment(self):
        """Comment for this key."""
        raise NotImplementedError

    @property
    def email(self):
        """Email for this key."""
        raise NotImplementedError

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
    def expired(self):
        """Returns True if the key is expired right now."""

        return self.expires < datetime.utcnow()

    @property
    def revoked(self):
        """Boolean indicating if the key is revoked."""

        raise NotImplementedError

    @property
    def fp(self):
        """Shortcut for ``fingerprint``."""

        return self.fingerprint

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
