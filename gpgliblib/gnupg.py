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

import os
import tempfile
from datetime import datetime
from threading import local

import gnupg
import six

from .base import VALIDITY_FULL
from .base import VALIDITY_MARGINAL
from .base import VALIDITY_NEVER
from .base import VALIDITY_ULTIMATE
from .base import VALIDITY_UNKNOWN
from .base import GpgBackendBase
from .base import GpgBadSignature
from .base import GpgKey
from .base import GpgKeyNotFoundError
from .base import GpgMimeError
from .base import GpgUntrustedKeyError


class GnuPGBackend(GpgBackendBase):
    """A backend using `python-gnupg <https://pythonhosted.org/python-gnupg/>`_.

    All ``kwargs`` for the constructor are passed to :py:class:`~gpgmime.base.GpgBackendBase`.

    This backend requires that you install ``python-gnupg``::

        pip install python-gnupg

    Paraemters
    ----------
    verbose : bool, optional
        Print additional information to the command line.
    use_agent : bool, optional
        If ``True``, gpg will be invoked with ``--use-agent``.
    options : list of str
        A list of strings representing additional keyword arguments.
    """

    def __init__(self, verbose=False, use_agent=False, options=None, **kwargs):
        self._verbose = verbose
        self._use_agent = use_agent
        self._options = options
        self._local = local()
        super(GnuPGBackend, self).__init__(**kwargs)

    @property
    def gpg(self):
        if hasattr(self._local, 'gpg') is False:
            kwargs = {}
            if self._home:
                kwargs['gnupghome'] = self._home
            if self._path:
                kwargs['gpgbinary'] = self._path
            if self._verbose:
                kwargs['verbose'] = True
            if self._use_agent:
                kwargs['use_agent'] = True
            if self._options:
                kwargs['options'] = self._options

            self._local.gpg = gnupg.GPG(**kwargs)

        return self._local.gpg

    def get_key(self, fingerprint):
        return GnuPGKey(self, fingerprint)

    def _get_fp(self, obj):
        if isinstance(obj, GpgKey):
            return obj.fingerprint
        return obj

    def sign(self, data, signer):
        fp = self._get_fp(signer)
        result = self.gpg.sign(data, keyid=fp, detach=True)
        if not result.data:  # signing does not provide status or ok :-(
            raise GpgKeyNotFoundError()
        return result.data

    def encrypt(self, data, recipients, **kwargs):
        always_trust = kwargs.get('always_trust', self._default_trust)
        recipients = [self._get_fp(r) for r in recipients]

        result = self.gpg.encrypt(data, recipients, always_trust=always_trust)
        if result.ok is False:
            if result.status == 'invalid recipient':
                raise GpgKeyNotFoundError
            elif result.status == '':
                raise GpgUntrustedKeyError('Key not trusted.')
            else:
                raise GpgMimeError("Unknown error: %s" % result.status)
        return result.data

    def sign_encrypt(self, data, recipients, signer, **kwargs):
        always_trust = kwargs.get('always_trust', self._default_trust)
        recipients = [self._get_fp(r) for r in recipients]
        signer = self._get_fp(signer)

        result = self.gpg.encrypt(data, recipients, sign=signer, always_trust=always_trust)
        if result.ok is False:
            if result.status in ['invalid recipient', '']:
                raise GpgKeyNotFoundError
        return result.data

    def verify(self, data, signature):
        fd, path = tempfile.mkstemp()

        try:
            # write data to temporary file (cannot use an in-memory stream :-()
            stream = os.fdopen(fd, mode='wb')
            stream.write(signature)
            stream.flush()

            verified = self.gpg.verify_data(path, data)
        finally:
            os.remove(path)

        if verified:
            return verified.fingerprint
        raise GpgBadSignature("Bad Signature")

    def decrypt(self, data):
        result = self.gpg.decrypt(data)
        return result.data

    def decrypt_verify(self, data):
        result = self.gpg.decrypt(data)
        return result.data, result.fingerprint

    def import_key(self, data, **kwargs):
        result = self.gpg.import_keys(data)
        return [GnuPGKey(self, fp) for fp in result.fingerprints]

    def import_private_key(self, data, **kwargs):
        result = self.gpg.import_keys(data)
        return [GnuPGKey(self, fp) for fp in result.fingerprints]


class GnuPGKey(GpgKey):
    @property
    def trust(self):
        trust = self.backend.gpg.list_keys(keys=self.fingerprint)[0]['ownertrust']

        if trust == '-':
            return VALIDITY_UNKNOWN
        elif trust == 'n':
            return VALIDITY_NEVER
        elif trust == 'm':
            return VALIDITY_MARGINAL
        elif trust == 'f':
            return VALIDITY_FULL
        elif trust == 'u':
            return VALIDITY_ULTIMATE
        else:
            return VALIDITY_UNKNOWN

    @trust.setter
    def trust(self, value):
        result = self.backend.gpg.result_map['verify'](self.backend.gpg)  # any result object

        if value == VALIDITY_NEVER:
            value = '3'
        elif value == VALIDITY_MARGINAL:
            value = '4'
        elif value == VALIDITY_FULL:
            value = '5'
        elif value == VALIDITY_ULTIMATE:
            value = '6'
        else:
            raise ValueError("Unknown trust passed.")

        line = '%s:%s\n' % (self.fingerprint, value)
        line = line.encode('utf-8')

        self.backend.gpg._handle_io(['--import-ownertrust'], six.BytesIO(line), result,
                                    binary=True)

    @property
    def expires(self):
        key = self.backend.gpg.list_keys(keys=self.fingerprint)[0]

        timestamp = key['expires']
        return datetime.fromtimestamp(int(timestamp)) if timestamp else None
