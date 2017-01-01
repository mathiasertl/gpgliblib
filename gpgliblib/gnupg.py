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

    def sign(self, data, signer):
        result = self.gpg.sign(data, keyid=signer, detach=True)
        if not result.data:  # signing does not provide status or ok :-(
            raise GpgKeyNotFoundError()
        return result.data

    def encrypt(self, data, recipients, **kwargs):
        always_trust = kwargs.get('always_trust', self._default_trust)

        result = self.gpg.encrypt(data, recipients, always_trust=always_trust)
        if result.ok is False:
            if result.status == 'invalid recipient':
                raise GpgKeyNotFoundError
            elif result.status == '':
                raise GpgUntrustedKeyError
            else:
                raise GpgMimeError("Unknown error: %s" % result.status)
        return result.data

    def sign_encrypt(self, data, recipients, signer, **kwargs):
        always_trust = kwargs.get('always_trust', self._default_trust)

        result = self.gpg.encrypt(data, recipients, sign=signer, always_trust=always_trust)
        if result.ok is False:
            if result.status in ['invalid recipient', '']:
                raise GpgKeyNotFoundError
        return result.data

    def verify(self, data, signature, **kwargs):
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

    def decrypt(self, data, **kwargs):
        always_trust = kwargs.pop('always_trust', self._default_trust)
        result = self.gpg.decrypt(data, always_trust=always_trust)
        return result.data

    def decrypt_verify(self, data, **kwargs):
        always_trust = kwargs.pop('always_trust', self._default_trust)
        result = self.gpg.decrypt(data, always_trust=always_trust)
        return result.data, result.fingerprint

    def import_key(self, data, **kwargs):
        result = self.gpg.import_keys(data)
        return result.fingerprints

    def import_private_key(self, data, **kwargs):
        result = self.gpg.import_keys(data)
        return result.fingerprints

    def set_trust(self, fingerprint, trust, **kwargs):
        result = self.gpg.result_map['verify'](self.gpg)  # any result object

        if trust == VALIDITY_NEVER:
            trust = '3'
        elif trust == VALIDITY_MARGINAL:
            trust = '4'
        elif trust == VALIDITY_FULL:
            trust = '5'
        elif trust == VALIDITY_ULTIMATE:
            trust = '6'
        else:
            raise ValueError("Unknown trust passed.")

        line = '%s:%s\n' % (fingerprint, trust)
        line = line.encode('utf-8')

        self.gpg._handle_io(['--import-ownertrust'], six.BytesIO(line), result, binary=True)

    def get_trust(self, fingerprint, **kwargs):
        trust = self.gpg.list_keys(keys=fingerprint)[0]['ownertrust']

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

    def expires(self, fingerprint, **kwargs):
        key = self.gpg.list_keys(keys=fingerprint)[0]

        timestamp = key['expires']
        return datetime.fromtimestamp(int(timestamp)) if timestamp else None
