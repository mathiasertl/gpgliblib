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

import os
import tempfile

from datetime import datetime

import gnupg
import six

from .base import GpgBackendBase
from .base import GpgKeyNotFoundError
from .base import GpgMimeError
from .base import GpgUntrustedKeyError
from .base import VALIDITY_UNKNOWN
from .base import VALIDITY_NEVER
from .base import VALIDITY_MARGINAL
from .base import VALIDITY_FULL
from .base import VALIDITY_ULTIMATE


class GnuPGBackend(GpgBackendBase):
    """A backend using `python-gnupg <https://pythonhosted.org/python-gnupg/>`_.

    All ``kwargs`` for the constructor are passed to :py:class:`~gpgmime.base.GpgBackendBase`.

    This backend requires that you install ``python-gnupg``::

        pip install python-gnupg

    Paraemters
    ----------
    verbose : bool, optional
    use_agent : bool, False
    options : list of str
    """

    def __init__(self, verbose=False, use_agent=False, options=None, **kwargs):
        self._verbose = verbose
        self._use_agent = use_agent
        self._options = options
        super(GnuPGBackend, self).__init__(**kwargs)


    def get_gpg(self, **kwargs):
        if kwargs.get('gpg'):
            return kwargs['gpg']

        # Set home and path for this context, if requested
        path = kwargs.get('path', self._path)
        home = kwargs.get('home', self._home)

        gnupg_kwargs = {}
        if home:
            gnupg_kwargs['gnupghome'] = home
        if path:
            gnupg_kwargs['gpgbinary'] = path
        if self._verbose or kwargs.get('verbose'):
            gnupg_kwargs['verbose'] = True
        if self._use_agent or kwargs.get('use_agent'):
            gnupg_kwargs['use_agent'] = True
        if self._options or kwargs.get('options'):
            gnupg_kwargs['options'] = self._options

        return gnupg.GPG(**gnupg_kwargs)

    def sign(self, data, signers, **kwargs):
        gpg = self.get_gpg(**kwargs)

        result = gpg.sign(data, keyid=signers[0], detach=True)
        if not result.data:  # signing does not provide status or ok :-(
            raise GpgKeyNotFoundError()
        return result.data

    def encrypt(self, data, recipients, **kwargs):
        always_trust = kwargs.pop('always_trust', self._always_trust)
        gpg = self.get_gpg(**kwargs)
        result = gpg.encrypt(data, recipients, always_trust=always_trust)
        if result.ok is False:
            if result.status == 'invalid recipient':
                raise GpgKeyNotFoundError
            elif result.status == '':
                raise GpgUntrustedKeyError
            else:
                raise GpgMimeError("Unknown error: %s" % result.status)
        return result.data

    def sign_encrypt(self, data, recipients, signers, **kwargs):
        always_trust = kwargs.pop('always_trust', self._always_trust)
        gpg = self.get_gpg(**kwargs)
        result = gpg.encrypt(data, recipients, sign=signers[0], always_trust=always_trust)
        if result.ok is False:
            if result.status in ['invalid recipient', '']:
                raise GpgKeyNotFoundError
        return result.data

    def verify(self, data, signature, **kwargs):
        gpg = self.get_gpg(**kwargs)
        fd, path = tempfile.mkstemp()

        try:
            # write data to temporary file
            stream = os.fdopen(fd, mode='wb')
            stream.write(signature)
            stream.flush()

            verified = gpg.verify_data(path, data)
        finally:
            os.remove(path)

        if verified:
            return [verified.fingerprint]

    def decrypt(self, data, **kwargs):
        always_trust = kwargs.pop('always_trust', self._always_trust)
        gpg = self.get_gpg(**kwargs)
        result = gpg.decrypt(data, always_trust=always_trust)
        return result.data

    def decrypt_verify(self, data, **kwargs):
        always_trust = kwargs.pop('always_trust', self._always_trust)
        gpg = self.get_gpg(**kwargs)
        result = gpg.decrypt(data, always_trust=always_trust)
        return result.data, [result.fingerprint]

    def import_key(self, data, **kwargs):
        gpg = self.get_gpg(**kwargs)
        result = gpg.import_keys(data)
        if len(result.fingerprints) >= 1:
            return result.fingerprints[0]

    def import_private_key(self, data, **kwargs):
        gpg = self.get_gpg(**kwargs)
        result = gpg.import_keys(data)
        if len(result.fingerprints) >= 1:
            return result.fingerprints[0]

    def set_trust(self, fingerprint, trust, **kwargs):
        gpg = self.get_gpg(**kwargs)
        result = gpg.result_map['verify'](gpg)  # any result object

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

        gpg._handle_io(['--import-ownertrust'], six.BytesIO(line), result, binary=True)

    def get_trust(self, fingerprint, **kwargs):
        gpg = self.get_gpg(**kwargs)
        key = gpg.list_keys(keys=fingerprint)[0]

        #TODO
        trust = key['ownertrust']

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
            print('trust: %s, %s' % (key['trust'], key['ownertrust']))
            return VALIDITY_UNKNOWN

    def expires(self, fingerprint, **kwargs):
        gpg = self.get_gpg(**kwargs)
        key = gpg.list_keys(keys=fingerprint)[0]

        timestamp = key['expires']
        return datetime.fromtimestamp(int(timestamp)) if timestamp else None
