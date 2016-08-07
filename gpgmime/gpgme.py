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

import gpgme
import six

from .base import GpgBackendBase


class GpgMeBackend(GpgBackendBase):
    """A backend using `pygpgme <https://pypi.python.org/pypi/pygpgme/>`_.

    This backend requires that you install ``pygpgme``::

        pip install pygpgme

    .. seealso::

       `Unofficial (and incomplete) documentation <pygpgme.readthedocs.io/en/latest/api.html>`_
       for pygpgme.

    Parameters
    ----------

    context : gpgme.Context, optional
        A default context to use. If not passed, a new context with no parameters will be used.
    """

    def __init__(self, context=None, **kwargs):
        self._context = context
        super(GpgMeBackend, self).__init__(**kwargs)

    def get_context(self, **kwargs):
        """get context"""
        if kwargs.get('context'):
            return kwargs['context']

        if self._context is None:
            context = gpgme.Context()
        else:
            context = self._context

        context.armor = True
        # TODO: handle options (especially home and path)

        return context

    def _encrypt_flags(self, always_trust=True, **kwargs):
        flags = 0
        if always_trust is True:
            flags |= gpgme.ENCRYPT_ALWAYS_TRUST
        return flags

    def _encrypt(self, data, recipients, context, always_trust):
        recipients = [context.get_key(k) if isinstance(k, six.string_types) else k
                      for k in recipients]

        output_bytes = six.BytesIO()
        flags = self._encrypt_flags(always_trust=always_trust)
        if context.signers:
            context.encrypt_sign(recipients, flags, six.BytesIO(data), output_bytes)
        else:
            context.encrypt(recipients, flags, six.BytesIO(data), output_bytes)

        output_bytes.seek(0)
        return output_bytes.getvalue()

    def sign(self, data, signers, **kwargs):
        context = self.get_context(**kwargs)
        signers = [(context.get_key(k) if isinstance(k, six.string_types) else k) for k in signers]
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
        signers = [(context.get_key(k) if isinstance(k, six.string_types) else k) for k in signers]
        context.signers = signers

        return self._encrypt(data, recipients, context, always_trust)
