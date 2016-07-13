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


class GpgBackendBase(object):
    def __init__(self, home=None, path=None):
        self._home = home
        self._path = path

    def fetch_key(self, keyserver='http://pool.sks-keyservers.net:11371'):
        pass

    def sign(self, data, recipients, signers, **kwargs):
        raise NotImplementedError

    def sign_encrypt(self, data, recipients, signers, **kwargs):
        raise NotImplementedError

    def encrypt(self, data, recipients, signers, **kwargs):
        raise NotImplementedError
