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
import shutil
import tempfile

from django.test import TestCase

from gpgmime.base import VALIDITY_FULL
from gpgmime.base import VALIDITY_MARGINAL
from gpgmime.base import VALIDITY_NEVER
from gpgmime.base import VALIDITY_ULTIMATE
from gpgmime.base import VALIDITY_UNKNOWN
from gpgmime.gpgme import GpgMeBackend

basedir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
testdatadir = os.path.join(basedir, 'testdata')

# load data into memory
user1_fp = 'CC9F343794DBB20E13DE097EE53338B91AA9A0AC'
with open(os.path.join(testdatadir, '%s.priv' % user1_fp), 'rb') as stream:
    user1_priv = stream.read()
with open(os.path.join(testdatadir, '%s.pub' % user1_fp), 'rb') as stream:
    user1_pub = stream.read()

user2_fp = '28B9BC9D1F71C23D8CE2ABD04657F2D6FF6A0F95'
with open(os.path.join(testdatadir, '%s.priv' % user2_fp), 'rb') as stream:
    user2_priv = stream.read()
with open(os.path.join(testdatadir, '%s.pub' % user2_fp), 'rb') as stream:
    user2_pub = stream.read()

user3_fp = '086E59B1917B90B0F8BCDC5C4E7109E63E81D74C'
with open(os.path.join(testdatadir, '%s.priv' % user3_fp), 'rb') as stream:
    user3_priv = stream.read()
with open(os.path.join(testdatadir, '%s.pub' % user3_fp), 'rb') as stream:
    user3_pub = stream.read()

user4_fp = '076E1C74BAD6DA878905169289BCCEEA8D95B1E0'
with open(os.path.join(testdatadir, '%s.priv' % user4_fp), 'rb') as stream:
    user4_priv = stream.read()
with open(os.path.join(testdatadir, '%s.pub' % user4_fp), 'rb') as stream:
    user4_pub = stream.read()


class TestCaseMixin(object):
    def test_import_key(self):
        self.assertEqual(self.backend.import_key(user1_pub), user1_fp)
        self.assertEqual(self.backend.import_key(user1_pub), user1_fp)

        self.assertEqual(self.backend.import_key(user2_pub), user2_fp)
        self.assertEqual(self.backend.import_key(user2_pub), user2_fp)

    def test_import_private_key(self):
        self.assertEqual(self.backend.import_private_key(user1_priv), user1_fp)
        self.assertEqual(self.backend.import_private_key(user1_priv), user1_fp)

        self.assertEqual(self.backend.import_private_key(user2_priv), user2_fp)
        self.assertEqual(self.backend.import_private_key(user2_priv), user2_fp)

    def test_expires(self):
        self.assertEqual(self.backend.import_key(user1_pub), user1_fp)
        self.assertIsNone(self.backend.expires(user1_fp))

        # TODO: Test a key that actually does expire

    def test_sign(self):
        data = b'testdata'

        self.assertEqual(self.backend.import_key(user3_pub), user3_fp)
        self.assertEqual(self.backend.import_private_key(user3_priv), user3_fp)

        signature = self.backend.sign(data, [user3_fp])
        self.assertEqual(self.backend.verify(data, signature), [user3_fp])

    def test_encrypt(self):
        data = b'testdata'
        self.assertEqual(self.backend.import_key(user1_pub), user1_fp)
        self.assertEqual(self.backend.import_private_key(user1_priv), user1_fp)

        encrypted = self.backend.encrypt(data, [user1_fp], always_trust=True)
        self.assertEqual(self.backend.decrypt(encrypted), data)

    def test_sign_encrypt(self):
        data = b'testdata'
        self.assertEqual(self.backend.import_key(user3_pub), user3_fp)
        self.assertEqual(self.backend.import_private_key(user1_priv), user1_fp)

        encrypted = self.backend.sign_encrypt(data, recipients=[user3_fp], signers=[user1_fp],
                                              always_trust=True)

        self.assertEqual(self.backend.import_private_key(user3_priv), user3_fp)
        self.assertEqual(self.backend.decrypt_verify(encrypted), (data, [user1_fp]))

    def test_trust(self):
        self.assertEqual(self.backend.import_key(user4_pub), user4_fp)
        self.assertEqual(self.backend.get_trust(user4_fp), VALIDITY_UNKNOWN)

        # NOTE: We cannot set VALIDITY_UNKNOWN again
        for trust in [VALIDITY_FULL, VALIDITY_MARGINAL, VALIDITY_NEVER]:
            self.backend.set_trust(user4_fp, trust)
            self.assertEqual(self.backend.get_trust(user4_fp), trust)

    def setUp(self):
        self.home = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.home)


class GpgMeTestCase(TestCaseMixin, TestCase):
    def setUp(self):
        super(GpgMeTestCase, self).setUp()
        self.backend = GpgMeBackend(home=self.home)
