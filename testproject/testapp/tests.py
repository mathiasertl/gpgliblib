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

from __future__ import unicode_literals, absolute_import

import doctest
import os
import shutil
import tempfile

try:
    from unittest import mock
except ImportError:
    import mock  # python2

from datetime import datetime

import six

from django.test import TestCase

from gpgliblib.base import MODE_ARMOR
from gpgliblib.base import MODE_BINARY
from gpgliblib.base import VALIDITY_FULL
from gpgliblib.base import VALIDITY_MARGINAL
from gpgliblib.base import VALIDITY_NEVER
from gpgliblib.base import VALIDITY_ULTIMATE
from gpgliblib.base import VALIDITY_UNKNOWN
from gpgliblib.base import GpgKeyNotFoundError
from gpgliblib.base import GpgUntrustedKeyError
from gpgliblib.base import GpgSecretKeyPresent
from gpgliblib.gpgme import GpgMeBackend
from gpgliblib.gnupg import GnuPGBackend
from gpgliblib.pyme import PymeBackend

basedir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
testdatadir = os.path.join(basedir, 'testdata')

# load data into memory
user1_fp = 'CC9F343794DBB20E13DE097EE53338B91AA9A0AC'
with open(os.path.join(testdatadir, '%s.priv' % user1_fp), 'r') as stream:
    user1_priv = stream.read()
with open(os.path.join(testdatadir, '%s.pub' % user1_fp), 'r') as stream:
    user1_pub = stream.read()
with open(os.path.join(testdatadir, '%s.bin.priv' % user1_fp), 'rb') as stream:
    user1_bin_priv = stream.read()
with open(os.path.join(testdatadir, '%s.bin.pub' % user1_fp), 'rb') as stream:
    user1_bin_pub = stream.read()

user2_fp = '28B9BC9D1F71C23D8CE2ABD04657F2D6FF6A0F95'
with open(os.path.join(testdatadir, '%s.priv' % user2_fp), 'r') as stream:
    user2_priv = stream.read()
with open(os.path.join(testdatadir, '%s.pub' % user2_fp), 'r') as stream:
    user2_pub = stream.read()

user3_fp = '086E59B1917B90B0F8BCDC5C4E7109E63E81D74C'
with open(os.path.join(testdatadir, '%s.priv' % user3_fp), 'r') as stream:
    user3_priv = stream.read()
with open(os.path.join(testdatadir, '%s.pub' % user3_fp), 'r') as stream:
    user3_pub = stream.read()

user4_fp = '076E1C74BAD6DA878905169289BCCEEA8D95B1E0'
with open(os.path.join(testdatadir, '%s.priv' % user4_fp), 'r') as stream:
    user4_priv = stream.read()
with open(os.path.join(testdatadir, '%s.pub' % user4_fp), 'r') as stream:
    user4_pub = stream.read()

expires_fp = '4C443E9B262ECB73835730DAA9711516C8D705FC'
with open(os.path.join(testdatadir, '%s.priv' % expires_fp), 'r') as stream:
    expires_priv = stream.read()
with open(os.path.join(testdatadir, '%s.pub' % expires_fp), 'r') as stream:
    expires_pub = stream.read()

expired_fp = '122E23C2717B7BCE1AB3E11B6FBC070283C802AB'
with open(os.path.join(testdatadir, '%s.priv' % expired_fp), 'r') as stream:
    expired_priv = stream.read()
with open(os.path.join(testdatadir, '%s.pub' % expired_fp), 'r') as stream:
    expired_pub = stream.read()

revoked_fp = 'BE57A1261FC904FF24FBD92F8D40928D3C5FF049'
with open(os.path.join(testdatadir, '%s.priv' % revoked_fp), 'r') as stream:
    revoked_priv = stream.read()
with open(os.path.join(testdatadir, '%s.pub' % revoked_fp), 'r') as stream:
    revoked_pub = stream.read()

multiple_fp = 'FF40CF5C4D6DDAA16D52B94288989BE6795A5C96'
with open(os.path.join(testdatadir, '%s.priv' % multiple_fp), 'r') as stream:
    multiple_priv = stream.read()
with open(os.path.join(testdatadir, '%s.pub' % multiple_fp), 'r') as stream:
    multiple_pub = stream.read()

known_public_keys = {
    user1_fp: user1_pub,
    user2_fp: user2_pub,
    user3_fp: user3_pub,
    user4_fp: user4_pub,
    expires_fp: expires_pub,
    expired_fp: expired_pub,
    revoked_fp: revoked_pub,
    multiple_fp: multiple_pub,
}


def load_tests(loader, tests, ignore):
    if six.PY2:
        # do not run doctests from sphinx in python2
        return tests

    def lookup_gpg_key(fp):
        return known_public_keys[fp[2:]]

    # Called once for each file
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.globs['gnupg_home'] = self.home
        self.globs['user1_priv'] = user1_priv
        self.patcher = mock.patch.object(GpgMeBackend, 'fetch_key',
                                         side_effect=lookup_gpg_key,
                                         return_value=user1_pub)
        self.patcher.start()

    def tearDown(self):
        shutil.rmtree(self.home)
        self.patcher.stop()

    docpath = os.path.join('..', '..', 'doc')
    docfiles = ['usage.rst']

    for docfile in docfiles:
        docfile = os.path.join(docpath, docfile)
        tests.addTest(doctest.DocFileSuite(docfile, setUp=setUp, tearDown=tearDown))

    return tests


class GpgTestCase(TestCase):
    if six.PY2:
        assertCountEqual = TestCase.assertItemsEqual

    def setUp(self):
        super(GpgTestCase, self).setUp()
        self.home = tempfile.mkdtemp()
        self.backend = self.backend_class(home=self.home)

    def tearDown(self):
        super(GpgTestCase, self).tearDown()
        shutil.rmtree(self.home)

    def assertKeys(self, result, expected):
        self.assertCountEqual([k.fp for k in result], expected)


class GpgKeyTestCase(GpgTestCase):
    """Subclass which already loads a public and a private key."""

    def setUp(self):
        super(GpgKeyTestCase, self).setUp()
        self.key1 = self.backend.import_key(user1_pub)[0]
        self.key2 = self.backend.import_key(user2_priv)[0]


class BasicTestsMixin(object):
    def test_import_key(self):
        self.assertKeys(self.backend.import_key(user1_pub), [user1_fp])
        self.assertKeys(self.backend.import_key(user1_pub), [user1_fp])

        self.assertKeys(self.backend.import_key(user2_pub), [user2_fp])
        self.assertKeys(self.backend.import_key(user2_pub), [user2_fp])

    def test_import_bin_key(self):
        self.assertKeys(self.backend.import_key(user1_bin_pub), [user1_fp])
        self.assertKeys(self.backend.import_key(user1_bin_pub), [user1_fp])

    def test_import_malformed_key(self):
        self.assertEqual(self.backend.import_key(b'foobar'), [])

    def test_import_private_key(self):
        self.assertKeys(self.backend.import_private_key(user1_priv), [user1_fp])
        self.assertKeys(self.backend.import_private_key(user1_priv), [user1_fp])

        self.assertKeys(self.backend.import_private_key(user2_priv), [user2_fp])
        self.assertKeys(self.backend.import_private_key(user2_priv), [user2_fp])

    def test_import_private_bin_key(self):
        self.assertKeys(self.backend.import_private_key(user1_bin_pub), [user1_fp])
        self.assertKeys(self.backend.import_private_key(user1_bin_pub), [user1_fp])

    def test_import_malformed_private_key(self):
        self.assertEqual(self.backend.import_private_key(b'foobar'), [])

    def test_multiple_imports(self):
        self.assertKeys(self.backend.import_key(user1_pub + user2_pub), [user1_fp, user2_fp])
        self.assertKeys(self.backend.import_key(user1_pub + user2_pub), [user1_fp, user2_fp])

        self.assertKeys(self.backend.import_private_key(user3_pub + user4_pub),
                        [user3_fp, user4_fp])
        self.assertKeys(self.backend.import_private_key(user3_pub + user4_pub),
                        [user3_fp, user4_fp])

    def test_list_keys(self):
        self.assertEqual(self.backend.list_keys(), [])
        self.assertKeys(self.backend.import_key(user1_pub), [user1_fp])
        self.assertEqual(self.backend.list_keys(), [self.backend.get_key(user1_fp)])

        # import a private key
        self.assertKeys(self.backend.import_private_key(user2_priv), [user2_fp])
        self.assertEqual(self.backend.list_keys(),
                         [self.backend.get_key(user1_fp), self.backend.get_key(user2_fp)])
        self.assertEqual(self.backend.list_keys(secret_keys=True),
                         [self.backend.get_key(user2_fp)])

        # import second public key, test query
        self.assertKeys(self.backend.import_key(user2_pub), [user2_fp])
        self.assertEqual(self.backend.list_keys(query='Private Citizen Two'),
                         [self.backend.get_key(user2_fp)])
        self.assertEqual(self.backend.list_keys(query='user@example.net'),
                         [self.backend.get_key(user2_fp)])
        self.assertEqual(self.backend.list_keys(query='user@example.com'),
                         [self.backend.get_key(user1_fp)])
        self.assertEqual(self.backend.list_keys(query='bogus'), [])

    def test_no_expires(self):
        keys = self.backend.import_key(user1_pub)
        self.assertKeys(keys, [user1_fp])
        self.assertIsNone(keys[0].expires)

    def test_expires(self):
        keys = self.backend.import_key(expires_pub)
        self.assertKeys(keys, [expires_fp])
        self.assertEqual(keys[0].expires, datetime(2046, 8, 12, 7, 53, 29))

    def test_expired(self):
        keys = self.backend.import_key(expired_pub)
        self.assertKeys(keys, [expired_fp])
        self.assertEqual(keys[0].expires, datetime(2016, 8, 20, 7, 56, 25))

    def test_sign(self):
        data = b'testdata'

        keys = self.backend.import_key(user3_pub)
        self.assertKeys(keys, [user3_fp])

        priv_keys = self.backend.import_private_key(user3_priv)
        self.assertKeys(priv_keys, [user3_fp])

        signature = self.backend.sign(data, priv_keys[0])
        self.assertEqual(self.backend.verify(data, signature), user3_fp)

        signature = self.backend.sign(data, user3_fp)
        self.assertEqual(self.backend.verify(data, signature), user3_fp)

    def test_sign_unknown_key(self):
        with self.assertRaises(GpgKeyNotFoundError):
            self.backend.sign(b'testdata', user3_fp)

    def test_encrypt(self):
        data = b'testdata'
        keys = self.backend.import_key(user1_pub)
        self.assertKeys(keys, [user1_fp])

        priv_keys = self.backend.import_private_key(user1_priv)
        self.assertKeys(priv_keys, [user1_fp])

        encrypted = self.backend.encrypt(data, keys, always_trust=True)
        self.assertEqual(self.backend.decrypt(encrypted), data)

        # also test with fingerprints
        encrypted = self.backend.encrypt(data, [user1_fp], always_trust=True)
        self.assertEqual(self.backend.decrypt(encrypted), data)

    def test_encrypt_unkown_key(self):
        with self.assertRaises(GpgKeyNotFoundError):
            self.backend.encrypt(b'foobar', [user1_fp], always_trust=True)

        with self.assertRaises(GpgKeyNotFoundError):
            self.backend.encrypt(b'foobar', [user1_fp])

    def test_sign_encrypt(self):
        data = b'testdata'
        keys = self.backend.import_key(user3_pub)
        self.assertKeys(keys, [user3_fp])
        priv_keys = self.backend.import_private_key(user1_priv)
        self.assertKeys(priv_keys, [user1_fp])

        encrypted = self.backend.sign_encrypt(data, recipients=keys, signer=priv_keys[0],
                                              always_trust=True)

        user3_keys = self.backend.import_private_key(user3_priv)
        self.assertKeys(user3_keys, [user3_fp])
        self.assertEqual(self.backend.decrypt_verify(encrypted), (data, user1_fp))

        encrypted = self.backend.sign_encrypt(data, recipients=[user3_fp], signer=user1_fp,
                                              always_trust=True)
        self.assertEqual(self.backend.decrypt_verify(encrypted), (data, user1_fp))

    def test_sign_encrypt_unknown_key(self):
        with self.assertRaises(GpgKeyNotFoundError):
            self.backend.sign_encrypt(b'test', recipients=[user3_fp], signer=user1_fp)

        with self.assertRaises(GpgKeyNotFoundError):
            self.backend.sign_encrypt(b'test', recipients=[user3_fp], signer=user1_fp,
                                      always_trust=True)

    def test_trust(self):
        keys = self.backend.import_key(user4_pub)
        self.assertKeys(keys, [user4_fp])
        self.assertEqual(keys[0].trust, VALIDITY_UNKNOWN)

        # NOTE: We cannot set VALIDITY_UNKNOWN again
        for trust in [VALIDITY_FULL, VALIDITY_MARGINAL, VALIDITY_NEVER, VALIDITY_ULTIMATE]:
            keys[0].trust = trust
            self.assertEqual(keys[0].trust, trust)

    def test_set_unknown_trust(self):
        keys = self.backend.import_key(user4_pub)
        self.assertKeys(keys, [user4_fp])
        self.assertEqual(keys[0].trust, VALIDITY_UNKNOWN)
        keys[0].trust = VALIDITY_FULL

        with self.assertRaises(ValueError):
            keys[0].trust = VALIDITY_UNKNOWN

        self.assertEqual(keys[0].trust, VALIDITY_FULL)

    def test_set_random_trust(self):
        keys = self.backend.import_key(user4_pub)
        self.assertKeys(keys, [user4_fp])
        self.assertEqual(keys[0].trust, VALIDITY_UNKNOWN)
        keys[0].trust = VALIDITY_FULL

        with self.assertRaises(ValueError):
            keys[0].trust = 'foobar'

        self.assertEqual(keys[0].trust, VALIDITY_FULL)

    def test_encrypt_no_key(self):
        data = b'testdata'
        with self.assertRaises(GpgKeyNotFoundError):
            self.backend.encrypt(data, [user1_fp], always_trust=False)

    def test_encrypt_no_trust(self):
        data = b'testdata'
        keys = self.backend.import_key(user1_pub)
        self.assertKeys(keys, [user1_fp])

        priv_keys = self.backend.import_private_key(user1_priv)
        self.assertKeys(priv_keys, [user1_fp])

        with self.assertRaises(GpgUntrustedKeyError):
            self.backend.encrypt(data, keys, always_trust=False)

    def test_settings(self):
        data = b'testdata'
        keys = self.backend.import_key(user1_pub)
        self.assertKeys(keys, [user1_fp])

        priv_keys = self.backend.import_private_key(user1_priv)
        self.assertKeys(priv_keys, [user1_fp])

        home = tempfile.mkdtemp()

        try:
            with self.assertRaises(GpgKeyNotFoundError):
                with self.backend.settings(home=home) as backend:
                    key = backend.get_key(user1_fp)
                    backend.encrypt(data, [key], always_trust=False)
        finally:
            shutil.rmtree(home)

    def test_temp_keyring(self):
        keys = self.backend.import_key(user1_pub)
        self.assertEqual(self.backend.list_keys(), keys)

        with self.backend.temp_keyring() as temp_backend:
            keys = self.backend.import_key(user1_pub)
            self.assertEqual(temp_backend.list_keys(), [])

        keys = self.backend.import_key(user1_pub)

    def test_default_trust(self):
        data = b'testdata'
        keys = self.backend.import_key(user1_pub)
        self.assertKeys(keys, [user1_fp])

        priv_keys = self.backend.import_private_key(user1_priv)
        self.assertKeys(priv_keys, [user1_fp])

        with self.assertRaises(GpgUntrustedKeyError):
            self.backend.encrypt(data, priv_keys)

        with self.backend.settings(default_trust=True) as backend:
            key = backend.get_key(user1_fp)
            backend.encrypt(data, [key])

            with self.assertRaises(GpgUntrustedKeyError):
                self.backend.encrypt(data, priv_keys, always_trust=False)


class KeyPropertiesTestsMixin(object):
    def test_key_properties(self):
        key = self.backend.import_key(user1_pub)[0]
        self.assertEqual(key.name, 'Private Citizen One')
        self.assertEqual(key.comment, None)
        self.assertEqual(key.email, 'user@example.com')
        self.assertFalse(key.revoked)
        self.assertFalse(key.has_secret_key)

        # import the private key
        key = self.backend.import_key(user1_priv)[0]
        self.assertTrue(key.has_secret_key)

        key = self.backend.import_key(revoked_pub)[0]
        self.assertTrue(key.revoked)
        self.assertEqual(key.name, 'Public Citizen One')
        self.assertEqual(key.comment, 'revoked')
        self.assertEqual(key.email, 'user+revoked@example.com')

    def test_revoked(self):
        key = self.backend.import_key(revoked_pub)[0]
        self.assertTrue(key.revoked)


class ExportKeyTestsMixin(object):
    def test_key_ascii_export(self):
        export = self.key1.export()

        self.assertTrue(isinstance(export, six.text_type))

        # NOTE: The exported key is not necessarily the same as the original, because this may
        #       contain headers (e.g. GnuPG version), so we just do some basic sanity checking.
        self.assertTrue(export.startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----\n'))
        self.assertTrue(export.endswith('-----END PGP PUBLIC KEY BLOCK-----\n'))

        # Now we try to import that again, to see if it returns a key with the same fp
        key1 = self.backend.import_key(export)[0]
        self.assertEqual(self.key1, key1)

    def test_key_binary_export(self):
        export = self.key1.export(mode=MODE_BINARY)

        self.assertTrue(isinstance(export, bytes))
        self.assertEqual(user1_bin_pub, export)

        # Now we try to import that again, to see if it returns a key with the same fp
        key1 = self.backend.import_key(export)[0]
        self.assertEqual(self.key1, key1)

    def check_key_write_export(self, mode):
        buf = six.BytesIO()
        self.key1.export(mode=mode, output=buf)
        export = buf.getvalue()

        self.assertTrue(isinstance(export, six.binary_type))

        # Now we try to import that again, to see if it returns a key with the same fp
        key1 = self.backend.import_key(export)[0]
        self.assertEqual(self.key1, key1)

        # Try to export to a file
        with tempfile.NamedTemporaryFile() as out:
            key1.export(mode=mode, output=out)
            out.flush()
            with open(out.name, 'rb') as stream:
                export2 = stream.read()

        # this should just be the same
        self.assertEqual(export, export2)
        return export

    def test_key_export_output(self):
        export = self.check_key_write_export(MODE_ARMOR)
        self.assertTrue(export.startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----\n'))
        self.assertTrue(export.endswith(b'-----END PGP PUBLIC KEY BLOCK-----\n'))

        self.check_key_write_export(MODE_BINARY)


class DeleteKeyTestsMixin(object):
    def test_basic(self):
        self.assertEqual(self.backend.list_keys(user1_fp), [self.key1])
        self.assertEqual(self.backend.list_keys(user2_fp), [self.key2])

        self.key1.delete()
        self.assertEqual(self.backend.list_keys(user1_fp), [])

    def test_delete_secret(self):
        self.key2.delete(secret_key=True)
        self.assertEqual(self.backend.list_keys(user2_fp), [])

    def test_secret_key_present(self):
        with self.assertRaisesRegex(GpgSecretKeyPresent,
                                    expected_regex='^Secret key is present\.$'):
            self.key2.delete()

        self.assertEqual(self.backend.list_keys(user2_fp), [self.key2])

    def test_key_not_found(self):
        key = self.backend.get_key(user3_fp)
        with self.assertRaisesRegex(GpgKeyNotFoundError, expected_regex='^%s$' % user3_fp):
            key.delete()


class BasicGpgMeTestCase(BasicTestsMixin, GpgTestCase):
    backend_class = GpgMeBackend


class BasicGnuPGTestCase(BasicTestsMixin, GpgTestCase):
    backend_class = GnuPGBackend


class KeyPropertiesGpgMeTestCase(KeyPropertiesTestsMixin, GpgKeyTestCase):
    backend_class = GpgMeBackend


class KeyPropertiesGnuPGTestCase(KeyPropertiesTestsMixin, GpgKeyTestCase):
    backend_class = GnuPGBackend


class KeyPropertiesPymeTestCase(KeyPropertiesTestsMixin, GpgKeyTestCase):
    backend_class = PymeBackend


class ExportKeyGpgMeTestCase(ExportKeyTestsMixin, GpgKeyTestCase):
    backend_class = GpgMeBackend


class ExportKeyGnuPGTestCase(ExportKeyTestsMixin, GpgKeyTestCase):
    backend_class = GnuPGBackend


class DeleteKeyGpgMeTestCase(DeleteKeyTestsMixin, GpgKeyTestCase):
    backend_class = GpgMeBackend


class DeleteKeyGnuPGTestCase(DeleteKeyTestsMixin, GpgKeyTestCase):
    backend_class = GnuPGBackend
