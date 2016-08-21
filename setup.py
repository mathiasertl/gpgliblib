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

from distutils.cmd import Command
from setuptools import find_packages
from setuptools import setup

testdata_dir = os.path.join(os.path.dirname(__file__), 'testdata')

class BackendMailCommand(Command):
    description = 'Create test-messages using basic MIME messages.'
    user_options = [
        ('dest=', 'd', 'Destination director for the messages.'),
        ('fp=', None, 'Fingerprint to use for signing/encrypting.'),
    ]
    def initialize_options(self):
        self.dest = os.path.join(os.path.abspath('build'), 'test_backends')

        # default is my own GPG key ;-)
        self.fp = 'CC9F343794DBB20E13DE097EE53338B91AA9A0AC'

    def finalize_options(self):
        if not os.path.exists(self.dest):
            os.makedirs(self.dest)

    def test_backend(self, backend):
        from gpgmime.base import VALIDITY_ULTIMATE

        dest_dir = os.path.join(self.dest, backend.__module__.split('.', 1)[1])
        if not os.path.exists(dest_dir):
            os.makedirs(dest_dir)

        with open(os.path.join(testdata_dir, '%s.priv' % self.fp), 'rb') as stream:
            backend.import_private_key(stream.read())

        with open(os.path.join(testdata_dir, '%s.pub' % self.fp), 'rb') as stream:
            backend.import_key(stream.read())

        backend.set_trust(self.fp, VALIDITY_ULTIMATE)

        msg = backend.sign_message('foobar', [self.fp])
        with open(os.path.join(dest_dir, 'signed-only.eml'), 'wb') as stream:
            stream.write(msg.as_bytes())

        msg = backend.encrypt_message('foobar', recipients=[self.fp])
        with open(os.path.join(dest_dir, 'encrypted-only.eml'), 'wb') as stream:
            stream.write(msg.as_bytes())

        msg = backend.encrypt_message('foobar', recipients=[self.fp], signers=[self.fp])
        with open(os.path.join(dest_dir, 'signed-encrypted.eml'), 'wb') as stream:
            stream.write(msg.as_bytes())

    def test_gpgme(self):
        tmpdir = tempfile.mkdtemp()

        try:
            from gpgmime import gpgme
            self.test_backend(gpgme.GpgMeBackend(home=tmpdir))
        finally:
            shutil.rmtree(tmpdir)

    def run(self):
        self.test_gpgme()


setup(
    name='gpg-mime',
    version='0.1',
    description='Library for creating PGP/MIME mails with various library backends.',
    long_description='TODO',  # TODO
    author='Mathias Ertl',
    author_email='mati@er.tl',
    url='https://github.com/mathiasertl/gpg-mime',
    packages=find_packages(),
    install_requires=[],
    cmdclass={
        'test_backends': BackendMailCommand,
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Framework :: Django :: 1.8',
        'Framework :: Django :: 1.9',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Security :: Cryptography',
        'Topic :: Security',
    ],
)
