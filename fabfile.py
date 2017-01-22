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

import os
import sys
import tempfile
import unittest

from fabric.api import local
from fabric.api import task
from fabric.context_managers import shell_env

from gpgliblib import gpgme
from gpgliblib import python_gnupg

testdata_dir = os.path.join(os.path.dirname(__file__), 'testdata')


@task
def test(name=None):
    """Run the testsuite."""

    if name is None:
        suite = unittest.TestLoader().discover('tests')
    else:
        sys.path.insert(0, os.path.dirname(__file__))
        suite = unittest.TestLoader().loadTestsFromName(name)

    unittest.TextTestRunner().run(suite)


@task
def coverage(gpgver='2.1'):
    with shell_env(GNUPG_VERSION=gpgver):
        local('coverage run --source=gpgliblib testproject/manage.py test testapp')
        local('coverage html')


@task
def check():
    """Run the testsuite and style-checks."""

    local('flake8 gpgliblib')
    local('isort --check-only -rc gpgliblib/')

    test()


@task
def test_mime_messages(fp=None, dest=None):
    """Create test-messages using basic MIME messages.

    Parameters
    ----------

    dest
        Destination directory for the messages, defaults to ``build/test_backends``.
    fp
        Fingerprint to use, defaults to ``"CC9F343794DBB20E13DE097EE53338B91AA9A0AC"``.
        If given, this should be one of the keys located in the ``testdata/`` directory..
    """

    if not fp:
        fp = 'CC9F343794DBB20E13DE097EE53338B91AA9A0AC'
    if not dest:
        dest = os.path.join(os.path.abspath('build'), 'test_backends')

    if not os.path.exists(dest):
        os.makedirs(dest)

    def test_backend(backend):
        dest_dir = os.path.join(dest, backend.__module__.split('.', 1)[1])
        if not os.path.exists(dest_dir):
            os.makedirs(dest_dir)

        with open(os.path.join(testdata_dir, '%s.priv' % fp), 'rb') as stream:
            backend.import_private_key(stream.read())

        with open(os.path.join(testdata_dir, '%s.pub' % fp), 'rb') as stream:
            backend.import_key(stream.read())

        msg = backend.sign_message('foobar', fp)
        with open(os.path.join(dest_dir, 'signed-only.eml'), 'wb') as stream:
            stream.write(msg.as_bytes())

        msg = backend.encrypt_message('foobar', recipients=[fp])
        with open(os.path.join(dest_dir, 'encrypted-only.eml'), 'wb') as stream:
            stream.write(msg.as_bytes())

        msg = backend.encrypt_message('foobar', recipients=[fp], signers=[fp])
        with open(os.path.join(dest_dir, 'signed-encrypted.eml'), 'wb') as stream:
            stream.write(msg.as_bytes())

    with tempfile.TemporaryDirectory() as home:
        backend = gpgme.GpgMeBackend(home=home, default_trust=True)
        test_backend(backend)

    with tempfile.TemporaryDirectory() as home:
        backend = python_gnupg.PythonGnupgBackend(home=home, default_trust=True)
        test_backend(backend)


@task
def autodoc():
    """Automatically rebuild documentation on source changes."""

    local('make -C doc clean')
    ignore = '-i *.sw[pmnox] -i *~ -i */4913'
    local('sphinx-autobuild -p 8080 --watch gpgliblib %s doc/ doc/_build/html/' % ignore)
