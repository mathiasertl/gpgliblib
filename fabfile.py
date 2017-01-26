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

import six
from fabric.api import local
from fabric.api import task

sys.path.insert(0, os.path.dirname(__file__))
coverage_dir = os.path.join(os.path.dirname(__file__), 'build', 'coverage')
testdata_dir = os.path.join(os.path.dirname(__file__), 'testdata')


class TestLoader(unittest.TestLoader):
    """TestLoader that creates a dynamic subclass for every TestCase with the backend passed in the
    constructor.
    """

    def __init__(self, name):
        self.name = name

    def loadTestsFromName(self, name):
        tests = super(TestLoader, self).loadTestsFromName(name)
        test = tests._tests[0]
        for test in tests:
            test.backend_name = self.name
        return tests

    def loadTestsFromTestCase(self, cls):
        tests = super(TestLoader, self).loadTestsFromTestCase(cls)
        for test in tests:
            test.backend_name = self.name
        return tests


@task
def test(name=None, backend=None):
    """Run the testsuite."""

    if backend is None:
        backends = ['gpgliblib.gpgme.GpgMeBackend',
                    'gpgliblib.python_gnupg.PythonGnupgBackend',
                    'gpgliblib.pyme.PymeBackend', ]
    else:
        backends = [backend]

    suites = []

    for backend in backends:
        if name is None:
            suite = TestLoader(backend).discover('tests')
        else:
            # fabric does not have the current directory in the path for some reason
            suite = TestLoader(backend).loadTestsFromName(name)

        suites.append(suite)

    big_suite = unittest.TestSuite(suites)
    unittest.TextTestRunner().run(big_suite)


@task
def coverage():
    import coverage

    cov = coverage.Coverage(source=['gpgliblib', ])

    if six.PY2:
        cov.exclude('pragma: py3')
    else:
        cov.exclude('pragma: py2')

    cov.start()

    # exclude code for specific GPG versions
    from gpgliblib.utils import get_version
    version = get_version()
    if version >= (2, ):
        cov.exclude('pragma: gpg1')
    elif version < (2, ):
        cov.exclude('pragma: gpg2')

    # omit pyme backend if pyme lib can't be imported
    omit = []
    try:
        import pyme  # NOQA
    except ImportError:
        omit.append('gpgliblib/pyme.py')

    test()

    cov.stop()
    cov.save()

    cov.html_report(directory=coverage_dir, omit=omit)


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

    # NOTE: we import here because coverage requires that files aren't imported before starting
    #       coverage.
    from gpgliblib import gpgme
    from gpgliblib import python_gnupg

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
