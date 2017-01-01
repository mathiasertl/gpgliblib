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

import os

from fabric.api import local
from fabric.api import task


@task
def test():
    """Run testsuite."""

    old = os.getcwd()
    os.chdir('testproject')
    local('python manage.py test')
    os.chdir(old)


@task
def check():
    """Run testsuite and style-checks."""

    local('flake8 gpgmime')
    local('isort --check-only -rc gpgmime/')

    test()


@task
def autodoc():
    """Automatically rebuild documentation on source changes."""

    local('make -C doc clean')
    ignore = '-i *.sw[pmnox] -i *~ -i */4913'
    local('sphinx-autobuild -p 8080 --watch gpgmime %s doc/ doc/_build/html/' % ignore)
