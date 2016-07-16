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

from distutils.cmd import Command
from setuptools import setup


class BackendMailCommand(Command):
    description = 'Create test-messages using basic MIME messages.'
    user_options = [
        ('dest=', 'd', 'Destination director for the messages.'),
    ]
    def initialize_options(self):
        self.dest = os.path.abspath('build')

    def finalize_options(self):
        if not os.path.exists(self.dest):
            os.makedirs(self.dest)

    def run(self):
        print(self.dest)


setup(
    name='gpg-mime',
    version='0.1',
    description='Library for creating PGP/MIME mails with various library backends.',
    long_description='TODO',  # TODO
    author='Mathias Ertl',
    author_email='mati@er.tl',
    url='https://github.com/mathiasertl/gpg-mime',
    packages=[
        'gpgmime',
    ],
    package_dir={'': 'gpgmime'},
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
