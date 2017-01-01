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

from django.core.management.base import BaseCommand

from gpgliblib import django
from gpgliblib import gpgme


class Command(BaseCommand):
    help = "Send test-emails."

    def add_arguments(self, parser):
        parser.add_argument('--sign', default='E8172F2940EA9F709842290870BD9664FA3947CD')
        parser.add_argument('--encrypt', default='E8172F2940EA9F709842290870BD9664FA3947CD')
        parser.add_argument('--from', default='mati@fsinf.at')
        parser.add_argument('--to', default='mati@fsinf.at')

    def handle(self, *args, **options):
        sign = [options['sign']]
        encrypt = [options['encrypt']]
        frm = options['from']
        to = [options['to']]

        backend = gpgme.GpgMeBackend()

        ##########################
        # Non-multipart messages #
        ##########################

        # only sign
        msg = django.GpgEmailMessage(
            to=to, from_email=frm, subject='non-multipart, signed',
            body='non-multipart, signed',
            gpg_backend=backend, gpg_signers=sign)
        print('Sending %s' % msg.subject)
        msg.send()

        # only encrypt
        msg = django.GpgEmailMessage(
            to=to, from_email=frm, subject='non-multipart, encrypted',
            body='non-multipart, encrypted',
            gpg_backend=backend, gpg_recipients=encrypt)
        print('Sending %s' % msg.subject)
        msg.send()

        # sign and encrypt
        msg = django.GpgEmailMessage(
            to=to, from_email=frm, subject='non-multipart, signed/encrypted',
            body='non-multipart, signed/encrypted',
            gpg_backend=backend, gpg_recipients=encrypt, gpg_signers=sign)
        print('Sending %s' % msg.subject)
        msg.send()

        ######################
        # Multipart messages #
        ######################
        # only sign
        msg = django.GpgEmailMessage(
            to=to, from_email=frm, subject='multipart, signed',
            body='multipart, signed',
            gpg_backend=backend, gpg_signers=sign)
        msg.attach_alternative('content in html', 'text/html')
        print('Sending %s' % msg.subject)
        msg.send()

        # only encrypt
        msg = django.GpgEmailMessage(
            to=to, from_email=frm, subject='multipart, encrypted',
            body='multipart, encrypted',
            gpg_backend=backend, gpg_recipients=encrypt)
        msg.attach_alternative('content in html', 'text/html')
        print('Sending %s' % msg.subject)
        msg.send()

        # sign and encrypt
        msg = django.GpgEmailMessage(
            to=to, from_email=frm, subject='multipart, signed/encrypted',
            body='multipart, signed/encrypted',
            gpg_backend=backend, gpg_recipients=encrypt, gpg_signers=sign)
        msg.attach_alternative('content in html', 'text/html')
        print('Sending %s' % msg.subject)
        msg.send()
