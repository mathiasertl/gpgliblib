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

import re
import subprocess

VERSION_RE = re.compile(r'gpg \(GnuPG\) (\d+(\.\d+)*)'.encode('ascii'), re.I)


def get_version(path='gpg'):
    """Get the GnuPG version from the command line.

    Parameters
    ----------

    path : str, optional
        Path to GnuPG binary.
    """
    output = subprocess.check_output([path, '--version'])
    version = VERSION_RE.match(output).groups()[0].decode('utf-8')
    return tuple([int(c) for c in version.split('.')])
