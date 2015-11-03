#
#    Written by Filippo Bonazzi
#    Copyright (C) 2015 Aalto University
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
"""Plugin to parse the global_macros file"""

from policysource.macro import M4Macro as M4Macro
import os
import re
import logging

macro_file = "global_macros"
log = logging.getLogger(__name__)


def expects(f):
    """Return True/False depending on whether the plugin can handle the file"""
    if f and os.path.basename(f) == macro_file:
        return True
    else:
        return False


def parse(f, tempdir, m4_freeze_file):
    """Parse the file and return a dictionary of macros."""
    # Check that we can handle the file we're served
    if not f or not expects(f):
        return None
    macros = {}
    # global_macros specific parsing
    macrodef = re.compile(r'^define\(\`([^\']+)\',\s+`([^\']+)\'')
    with open(f) as macros_file:
        for line in macros_file:
            n = macrodef.search(line)
            if n is not None:
                macros[n.group(1)] = M4Macro(n.group(1), n.group(2), f)
    return macros
