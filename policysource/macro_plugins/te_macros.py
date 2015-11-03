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
"""Plugin to parse the te_macros file"""

from policysource.macro import M4Macro as M4Macro
import os
import re
import subprocess
from subprocess import check_output, CalledProcessError
import logging

macro_file = "te_macros"
log = logging.getLogger(__name__)
blk = r"^#\s[a-zA-Z][a-zA-Z0-9_]*\((?:[a-zA-Z0-9_]+,\s?)*(?:[a-zA-Z0-9_]+)\)$"


def expects(f):
    """Return True/False depending on whether the plugin can handle the file"""
    if f and os.path.basename(f) == macro_file:
        return True
    else:
        return False


def parse(f, tempdir, m4_freeze_file):
    """Parse the file and return a dictionary of macros."""
    if not f or not expects(f):
        return None
    macros = {}
    tmp = os.path.join(tempdir, "te_macrofile")
    with open(f) as te_file:
        fc = te_file.read()
        # Split the file in blocks
        blocks = re.findall("^#+$\n(?:^.*$\n)+?\n", fc, re.MULTILINE)
        for b in blocks:
            # Parse the macro block
            comments = []
            # Split the macro block in lines, removing empty lines
            block = [x for x in b.splitlines() if x]
            # Check that the macro definition line is correct
            if not re.match(blk, block[1]):
                # If not, skip this macro.
                lineno = 0
                for i, l in enumerate(fc.splitlines()):
                    if block[1] == l:
                        lineno = i
                        break
                log.warning("Bad macro definition at {}:{}".format(f, lineno))
                continue
            # Tokenize the macro definition line, removing empy tokens
            # "macro(arg1,arg2)" -> ["macro", "arg1", "arg2"]
            definition = [x for x in re.split(r'\W+', block[1]) if x]
            name = definition[0]  # ["macro"]
            args = definition[1:]  # ["arg1", "arg2"]
            # Get comments
            for l in block:
                if l.startswith('#'):
                    comments.append(l)
            # Expand the macro
            with open(tmp, "w") as mfile:
                # Write "name(@@ARG0@@, @@ARG1@@, ...)" to file
                mfile.write(name + "(" + ", ".join(
                    ["@@ARG{}@@".format(x) for x in range(0, len(args))])
                    + ")")
            try:
                command = ["m4", "-R", m4_freeze_file, tmp]
                expansion = subprocess.check_output(command)
            except CalledProcessError as e:
                # We failed to expand a macro.
                # TODO: add loggin e.msg
                # Find the macro line and report it to the user
                lineno = 0
                for i, l in enumerate(fc.splitlines()):
                    if block[1] == l:
                        lineno = i
                        break
                log.warning("Failed to expand macro \"{}\" at "
                            "{}:{}".format(name, f, lineno))
                # Skip to the next macro
                continue
            # Add the macro to the macro dictionary
            macros[name] = M4Macro(name, expansion, f, args, comments)
    try:
        os.remove(tmp)
    except OSError:
        pass
    return macros
