#
#    Written by Filippo Bonazzi
#    Copyright (C) 2016 Aalto University
#
#    This file is part of the policysource library.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Lesser General Public License as
#    published by the Free Software Foundation, either version 2.1 of
#    the License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public
#    License along with this program.  If not, see
#    <http://www.gnu.org/licenses/>.
#
"""Plugin to parse the global_macros file"""

from policysource.macro import M4Macro as M4Macro, M4MacroError as M4MacroError
import os
import re
import subprocess
import logging

MACRO_FILE = "global_macros"
LOG = logging.getLogger(__name__)


def expects(expected_file):
    """Return True/False depending on whether the plugin can handle the file"""
    if expected_file and os.path.basename(expected_file) == MACRO_FILE:
        return True
    else:
        return False


def __expand(name, tmp, m4_freeze_file):
    """Expand the macro with the given name, using the supplied temporary
    file and m4 freeze file."""
    with open(tmp, "w") as mfile:
        # Write the macro to the temporary file
        mfile.write(name)
    # Define the expansion command
    command = ["m4", "-R", m4_freeze_file, tmp]
    # Try to get the macro expansion with m4
    try:
        expansion = subprocess.check_output(command)
    except subprocess.CalledProcessError as e:
        # Log the error and change the function return value to None
        LOG.warning("%s", e.msg)
        expansion = None
    return expansion


def parse(f_to_parse, tmpdir, m4_freeze_file):
    """Parse the file and return a dictionary of macros.

    Raise ValueError if unable to handle the file."""
    # Check that we can handle the file we're served
    if not f_to_parse or not expects(f_to_parse):
        raise ValueError("{} can't handle {}.".format(MACRO_FILE, f_to_parse))
    macros = {}
    # Parse the global_macros file
    macrodef = re.compile(r'^define\(\`([^\']+)\',\s+`([^\']+)\'')
    # Create a temporary file that will contain, at each iteration, the
    # macro to be expanded by m4. This is better than piping input to m4.
    tmp = os.path.join(tmpdir, "global_macrofile")
    LOG.debug("Created temporary file \"%s\"", tmp)
    with open(f_to_parse) as global_macros_file:
        for lineno, line in enumerate(global_macros_file):
            # If the line contains a macro, parse it
            macro_match = macrodef.search(line)
            if macro_match is not None:
                # Construct the new macro object
                name = macro_match.group(1)
                expansion = __expand(name, tmp, m4_freeze_file)
                if expansion:
                    try:
                        new_macro = M4Macro(name, expansion, f_to_parse)
                    except M4MacroError as e:
                        # Log the failure and skip
                        # Find the macro line and report it to the user
                        LOG.warning("%s", e.msg)
                        LOG.warning("Macro \"%s\" is at %s:%s",
                                    name, f_to_parse, lineno)
                    else:
                        # Add the new macro to the dictionary
                        macros[name] = new_macro
                else:
                    # Log the failure and skip this macro
                    LOG.warning("Failed to expand macro \"%s\" at %s:%s",
                                name, f_to_parse, lineno)
    # Try to remove the temporary file
    try:
        os.remove(tmp)
    except OSError:
        LOG.debug("Trying to remove temporary file \"%s\"... failed!", tmp)
    else:
        LOG.debug("Trying to remove temporary file \"%s\"... done!", tmp)
    return macros
