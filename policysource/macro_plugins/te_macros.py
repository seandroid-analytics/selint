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

from policysource.macro import M4Macro as M4Macro, M4MacroError as M4MacroError
import os
import re
import subprocess
import logging

MACRO_FILE = "te_macros"
LOG = logging.getLogger(__name__)
MDL = r"^#\s[a-zA-Z][a-zA-Z0-9_]*\((?:[a-zA-Z0-9_]+,\s?)*(?:[a-zA-Z0-9_]+)\)$"
BLK_SEP = r"^##+$\n"


def expects(expected_file):
    """Return True/False depending on whether the plugin can handle the file"""
    if expected_file and os.path.basename(expected_file) == MACRO_FILE:
        return True
    else:
        return False


def __expand__(name, args, tmp, m4_freeze_file):
    """ Expand the macro with the given name and args, using the supplied
    temporary file and m4 freeze file"""

    with open(tmp, "w") as mfile:
        # Write the macro to the temporary file
        # "name(@@ARG0@@, @@ARG1@@, ...)"
        mfile.write(name + "(" + ", ".join(
            ["@@ARG{}@@".format(x) for x in range(0, len(args))]) + ")")
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


def parse(f_to_parse, tempdir, m4_freeze_file):
    """Parse the file and return a dictionary of macros.

    Raise ValueError if unable to handle the file."""
    # TODO: refactor this function, too many local variables
    # Check that we can handle the file we're served
    if not f_to_parse or not expects(f_to_parse):
        raise ValueError("{} can't handle {}.".format(MACRO_FILE, f_to_parse))
    macros = {}
    # Parse the te_macros file
    # Create a temporary file that will contain, at each iteration, the
    # macro to be expanded by m4. This is better than piping input to m4.
    tmp = os.path.join(tempdir, "te_macrofile")
    with open(f_to_parse) as te_macro_file:
        file_content = te_macro_file.read()
        # Split the file in blocks
        blocks = [x for x in re.split(
            BLK_SEP, file_content, flags=re.MULTILINE) if x]
        for current_block in blocks:
            # Parse the macro block
            comments = []
            # Split the macro block in lines, removing empty lines
            block = [x for x in current_block.splitlines() if x]
            # Check that the macro definition line is correct
            if not re.match(MDL, block[0]):
                # If not, log the failure and skip this block
                # Find the macro definition line
                lineno = file_content.splitlines().index(block[0])
                LOG.warning("Bad macro definition at %s:%s",
                            f_to_parse, lineno)
                continue
            # Tokenize the macro definition line, removing empy tokens
            # "# macro(arg1,arg2)" -> ["macro", "arg1", "arg2"]
            definition = [x for x in re.split(r'\W+', block[0]) if x]
            name = definition[0]    # ["macro"]
            args = definition[1:]   # ["arg1", "arg2"]
            # Get comments
            for line in block:
                if line.startswith('#'):
                    comments.append(line)
            # Get the macro expansion
            expansion = __expand__(name, args, tmp, m4_freeze_file)
            if expansion:
                # Construct the new macro object
                try:
                    new_macro = M4Macro(
                        name, expansion, f_to_parse, args, comments)
                except M4MacroError as e:
                    # Log the failure and skip
                    LOG.warning("%s", e.msg)
                else:
                    # Add the macro to the macro dictionary
                    macros[name] = new_macro
            else:
                # Log the failure and skip this macro
                # Find the macro line and report it to the user
                lineno = file_content.splitlines().index(block[0])
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
