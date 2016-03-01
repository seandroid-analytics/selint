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
"""Classes providing abstractions for m4 macros."""

import os
import re
import tempfile
import subprocess
import logging


class Error(Exception):
    """Custom error base class."""

    def __init__(self, message):
        super(Error, self).__init__(message)


class M4MacroError(Error):
    """Exception raised by the M4Macro constructor if a macro is not valid"""
    pass


class M4MacroExpanderError(Error):
    """Exception raised by the M4MacroExpander constructor"""
    pass


class M4FreezeFileError(Error):
    """Exception raised by the M4FreezeFile constructor if file creation
    failed"""
    pass


class M4MacroExpander(object):
    """Class providing a way to expand m4 macros."""

    def __init__(self, macro_files, tmpdir, extra_defs):
        """Initialize a macro expander.

        Create a freeze file with the supplied macro definition files,
        and set it up to be used to expand m4 macros."""
        # Setup logger
        self.log = logging.getLogger(self.__class__.__name__)
        # Setup temporary directory
        if (tmpdir and os.access(tmpdir, os.F_OK) and
                os.access(tmpdir, os.R_OK | os.W_OK | os.X_OK)):
            # We have been provided with a valid directory
            # We do not manage it (do not destroy it!)
            self._tmpdir = tmpdir
            self._tmpdir_managed = False
        else:
            # Create a temporary directory
            self._tmpdir = tempfile.mkdtemp()
            self.log.debug("Created temporary directory \"%s\".", self._tmpdir)
            # We manage it (we must destroy it when we're done)
            self._tmpdir_managed = True
        # Setup freeze file
        try:
            self.freeze_file = M4FreezeFile(
                macro_files, self.tmpdir, extra_defs)
        except M4FreezeFileError as e:
            # We failed to generate the freeze file, abort
            self.log.error("%s", e.message)
            raise M4MacroExpanderError(e.message)
        # Create a temporary file that will contain, at each request, the
        # macro to be expanded by m4. This is better than piping input to m4.
        # mkstemp() returns a tuple containing a handle to an open file
        # and the absolute pathname of that file, in that order
        tpl = tempfile.mkstemp(dir=self.tmpdir)
        os.close(tpl[0])
        self._tmp = tpl[1]
        self.log.debug("Created temporary file \"%s\".", self.tmp)
        # Define the expansion command
        self.expansion_command = ["m4", "-R",
                                  self.freeze_file.freeze_file, self.tmp]

    def __del__(self):
        """Clean up the temporary file, the freeze file and the
        temporary directory"""
        # Remove the temporary file
        try:
            os.remove(self.tmp)
        except OSError:
            self.log.warning("Trying to remove the temporary file"
                             " \"%s\"... failed!", self.tmp)
        else:
            self.log.debug("Trying to remove the temporary file"
                           " \"%s\"... done!", self.tmp)
        # Force removal of the freeze file
        del self.freeze_file
        # Try to remove the temporary directory if managed
        if self.tmpdir_managed:
            try:
                os.rmdir(self.tmpdir)
            except OSError:
                self.log.warning("Trying to remove the temporary directory"
                                 " \"%s\"... failed!", self.tmpdir)
            else:
                self.log.debug("Trying to remove the temporary directory"
                               " \"%s\"... done!", self.tmpdir)

    def expand(self, text):
        """Expand a string of text representing a m4 macro."""
        # Write the macro to the temporary file
        with open(self.tmp, "w") as mfile:
            mfile.write(text)
        # Try to get the macro expansion with m4
        try:
            expansion = subprocess.check_output(self.expansion_command)
        except subprocess.CalledProcessError as e:
            # Log the error and change the function return value to None
            self.log.warning("%s", e.output)
            expansion = None
        return expansion

    def dump(self, text):
        """Dump the definition of a m4 macro."""
        # Write the command to a temporary file
        with open(self.tmp, "w") as mfile:
            mfile.write("dumpdef(`{}')".format(text))
        # Run the m4 command
        try:
            definition = subprocess.check_output(self.expansion_command,
                                                 stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            # Log the error and change the function return value to None
            self.log.warning("%s", e.output)
            definition = None
        return definition

    @property
    def tmpdir(self):
        """Get the temporary directory used by the expander."""
        return self._tmpdir

    @property
    def tmpdir_managed(self):
        """Check if the temporary directory used by the expander is
        managed by the expander."""
        return self._tmpdir_managed

    @property
    def tmp(self):
        """Get the temporary file used by the expander."""
        return self._tmp


class M4FreezeFile(object):

    """Class for handling an m4 freeze file."""

    def __init__(self, files, tmpdir, extra_defs=[], name="freezefile"):
        """Generate the freeze file with all macro definitions."""
        # Setup logger
        self.log = logging.getLogger(self.__class__.__name__)
        # Setup parameters
        self.files = files
        self.tmpdir = tmpdir
        self.extra_defs = extra_defs
        self.name = name
        self.freeze_file = os.path.join(tmpdir, name)
        self.command = ["m4"]
        for definition in self.extra_defs:
            self.command.extend(["-D", definition])
        self.command.extend(["-s"])
        self.command.extend(self.files)
        self.command.extend(["-F", self.freeze_file])
        self.log.debug("Trying to generate freeze file \"%s\"...",
                       self.freeze_file)
        self.log.debug("$ %s", " ".join(self.command))
        try:
            # Generate the freeze file
            with open(os.devnull, "w") as devnull:
                subprocess.check_call(self.command, stdout=devnull)
        except subprocess.CalledProcessError:
            # We failed to generate the freeze file, abort
            self.log.error(
                "Failed to generate freeze file \"%s\".", self.freeze_file)
            raise M4FreezeFileError("Failed to generate freeze file")
        else:
            # We successfully generated the freeze file
            self.log.debug("Successfully generated freeze file \"%s\".",
                           self.freeze_file)

    def __del__(self):
        """Delete the freeze file"""
        try:
            os.remove(self.freeze_file)
        except OSError:
            self.log.debug("Trying to remove the freeze file "
                           "\"%s\"... failed!", self.freeze_file)
        else:
            self.log.debug("Trying to remove the freeze file "
                           "\"%s\"... done!", self.freeze_file)


class M4Macro(object):

    """Class providing an abstraction for a m4 macro."""
    operators = ("ifelse(", "incr(", "decr(", "errprint(")

    def __init__(self, name, expander, file_defined, args=[], comments=[]):
        # Check if we have enough data
        if (not name or not expander or not file_defined or args is None
                or comments is None):
            if not name:
                name = "noname"
            if args is None:
                args = ["noargs"]
            raise M4MacroError("Bad parameters for macro \"{}({})\"".format(
                name, ", ".join(args)))
        # Initialize the macro
        self._name = name
        self._expander = expander
        self._expansion = None
        self._expansion_static = None
        self._dump = None
        self._file_defined = file_defined
        self._args = args
        self._comments = comments

    @property
    def name(self):
        """Get the macro name."""
        return self._name

    def expand(self, args=None):
        """Get the macro expansion using the provided arguments."""
        # Check whether the M4 expansion is static (simple variable
        # substitution) or dynamic (ifelses, ...)
        if self._expansion_static is None:
            # If the macro definition contains any m4 operator
            if any(s in self.dump for s in M4Macro.operators):
                self._expansion_static = False
            else:
                self._expansion_static = True
        if self.nargs == 0:
            # Ignore supplied arguments
            # Macro without arguments: the expansion is static. Save it for
            # faster access
            if not self._expansion:
                self._expansion = self._expander.expand(self.name)
            return self._expansion
        if args is None:
            # Return the expansion as defined in the macro definition
            # Don't expand the macro with the placeholder arguments, as that
            # breaks on macros that expect numeric arguments
            # e.g. "gen_sens(N)" will not terminate if N is not a number
            return self.dump
        # Sanity check
        if len(args) != len(self.args):
            return None
        # Expand the macro
        if not self.expansion_static:
            # If the expansion is dynamic, we have to call m4 every time
            text = self.name + "(" + ", ".join(args) + ")"
            return self._expander.expand(text)
        else:
            # If the expansion is static, we can call m4 only once, and then
            # perform Python string formatting all the other times.
            if not self._expansion:
                # Get the expansion with placeholders, if we don't have it
                placeholders = []
                for i in xrange(self.nargs):
                    placeholders.append("@@ARG{}@@".format(i))
                tmp = self.name + "(" + ", ".join(placeholders) + ")"
                expansion = self._expander.expand(tmp)
                # Double all curly brackets to make them literal
                expansion = re.sub(r"([{}])", r"\1\1", expansion)
                # Substitute @@ARGN@@ with {N} to format the argument for
                # Python string formatting
                self._expansion = re.sub(
                    r"@@ARG([0-9]+)@@", r"{\1}", expansion)
            # Expand using the given arguments
            return self._expansion.format(*args)

    @property
    def expansion_static(self):
        """Check whether the macro expansion is static (simple string
        substitution) or dynamic (variable length depending on arguments)."""
        return self._expansion_static

    @property
    def dump(self):
        """Get the macro definition."""
        if not self._dump:
            dump = self._expander.dump(self.name)
            # Remove the first line ("name:")
            self._dump = "\n".join(dump.splitlines()[1:])
        return self._dump

    @property
    def file_defined(self):
        """Get the file where the macro was defined."""
        return self._file_defined

    @property
    def args(self):
        """Get the names of the macro arguments."""
        return self._args

    @property
    def nargs(self):
        """Get the number of macro arguments."""
        return len(self._args)

    @property
    def comments(self):
        """Get the macro comments as a list of lines"""
        return self._comments

    def __repr__(self):
        tmp = self.name
        if self.nargs > 0:
            tmp += "(" + ", ".join(self.args) + ")"
        return tmp

    def __eq__(self, other):
        # If they have the same representation
        # And the same expansion
        # And they are defined in the same file
        # And they have the same number of arguments
        # And the same comments
        return str(self) == str(other)\
            and self.expand() == other.expand()\
            and self.file_defined == other.file_defined\
            and self.nargs == other.nargs\
            and len(self.comments) == len(other.comments)\
            and "".join(self.comments) == "".join(other.comments)

    def __ne__(self, other):
        return not self == other


class MacroInPolicy(object):

    """Class providing an abstraction for an usage of a m4 macro."""

    def __init__(self, existing_macros, file_used, line_used, name, args=[]):
        # Check that we have enough data
        if (not existing_macros or not file_used or line_used is None or
                not isinstance(line_used, int) or int(line_used) < 0 or
                not name or args is None):
            if not name:
                name = "noname"
            if args is None:
                args = ["noargs"]
            raise M4MacroError(
                "Bad parameters for macro \"{}({})\"".format(
                    name, ", ".join(args)))
        # Initialize the macro
        # If the macro is a valid macro
        if name in existing_macros and existing_macros[name]\
                and existing_macros[name].nargs == len(args):
            # Link this macro usage with the macro definition
            self.macro = existing_macros[name]
            # Record the specific arguments for this macro usage
            self._args = args
            # Record the file for this usage
            self._file_used = file_used
            # Record the line number for this usage
            self._line_used = int(line_used)
        else:
            raise M4MacroError(
                "Invalid macro \"{}({})\"".format(name, ", ".join(args)))

    @property
    def name(self):
        """Get the macro name"""
        return self.macro.name

    @property
    def expansion(self):
        """Get the macro expansion using the specific usage's arguments."""
        # If we have not generated the macro expansion yet, generate it on the
        # fly and save it for future use
        if not hasattr(self, "_expansion"):
            # TODO: warning: expand() can return None if the number of
            # arguments is wrong. This should not happen, maybe put some more
            # checks to be sure?
            self._expansion = self.macro.expand(self.args)
            self._expansion_linelen = len(self._expansion.splitlines())
        return self._expansion

    @property
    def expansion_linelen(self):
        """Get the length in lines of the macro expansion with the specific
        arguments."""
        # If we have not generated the macro expansion yet, generate it on the
        # fly and save it for future use
        if not hasattr(self, "_expansion"):
            # TODO: warning: expand() can return None if the number of
            # arguments is wrong. This should not happen, maybe put some more
            # checks to be sure?
            self._expansion = self.macro.expand(self.args)
            self._expansion_linelen = len(self._expansion.splitlines())
        return self._expansion_linelen

    @property
    def file_used(self):
        """Get the file where the macro was used"""
        return self._file_used

    @property
    def line_used(self):
        """Get the line where the macro was used"""
        return self._line_used

    @property
    def args(self):
        """Get the names of the macro arguments"""
        return self._args

    @property
    def args_descriptions(self):
        """Get the descriptions of the macro arguments"""
        return self.macro.args

    @property
    def nargs(self):
        """Get the number of macro arguments"""
        return len(self._args)

    def __repr__(self):
        tmp = self.name
        if self.nargs > 0:
            tmp += "(" + ", ".join(self.args) + ")"
        return tmp

    def __eq__(self, other):
        # If they are a usage of the same M4Macro instance
        # With the same arguments
        # And with the same expansion (sort of redundant check)
        # Used in the same place
        return self.macro == other.macro\
            and self.nargs == other.nargs\
            and self.expansion == other.expansion\
            and self.file_used == other.file_used\
            and self.line_used == other.line_used

    def __ne__(self, other):
        return not self == other
