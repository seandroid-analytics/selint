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
"""Classes providing abstractions for m4 macros."""

import re


class M4MacroError(Exception):
    """Exception raised by the M4Macro constructor if a macro is not valid"""
    pass


class M4Macro(object):

    """Class providing an abstraction for a m4 macro."""

    def __init__(self, name, expansion, file_defined, args=[], comments=[]):
        # Check if we have enough data
        if (not name or not expansion or not file_defined or args is None
                or comments is None):
            if not name:
                name = "noname"
            if args is None:
                args = ["noargs"]
            raise M4MacroError(
                "Bad parameters for macro \"{}({})\"".format(
                    name, ", ".join(args)))
        # Initialize the macro
        self._name = name
        # Double all curly brackets to make them literal
        expansion = re.sub(r"([{}])", r"\1\1", expansion)
        # Substitute @@ARGN@@ with {N} to format the argument for Python
        # substitution
        self._expansion = re.sub(r"@@ARG([0-9]+)@@", r"{\1}", expansion)
        self._file_defined = file_defined
        self._args = args
        self._comments = comments

    @property
    def name(self):
        """Get the macro name."""
        return self._name

    def expand(self, args=None):
        """Get the macro expansion using the provided arguments."""
        if self.nargs == 0:
            # Ignore supplied arguments
            return self._expansion.format()
        if args is None:
            # Expand using the definition arguments as placeholders
            return self._expansion.format(*self.args)
        # Remove empty arguments
        args = [x for x in args if x]
        if len(args) == len(self.args):
            # Expand using the given arguments
            return self._expansion.format(*args)
        else:
            return None

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
        # If they have the same name
        if(self._name == other._name
                # And the same expansion
                and self._expansion == other._expansion
                # They are defined in the same file
                and self._file_defined == other._file_defined
                # They have the same arguments
                and len(self._args) == len(other._args)
                and set(self._args) == set(other._args)
                # And the same comments
                and len(self._comments) == len(other._comments)
                and set(self._comments) == set(other._comments)):
            return True
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)


class MacroInPolicy(object):

    """Class providing an abstraction for an usage of a m4 macro."""

    def __init__(self, existing_macros, file_used, line_no, name, args=[]):
        # Check that we have enough data
        if (not existing_macros or not file_used or not line_no or not name
                or args is None):
            if not name:
                name = "noname"
            if args is None:
                args = ["noargs"]
            raise M4MacroError(
                "Bad parameters for macro \"{}({})\"".format(
                    name, ", ".join(args)))
        # Initialize the macro
        # If the macro is a valid macro
        if existing_macros[name] and existing_macros[name].nargs == len(args):
            # Link this macro usage with the macro
            self._macro = existing_macros[name]
            # Record the specific arguments for this macro usage
            self._args = args
            # Record the file for this usage
            self._file_used = file_used
            # Record the line number for this usage
            self._line_no = line_no
        else:
            raise M4MacroError(
                "Invalid macro \"{}({})\"".format(name, ", ".join(args)))

    @property
    def name(self):
        """Get the macro name"""
        return self._macro.name

    def expand(self):
        """Get the macro expansion using the specific usage's arguments"""
        return self._macro.expand(self._args)

    @property
    def file_used(self):
        """Get the file where the macro was used"""
        return self._file_used

    @property
    def line_no(self):
        """Get the line where the macro was used"""
        return self._line_no

    @property
    def args(self):
        """Get the names of the macro arguments"""
        return self._args

    @property
    def args_descriptions(self):
        """Get the descriptions of the macro arguments"""
        return self._macro.args

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
        if(self._macro == other._macro
           # With the same arguments
           and len(self._args) == len(other._args)
           and set(self._args) == set(other._args)
           # And with the same expansion (sort of redundant check)
           and self.expand() == other.expand()
           # Used in the same place
           and self._file_used == other._file_used
           and self._line_no == other._line_no):
            return True
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)
