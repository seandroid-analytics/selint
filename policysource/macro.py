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
"""Class providing an abstraction for a m4 macro."""

import re

class M4Macro(object):
    def __init__(self, name, expansion, file_defined, args=[], comments=[]):
        # Check if we have enough data
        if (not name or not expansion or not file_defined or args is None or comments is None):
            if not name:
                name = "noname"
            if args is None:
                args = ["noargs"]
            raise Exception("Bad macro \"{}({})\"".format(name,", ".join(args)))
        # Initialize the macro
        self._name = name
        # Double all curly brackets to make them literal
        expansion = re.sub(r"([{}])", r"\1\1", expansion)
        # Substitute @@ARGN@@ with {N} to format the argument for Python substitution
        self._expansion = re.sub(r"@@ARG([0-9]+)@@", r"{\1}", expansion)
        self._file_defined = file_defined
        self._args = args
        self._comments = comments

    @property
    def name(self):
        """Get the macro name."""
        return self._name

    def expand(self,args=[]):
        """Get the macro expansion using the provided arguments."""
        if self.nargs == 0 or args == None:
            # Ignore supplied arguments
            return self._expansion
        # Remove empty arguments
        args = [ x for x in args if x]
        if len(args) == len(self.args):
            # Expand using the given arguments
            return self._expansion.format(*args)
        else:
            # Expand using the definition arguments as placeholders
            return self._expansion.format(*self.args)

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
        r = self.name
        if self.nargs > 0:
            r += "(" + ", ".join(self.args) + ")"
        return r
