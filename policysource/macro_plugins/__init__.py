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
"""Plugin module implementing file-specific macro parsing functions"""
import os
from os import path
import sys
import keyword
import inspect
from tempfile import mkdtemp
from subprocess import check_call, CalledProcessError
import logging


__all__ = []
for plugin_file in os.listdir(os.path.dirname(__file__)):
    if plugin_file.endswith(".py"):
        module = os.path.splitext(plugin_file)[0]
        if not module.startswith('_') and not keyword.iskeyword(module):
            try:
                __import__(__name__ + '.' + module)
            except:
                e = sys.exc_info()
                print e
            else:
                __all__.append(module)
__all__.sort()


class M4MacroParser(object):

    """Class providing a m4 file parser.

    The class handles a list of specific macro files through a plugin
    architecture defined in the macro_plugin module."""

    class M4FreezeFileError(Exception):
        """Exception raised by the M4FreezeFile constructor if file creation
        failed"""
        pass

    class M4FreezeFile(object):

        """Class for handling an m4 freeze file."""

        def __init__(self, files, tempdir, extra_defs=[], name="freezefile"):
            """Generate the freeze file with all macro definitions."""
            # Setup logger
            self.log = logging.getLogger(self.__class__.__name__)
            # Setup parameters
            self.files = files
            self.tempdir = tempdir
            self.extra_defs = extra_defs
            self.name = name
            self.freeze_file = os.path.join(tempdir, name)
            self.command = ["m4"]
            for definition in self.extra_defs:
                self.command.extend(["-D", definition])
            self.command.extend(["-s"])
            self.command.extend(self.files)
            self.command.extend(["-F", self.freeze_file])
            self.log.debug("Trying to generate freeze file \"%s\"...",
                           self.freeze_file)
            self.log.debug("$ %s", self.command)
            try:
                # Generate the freeze file
                with open(os.devnull, "w") as devnull:
                    check_call(self.command, stdout=devnull)
            except CalledProcessError as e:
                # We failed to generate the freeze file, abort
                self.log.error("%s", e.msg)
                raise self.M4FreezeFileError("Failed to generate freeze file"
                                             "\"%s\".", self.freeze_file)
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

    def __init__(self):
        """Initialize plugin architecture.

        Find all plugins offered by macro_plugins, check that they implement
        the required methods and add them to the plugin dictionary."""
        # Setup logger
        self.log = logging.getLogger(self.__class__.__name__)

        self.plugins = {}
        for mod in __all__:
            plugin = globals()[mod]
            if (inspect.isfunction(plugin.expects)
                    and inspect.isfunction(plugin.parse)):
                self.plugins[mod] = plugin
                self.log.debug("Found plugin \"%s\"", mod)
            else:
                self.log.debug("Invalid plugin \"%s\"", mod)

    def __get_parser__(self, single_file):
        """Find the appropriate parser for the given file.

        The match is currently based on the basename."""
        if os.path.basename(single_file) in self.plugins:
            return self.plugins[os.path.basename(single_file)]
        else:
            return None

    def __parse_file__(self, single_file, parser, tempdir, m4_freeze_file):
        """Parse a single file"""
        f_macros = None
        try:
            # Parse the file using the appropriate parser
            f_macros = parser.parse(single_file, tempdir,
                                    m4_freeze_file.freeze_file)
        except ValueError as e:
            # This really should not happen, since we have already
            # checked that the plugin accepts the file.
            # Log and skip
            self.log.warning("%s", e.msg)
            self.log.warning(
                "Could not parse \"%s\"", single_file)
        else:
            # File parsed successfully
            self.log.debug(
                "Parsed macros from \"%s\"", single_file)
        return f_macros

    def expects(self):
        """Returns a list of files that the parser can handle."""
        return self.plugins.keys()

    def parse(self, files):
        """Parses a list of files and returns a dictionary of macros."""
        # Remove empty strings, normalize paths
        files = [os.path.abspath(x) for x in files if x]
        # Create a temporary work directory
        tempdir = mkdtemp()
        self.log.debug("Created temporary directory \"%s\".", tempdir)
        # Generate the m4 freeze file with all macro definitions
        extra_defs = ["mls_num_sens=1",
                      "mls_num_cats=1024", "target_build_variant=eng"]
        try:
            m4_freeze_file = self.M4FreezeFile(files, tempdir, extra_defs)
        except self.M4FreezeFileError as e:
            # We failed to generate the freeze file, abort
            self.log.error("%s", e.msg)
            macros = None
        else:
            # Parse each file, using the freeze file
            macros = {}
            for single_file in files:
                # Find the appropriate parser
                parser = self.__get_parser__(single_file)
                if parser:
                    # We have a parser for this file
                    self.log.debug("Parsing macros from \"%s\" with plugin "
                                   "\"%s\"", single_file, parser.__name__)
                    f_macros = self.__parse_file__(
                        single_file, parser, tempdir, m4_freeze_file)
                    if f_macros:
                        # Update the global macro dictionary
                        macros.update(f_macros)
                else:
                    # We don't have a parser for this file
                    self.log.debug("No parser for \"%s\"", single_file)

        finally:
            # Necessary to empty the directory
            del m4_freeze_file
            # Try to remove the temporary directory
            try:
                os.rmdir(tempdir)
            except OSError:
                self.log.debug("Trying to remove the temporary directory "
                               "\"%s\"... failed!", tempdir)
            else:
                self.log.debug("Trying to remove the temporary directory "
                               "\"%s\"... done!", tempdir)
        return macros
