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
import subprocess
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

    def __init__(self):
        """Initialize plugin architecture.

        Find all plugins offered by macro_plugins, check that they implement
        the required methods and add them to the plugin dictionary."""
        # Setup logger
        self.log = logging.getLogger(self.__class__.__name__)

        self.plugins = {}
        for p in __all__:
            plugin = globals()[p]
            if (inspect.isfunction(plugin.expects)
                    and inspect.isfunction(plugin.parse)):
                self.plugins[p] = plugin
                self.log.debug("Found plugin \"%s\"", p)
            else:
                self.log.debug("Invalid plugin \"%s\"", p)

    def expects(self):
        """Returns a list of files that the parser can handle."""
        return self.plugins.keys()

    def parse(self, files):
        """Parses a list of files and returns a dictionary of macros."""
        macros = {}
        # Remove empty strings, normalize paths
        files = [os.path.abspath(x) for x in files if x]
        # Create a temporary work directory
        tempdir = mkdtemp()
        self.log.debug("Created temporary directory \"%s\".", tempdir)

        m4_freeze_file = os.path.join(tempdir, "freezefile")
        self.log.debug(
            "Trying to generate freeze file \"%s\"...", m4_freeze_file)
        try:
            # Generate the m4 freeze file with all macro definitions
            command = ["m4", "-D", "mls_num_sens=1", "-D", "mls_num_cats=1024",
                       "-D", "target_build_variant=eng", "-s"]
            command.extend(files)
            command.extend(["-F", m4_freeze_file])
            with open(os.devnull, "w") as devnull:
                subprocess.check_call(command, stdout=devnull)
        except CalledProcessError as e:
            self.log.error("%s", e.msg)
            self.log.error("Failed to generate freeze file \"%s\". "
                           "Macros cannot be expanded.", m4_freeze_file)
            # We failed to generate the freeze file, abort
            macros = None
        else:
            self.log.debug(
                "Successfully generated freeze file \"%s\".", m4_freeze_file)
            # Parse each file, using the freeze file
            for f in files:
                if os.path.basename(f) in self.plugins:
                    self.log.debug("Parsing macros from \"%s\" with plugin "
                                   "\"%s\"", f, os.path.basename(f))
                    # Find the appropriate parser
                    parser = self.plugins[os.path.basename(f)]
                    # Parse f with the appropriate parser
                    try:
                        f_macros = parser.parse(f, tempdir, m4_freeze_file)
                    except ValueError as e:
                        # This really should not happen
                        # Log and skip
                        self.log.warning("%s", e.msg)
                        self.log.warning("Could not parse \"%s\"", f)
                    else:
                        # Update the global macro dictionary
                        macros.update(f_macros)
                        self.log.debug("Parsed macros from \"%s\"", f)
                else:
                    # We don't have a parser for this file
                    self.log.debug("No parser for \"%s\"", f)
        finally:
            # Try to remove the freeze file
            try:
                os.remove(m4_freeze_file)
            except OSError:
                self.log.debug("Trying to remove the freeze file "
                               "\"%s\"... failed!", m4_freeze_file)
            else:
                self.log.debug("Trying to remove the freeze file "
                               "\"%s\"... done!", m4_freeze_file)
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
