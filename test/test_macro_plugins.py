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
"""Tests for all functions defined in the macro_plugins module"""

import unittest
from policysource import macro_plugins as macro_plugins
import os
import os.path
from tempfile import mkdtemp
from subprocess import check_call, CalledProcessError
import logging
import global_parameters as gbp


class TestMacroPluginArchitecture(unittest.TestCase):
    """Test the M4Macro parser class."""

    def setUp(self):
        logging.basicConfig()
        self.parser = macro_plugins.M4MacroParser()

    def tearDown(self):
        self.parser = None

    def test_plugin_import(self):
        """Test that all plugins in the plugin directory are imported."""
        self.assertItemsEqual(macro_plugins.__all__,
                              gbp.EXISTING_PLUGINS)

    def test_valid_plugins(self):
        """Test that all valid plugins are loaded by the parser."""
        self.assertItemsEqual(self.parser.expects(), gbp.VALID_PLUGINS)

    def test_parse(self):
        """Test that the parser correctly parses the supplied test files."""
        files = gbp.join_files(gbp.BASE_DIR, gbp.MACROFILES)
        macros = self.parser.parse(files)
        expected_macros = ["x_file_perms", "r_file_perms", "w_file_perms",
                           "rx_file_perms", "ra_file_perms", "rw_file_perms",
                           "rwx_file_perms", "create_file_perms",
                           "domain_trans", "domain_auto_trans", "tmpfs_domain"]
        self.assertIsNotNone(macros)
        self.assertItemsEqual(macros.keys(), expected_macros)


class TestMacroPlugin(unittest.TestCase):
    """Test the plugin parser modules"""

    def setUp(self):
        logging.basicConfig()
        self.parser = macro_plugins.M4MacroParser()
        self.tempdir = mkdtemp()
        self.m4_freeze_file = os.path.join(self.tempdir, "freezefile")
        self.files = gbp.join_files(gbp.BASE_DIR, gbp.MACROFILES)
        try:
            # Generate the m4 freeze file with all macro definitions
            command = ["m4", "-D", "mls_num_sens=1", "-D", "mls_num_cats=1024",
                       "-D", "target_build_variant=eng", "-s"]
            command.extend(self.files)
            command.extend(["-F", self.m4_freeze_file])
            with open(os.devnull, "w") as devnull:
                check_call(command, stdout=devnull)
        except CalledProcessError as e:
            # We failed to generate the freeze file, abort
            self.fail(e.msg)

    def tearDown(self):
        os.remove(self.m4_freeze_file)
        os.rmdir(self.tempdir)

    def test_global_macros_expects(self):
        """Test whether the plugin expects the correct file"""
        f = next(x for x in self.files if x.endswith("global_macros"))
        self.assertTrue(self.parser.plugins["global_macros"].expects(f))

    def test_global_macros_parse(self):
        """Test whether the plugin parses correctly"""
        f = next(x for x in self.files if x.endswith("global_macros"))
        macros = self.parser.plugins["global_macros"].parse(
            f, self.tempdir, self.m4_freeze_file)
        expected_macros = ["x_file_perms", "r_file_perms", "w_file_perms",
                           "rx_file_perms", "ra_file_perms", "rw_file_perms",
                           "rwx_file_perms", "create_file_perms"]
        self.assertIsNotNone(macros)
        self.assertItemsEqual(macros.keys(), expected_macros)

    def test_te_macros_expects(self):
        """Test whether the plugin expects the correct file"""
        f = next(x for x in self.files if x.endswith("te_macros"))
        self.assertTrue(self.parser.plugins["te_macros"].expects(f))

    def test_te_macros_parse(self):
        """Test whether the plugin parses correctly"""
        f = next(x for x in self.files if x.endswith("te_macros"))
        macros = self.parser.plugins["te_macros"].parse(
            f, self.tempdir, self.m4_freeze_file)
        expected_macros = ["domain_trans", "domain_auto_trans", "tmpfs_domain"]
        self.assertIsNotNone(macros)
        self.assertItemsEqual(macros.keys(), expected_macros)
