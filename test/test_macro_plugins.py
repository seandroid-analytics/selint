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
import os.path
import logging

BASE_DIR_GLOBAL = "test/test_policy_files"
MACROFILES_GLOBAL = [
    "global_macros",
    "te_macros",
    "ioctl_macros"]
POLICYFILES_GLOBAL = [
    "rules.te"]
SUPPORTED_MACRO_FILES_GLOBAL = [
    "global_macros",
    "te_macros"]
EXISTING_PLUGINS_GLOBAL = [
    "global_macros",
    "te_macros"]
VALID_PLUGINS_GLOBAL = [
    "global_macros",
    "te_macros"]


class TestMacroPluginArchitecture(unittest.TestCase):

    def setUp(self):
        logging.basicConfig()
        self.parser = macro_plugins.M4MacroParser()

    def tearDown(self):
        self.parser = None

    def test_plugin_import(self):
        """Test that all plugins in the plugin directory are imported."""
        self.assertTrue(
            set(macro_plugins.__all__) == set(EXISTING_PLUGINS_GLOBAL))

    def test_valid_plugins(self):
        """Test that all valid plugins are loaded by the parser."""
        self.assertTrue(
            set(self.parser.expects()) == set(VALID_PLUGINS_GLOBAL))

    def test_parse(self):
        """Test that the parser correctly parses the supplied test files."""
        files = [os.path.join(os.path.expanduser(BASE_DIR_GLOBAL), x)
                 for x in MACROFILES_GLOBAL if x]
        macros = self.parser.parse(files)
        expected_macros = ["x_file_perms", "r_file_perms", "w_file_perms",
                           "rx_file_perms", "ra_file_perms", "rw_file_perms",
                           "rwx_file_perms", "create_file_perms",
                           "domain_trans", "domain_auto_trans", "tmpfs_domain"]
        self.assertFalse(macros is None)
        self.assertTrue(set(macros.keys()) == set(expected_macros))

#suite = unittest.TestLoader().loadTestsFromTestCase(TestMacroPluginArchitecture)
