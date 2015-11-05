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
import subprocess
from subprocess import check_call, CalledProcessError
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


def join_files(basedir, files):
    return [os.path.join(os.path.expanduser(basedir), x) for x in files if x]


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
        files = join_files(BASE_DIR_GLOBAL, MACROFILES_GLOBAL)
        macros = self.parser.parse(files)
        expected_macros = ["x_file_perms", "r_file_perms", "w_file_perms",
                           "rx_file_perms", "ra_file_perms", "rw_file_perms",
                           "rwx_file_perms", "create_file_perms",
                           "domain_trans", "domain_auto_trans", "tmpfs_domain"]
        self.assertFalse(macros is None)
        self.assertItemsEqual(macros.keys(), expected_macros)


class TestMacroPlugin(unittest.TestCase):

    def setUp(self):
        logging.basicConfig()
        self.parser = macro_plugins.M4MacroParser()
        self.tempdir = mkdtemp()
        self.m4_freeze_file = os.path.join(self.tempdir, "freezefile")
        self.files = join_files(BASE_DIR_GLOBAL, MACROFILES_GLOBAL)
        try:
            # Generate the m4 freeze file with all macro definitions
            command = ["m4", "-D", "mls_num_sens=1", "-D", "mls_num_cats=1024",
                       "-D", "target_build_variant=eng", "-s"]
            command.extend(self.files)
            command.extend(["-F", self.m4_freeze_file])
            with open(os.devnull, "w") as devnull:
                subprocess.check_call(command, stdout=devnull)
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

    def test_te_macros_expects(self):
        """Test whether the plugin expects the correct file"""
        f = next(x for x in self.files if x.endswith("te_macros"))
        self.assertTrue(self.parser.plugins["te_macros"].expects(f))
