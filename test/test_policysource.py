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
"""Tests for all functions defined in the policysource module"""

import unittest
import policysource.policy as p
import policysource.macro as m
import policysource.macro_plugins as macro_plugins
import global_parameters as gbp
import logging


class TestPolicy(unittest.TestCase):

    def setUp(self):
        logging.basicConfig()
        self.policy_files = []
        self.policy_files.extend(gbp.MACROFILES_GLOBAL)
        self.policy_files.extend(gbp.POLICYFILES_GLOBAL)

    def tearDown(self):
        pass

    def test_find_macro_files(self):
        """Test that all files containing macro definitions are found."""
        files = p.find_macro_files(gbp.BASE_DIR_GLOBAL, self.policy_files)
        expected_files = gbp.join_files(
            gbp.BASE_DIR_GLOBAL, gbp.MACROFILES_GLOBAL)
        self.assertItemsEqual(files, expected_files)

    def test_expand_macros(self):
        """Test that all macros are expanded as expected."""
        macros = p.expand_macros(gbp.BASE_DIR_GLOBAL, self.policy_files)
        expected_macros = {}
        f_global = next(
            x for x in self.policy_files if x.endswith("global_macros"))
        f_te = next(x for x in self.policy_files if x.endswith("te_macros"))
        # x_file_perms
        tmp = m.M4Macro("x_file_perms",
                      "{ getattr execute execute_no_trans }", f_global)
        expected_macros["x_file_perms"] = tmp
        # r_file_perms
        tmp = m.M4Macro("r_file_perms",
                      "{ getattr open read ioctl lock }", f_global)
        expected_macros["r_file_perms"] = tmp
        # w_file_perms
        tmp = m.M4Macro("w_file_perms", "{ open append write }", f_global)
        expected_macros["w_file_perms"] = tmp
        # rx_file_perms
        tmp = m.M4Macro("rx_file_perms",
                      "{ r_file_perms x_file_perms }", f_global)
        expected_macros["rx_file_perms"] = tmp
        # ra_file_perms
        tmp = m.M4Macro("ra_file_perms", "{ r_file_perms append }", f_global)
        expected_macros["ra_file_perms"] = tmp
        # rw_file_perms
        tmp = m.M4Macro("rw_file_perms",
                      "{ r_file_perms w_file_perms }", f_global)
        expected_macros["rw_file_perms"] = tmp
        # rwx_file_perms
        tmp = m.M4Macro("rwx_file_perms",
                      "{ rw_file_perms x_file_perms }", f_global)
        expected_macros["rwx_file_perms"] = tmp
        # create_file_perms
        tmp = m.M4Macro("create_file_perms",
                      "{ create rename setattr unlink rw_file_perms }", f_global)
        expected_macros["create_file_perms"] = tmp
        # domain_trans(olddomain, type, newdomain)
        tmp = m.M4Macro("domain_trans", """
# Old domain may exec the file and transition to the new domain.
allow olddomain type:file { getattr open read execute };
allow olddomain newdomain:process transition;
# New domain is entered by executing the file.
allow newdomain type:file { entrypoint open read execute getattr };
# New domain can send SIGCHLD to its caller.
allow newdomain olddomain:process sigchld;
# Enable AT_SECURE, i.e. libc secure mode.
dontaudit olddomain newdomain:process noatsecure;
# XXX dontaudit candidate but requires further study.
allow olddomain newdomain:process { siginh rlimitinh };

""",
                      f_te, ["olddomain", "type", "newdomain"], [
                          "# domain_trans(olddomain, type, newdomain)",
                          "# Allow a transition from olddomain to newdomain",
                          "# upon executing a file labeled with type.",
                          "# This only allows the transition; it does not",
                          "# cause it to occur automatically - use domain_auto_trans",
                          "# if that is what you want.",
                          "#",
                          "# Old domain may exec the file and transition to the new domain.",
                          "# New domain is entered by executing the file.",
                          "# New domain can send SIGCHLD to its caller.",
                          "# Enable AT_SECURE, i.e. libc secure mode.",
                          "# XXX dontaudit candidate but requires further study."])
        expected_macros["domain_trans"] = tmp
        # domain_auto_trans(olddomain, type, newdomain)
        tmp = m.M4Macro("domain_auto_trans", """
# Allow the necessary permissions.

# Old domain may exec the file and transition to the new domain.
allow olddomain type:file { getattr open read execute };
allow olddomain newdomain:process transition;
# New domain is entered by executing the file.
allow newdomain type:file { entrypoint open read execute getattr };
# New domain can send SIGCHLD to its caller.
allow newdomain olddomain:process sigchld;
# Enable AT_SECURE, i.e. libc secure mode.
dontaudit olddomain newdomain:process noatsecure;
# XXX dontaudit candidate but requires further study.
allow olddomain newdomain:process { siginh rlimitinh };

# Make the transition occur by default.
type_transition olddomain type:process newdomain;

""",
                      f_te, ["olddomain", "type", "newdomain"], [
                          "# domain_auto_trans(olddomain, type, newdomain)",
                          "# Automatically transition from olddomain to newdomain",
                          "# upon executing a file labeled with type.",
                          "#",
                          "# Allow the necessary permissions.",
                          "# Make the transition occur by default."])
        expected_macros["domain_auto_trans"] = tmp
        # tmpfs_domain(domain)
        tmp = m.M4Macro("tmpfs_domain", """
type domain_tmpfs, file_type;
type_transition domain tmpfs:file domain_tmpfs;
allow domain domain_tmpfs:file { read write };

""",
                      f_te, ["domain"], [
                          "# Define and allow access to a unique type for",
                          "# this domain when creating tmpfs / shmem / ashmem files."])
        expected_macros["tmpfs_domain"] = tmp
        # Finally test
        self.assertItemsEqual(macros, expected_macros)
