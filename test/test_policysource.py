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
"""Tests for all functions defined in the policy module"""

import unittest
import policysource.policy as p
import policysource.macro as m
import global_parameters as gbp
import logging


class TestPolicy(unittest.TestCase):
    """Test the SourcePolicy class"""

    def setUp(self):
        logging.basicConfig(level=logging.CRITICAL)
        self.policy_files = gbp.MACROFILES + gbp.POLICYFILES
        #self.policy = p.SourcePolicy(gbp.BASE_DIR, self.policy_files)

    def tearDown(self):
        self.policy_files = None

    @unittest.skip("Skipping test, test files not suitable")
    def test___find_macro_files__(self):
        """Test that all files containing macro definitions are found."""
        joined_files = gbp.join_files(gbp.BASE_DIR, self.policy_files)
        files = p.SourcePolicy.__find_macro_files__(joined_files)
        expected_files = gbp.join_files(
            gbp.BASE_DIR, gbp.MACROFILES)
        self.assertItemsEqual(files, expected_files)

    def test_constructor(self):
        """Test the behaviour of the SourcePolicy constructor"""
        # Invalid usages
        with self.assertRaises(RuntimeError):
            policy = p.SourcePolicy(None, None)
        with self.assertRaises(RuntimeError):
            policy = p.SourcePolicy(None, [])
        with self.assertRaises(RuntimeError):
            policy = p.SourcePolicy("", None)
        with self.assertRaises(RuntimeError):
            policy = p.SourcePolicy("", [])
        with self.assertRaises(RuntimeError):
            policy = p.SourcePolicy(None, self.policy_files)
        with self.assertRaises(RuntimeError):
            policy = p.SourcePolicy("", self.policy_files)
        with self.assertRaises(RuntimeError):
            policy = p.SourcePolicy(gbp.BASE_DIR, None)
        with self.assertRaises(RuntimeError):
            policy = p.SourcePolicy(gbp.BASE_DIR, [])

    @unittest.skip("Skipping test, test files not suitable")
    def test_macro_defs(self):
        """Test that all macros are expanded as expected."""
        macros = self.policy.macro_defs
        self.assertIsNotNone(macros)
        expected_macros = {}
        f_global = gbp.join_files(gbp.BASE_DIR, ["global_macros"])[0]
        f_te = gbp.join_files(gbp.BASE_DIR, ["te_macros"])[0]
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
        tmp = m.M4Macro("rw_file_perms", "{ r_file_perms w_file_perms }",
                        f_global)
        expected_macros["rw_file_perms"] = tmp
        # rwx_file_perms
        tmp = m.M4Macro("rwx_file_perms", "{ rw_file_perms x_file_perms }",
                        f_global)
        expected_macros["rwx_file_perms"] = tmp
        # create_file_perms
        tmp = m.M4Macro("create_file_perms",
                        "{ create rename setattr unlink rw_file_perms }",
                        f_global)
        expected_macros["create_file_perms"] = tmp
        # domain_trans(olddomain, type, newdomain)
        tmp = m.M4Macro("domain_trans", """
# Old domain may exec the file and transition to the new domain.
allow @@ARG0@@ @@ARG1@@:file { getattr open read execute };
allow @@ARG0@@ @@ARG2@@:process transition;
# New domain is entered by executing the file.
allow @@ARG2@@ @@ARG1@@:file { entrypoint open read execute getattr };
# New domain can send SIGCHLD to its caller.
allow @@ARG2@@ @@ARG0@@:process sigchld;
# Enable AT_SECURE, i.e. libc secure mode.
dontaudit @@ARG0@@ @@ARG2@@:process noatsecure;
# XXX dontaudit candidate but requires further study.
allow @@ARG0@@ @@ARG2@@:process { siginh rlimitinh };
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
allow @@ARG0@@ @@ARG1@@:file { getattr open read execute };
allow @@ARG0@@ @@ARG2@@:process transition;
# New domain is entered by executing the file.
allow @@ARG2@@ @@ARG1@@:file { entrypoint open read execute getattr };
# New domain can send SIGCHLD to its caller.
allow @@ARG2@@ @@ARG0@@:process sigchld;
# Enable AT_SECURE, i.e. libc secure mode.
dontaudit @@ARG0@@ @@ARG2@@:process noatsecure;
# XXX dontaudit candidate but requires further study.
allow @@ARG0@@ @@ARG2@@:process { siginh rlimitinh };

# Make the transition occur by default.
type_transition @@ARG0@@ @@ARG1@@:process @@ARG2@@;
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
type @@ARG0@@_tmpfs, file_type;
type_transition @@ARG0@@ tmpfs:file @@ARG0@@_tmpfs;
allow @@ARG0@@ @@ARG0@@_tmpfs:file { read write };
""",
                        f_te, ["domain"], [
                            "# tmpfs_domain(domain)",
                            "# Define and allow access to a unique type for",
                            "# this domain when creating tmpfs / shmem / ashmem files."])
        expected_macros["tmpfs_domain"] = tmp
        # Finally test
        self.assertEqual(len(macros), len(expected_macros))
        self.assertEqual(macros.keys(), expected_macros.keys())
        self.assertEqual(macros.values(), expected_macros.values())
        # If you need to know more in detail, you can use m4_dict_diff():
        # msg = m4_dict_diff(expected_macros, macros)
        # if msg:
        #     self.maxDiff = None
        #     self.fail(msg)

    @unittest.skip("Skipping test, test files not suitable")
    def test_macro_usages(self):
        """Test that all macro usages are found"""
        macro_usages = self.policy.macro_usages
        self.assertIsNotNone(macro_usages)
        macros = self.policy.macro_defs
        f_rules = gbp.join_files(gbp.BASE_DIR, ["rules.te"])[0]
        expected_usages = []
        # Line 1
        tmp = m.MacroInPolicy(macros, f_rules, 1, "domain_auto_trans",
                              ["adbd", "shell_exec", "shell"])
        expected_usages.append(tmp)
        # Line 2
        tmp = m.MacroInPolicy(macros, f_rules, 2,
                              "tmpfs_domain", ["somedomain"])
        expected_usages.append(tmp)
        # Line 4
        tmp = m.MacroInPolicy(macros, f_rules, 4, "rw_file_perms")
        expected_usages.append(tmp)
        # Line 5
        tmp = m.MacroInPolicy(macros, f_rules, 5, "r_file_perms")
        expected_usages.append(tmp)
        # Line 6
        tmp = m.MacroInPolicy(macros, f_rules, 6, "x_file_perms")
        expected_usages.append(tmp)
        # Line 7
        tmp = m.MacroInPolicy(macros, f_rules, 7, "w_file_perms")
        expected_usages.append(tmp)
        # Line 8
        tmp = m.MacroInPolicy(macros, f_rules, 8, "rx_file_perms")
        expected_usages.append(tmp)
        # Line 9
        tmp = m.MacroInPolicy(macros, f_rules, 9, "ra_file_perms")
        expected_usages.append(tmp)
        # Line 10
        tmp = m.MacroInPolicy(macros, f_rules, 10, "rw_file_perms")
        expected_usages.append(tmp)
        # Line 11
        tmp = m.MacroInPolicy(macros, f_rules, 11, "rwx_file_perms")
        expected_usages.append(tmp)
        # Line 12
        tmp = m.MacroInPolicy(macros, f_rules, 12, "create_file_perms")
        expected_usages.append(tmp)
        # Finally test
        self.assertEqual(len(expected_usages), len(macro_usages))
        self.maxDiff = None
        self.assertEqual(expected_usages, macro_usages)
