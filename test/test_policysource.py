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
import global_parameters as gbp
import logging
import difflib
import copy


def macro_deep_print(macro):
    print "#############################################################"
    print "Macro: \"{}\"".format(macro)
    print "Name:  \"{}\"".format(macro.name)
    print "Expansion:"
    print "{}".format(macro.expand())
    print "File defined: \"{}\"".format(macro.file_defined)
    print "Arguments: " + '"{0}"'.format('", "'.join(macro.args))
    print "Comments:"
    print "\n".join(macro.comments)


def macro_diff(m1, m2):
    d = difflib.Differ()
    if not m1 or not m2:
        return None
    if m1 == m2:
        return ""
    else:
        diff = "--- m2: {}\n+++ m1: {}".format(m2, m1)
    # Compare names
    if m1.name != m2.name:
        diff += "\n@@ Name @@"
        diff += "\n-{}\n+{}".format(m1.name, m2.name)
    # Compare the expansions
    if m1.expand() != m2.expand():
        diff += "\n@@ Expansion @@"
        e1 = m1.expand().splitlines()
        e2 = m2.expand().splitlines()
        for l in list(d.compare(e1, e2)):
            diff += "\n{}".format(l)
    # Compare definition files
    if m1.file_defined != m2.file_defined:
        diff += "\n@@ File defined @@"
        diff += "\n-\"{}\"\n+\"{}\"".format(m1.file_defined, m2.file_defined)
    # Compare arguments
    if m1.nargs != m2.nargs or str(m1) != str(m2):
        diff += "\n@@ Arguments @@"
        for l in list(d.compare(m1.args, m2.args)):
            diff += "\n{}".format(l)
    # Compare comments
    if (len(m1.comments) != len(m2.comments)
            or "".join(m1.comments) != "".join(m2.comments)):
        diff += "\n@@ Comments @@"
        for l in list(d.compare(m1.comments, m2.comments)):
            diff += "\n{}".format(l)
    diff += "\n"
    return diff


class TestM4Macro(unittest.TestCase):

    def setUp(self):
        # Full valid macro
        self.name = "some_macro"
        expansion = "{expansion with arguments @@ARG0@@ and @@ARG1@@}"
        self.expand = "{expansion with arguments arg0 and arg1}"
        self.file_defined = "some_file"
        self.args = ["arg0", "arg1"]
        self.comments = ["# Some comment lines which are",
                         "# totally unnecessary"]

        self.macro = m.M4Macro(self.name, expansion, self.file_defined,
                               self.args, self.comments)

    def tearDown(self):
        self.name = None
        self.expand = None
        self.file_defined = None
        self.args = None
        self.comments = None

    def test_constructor(self):
        """Test the behaviour of the M4Macro constructor"""
        # Invalid macro
        with self.assertRaises(m.M4MacroError):
            m.M4Macro("", "", "")
        with self.assertRaises(m.M4MacroError):
            m.M4Macro("name", "exp", "file", None, None)
        with self.assertRaises(m.M4MacroError):
            m.M4Macro(None, "", "")
        with self.assertRaises(m.M4MacroError):
            m.M4Macro("", None, "")
        with self.assertRaises(m.M4MacroError):
            m.M4Macro("", "", None)
        with self.assertRaises(m.M4MacroError):
            m.M4Macro(None, None, None)
        self.assertIsInstance(self.macro, m.M4Macro)

    def test_name(self):
        self.assertEqual(self.macro.name, self.name)

    def test_expand(self):
        self.assertEqual(self.macro.expand(), self.expand)

    def test_file_defined(self):
        self.assertEqual(self.macro.file_defined, self.file_defined)

    def test_nargs(self):
        self.assertEqual(self.macro.nargs, len(self.args))

    def test_args(self):
        self.assertEqual(self.macro.args, self.args)

    def test_comments(self):
        self.assertEqual(self.macro.comments, self.comments)

    def test___repr__(self):
        representation = self.name + "(" + ", ".join(self.args) + ")"
        self.assertEqual(str(self.macro), representation)

    def test___eq__(self):
        other = copy.deepcopy(self.macro)
        self.assertEqual(self.macro, other)

    def test___ne__(self):
        other = copy.deepcopy(self.macro)
        other._file_defined = "some_other_file"
        self.assertNotEqual(self.macro, other)


class TestMacroInPolicy(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    # TODO: implement following a similar structure to TestM4Macro


class TestPolicy(unittest.TestCase):

    def setUp(self):
        logging.basicConfig()
        self.policy_files = []
        self.policy_files.extend(gbp.MACROFILES)
        self.policy_files.extend(gbp.POLICYFILES)

    def tearDown(self):
        self.policy_files = None

    def test_find_macro_files(self):
        """Test that all files containing macro definitions are found."""
        files = p.find_macro_files(gbp.BASE_DIR, self.policy_files)
        expected_files = gbp.join_files(
            gbp.BASE_DIR, gbp.MACROFILES)
        self.assertItemsEqual(files, expected_files)

    def test_expand_macros(self):
        """Test that all macros are expanded as expected."""
        macros = p.expand_macros(gbp.BASE_DIR, self.policy_files)
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
                            "# tmpfs_domain(domain)",
                            "# Define and allow access to a unique type for",
                            "# this domain when creating tmpfs / shmem / ashmem files."])
        expected_macros["tmpfs_domain"] = tmp
        # Finally test
        self.assertEqual(len(macros), len(expected_macros))
        self.assertItemsEqual(macros.keys(), expected_macros.keys())
        missing = []
        differing = []
        for mname in expected_macros.keys():
            if not macros[mname]:
                missing.append(mname)
            else:
                if macros[mname] != expected_macros[mname]:
                    differing.append(
                        macro_diff(macros[mname], expected_macros[mname]))
        msg = ""
        if missing:
            msg += "\n{} macros are missing:\n".format(len(missing))
            msg += "\n".join(missing)
        if differing:
            msg += "\n"
            msg += "\n".join(differing)
            msg += "\n"
            msg += "{} macros differ".format(len(differing))
        if msg:
            self.maxDiff = None
            self.fail(msg)

    def test_find_macros(self):
        """Test that all macro usages are found"""
        # TODO: write
        pass
