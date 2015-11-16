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
"""TODO: file docstring"""

import unittest
import policysource.policy as p
import policysource.macro as m
import global_parameters as gbp
import logging
import difflib
import copy


def m4_macro_deep_print(macro):
    print "#############################################################"
    print "Macro: \"{}\"".format(macro)
    print "Name:  \"{}\"".format(macro.name)
    print "Expansion:"
    print "{}".format(macro.expand())
    print "File defined: \"{}\"".format(macro.file_defined)
    print "Arguments: " + '"{0}"'.format('", "'.join(macro.args))
    print "Comments:"
    print "\n".join(macro.comments)


def m4_macro_diff(m1, m2):
    """Print the diff between macros m1 and m2, i.e. m2 - m1"""
    d = difflib.Differ()
    if not m2 or not m1:
        return None
    if m2 == m1:
        return ""
    else:
        diff = "--- m1: {0}\n+++ m2: {1}".format(m1, m2)
    # Compare names
    if m2.name != m1.name:
        diff += "\n@@ Name @@"
        diff += "\n-{}\n+{}".format(m1.name, m2.name)
    # Compare the expansions
    if m2.expand() != m1.expand():
        diff += "\n@@ Expansion @@"
        e2 = m2.expand().splitlines()
        e1 = m1.expand().splitlines()
        for l in list(d.compare(e2, e1)):
            diff += "\n{}".format(l)
    # Compare definition files
    if m2.file_defined != m1.file_defined:
        diff += "\n@@ File defined @@"
        for l in list(d.compare([m2.file_defined], [m1.file_defined])):
            diff += "\n{}".format(l)
    # Compare arguments
    if m2.nargs != m1.nargs or str(m2) != str(m1):
        diff += "\n@@ Arguments @@"
        for l in list(d.compare(m2.args, m1.args)):
            diff += "\n{}".format(l)
    # Compare comments
    if (len(m2.comments) != len(m1.comments)
            or "".join(m2.comments) != "".join(m1.comments)):
        diff += "\n@@ Comments @@"
        for l in list(d.compare(m2.comments, m1.comments)):
            diff += "\n{}".format(l)
    diff += "\n"
    return diff


def m4_dict_diff(d1, d2):
    """Print the diff between dictionaries d1 and d2, i.e. d2 - d1"""
    missing = []
    extra = []
    differing = []
    for mname in d1.keys():
        if not d2[mname]:
            missing.append(mname)
        else:
            if d2[mname] != d1[mname]:
                differing.append(m4_macro_diff(d1[mname], d2[mname]))
    for mname in d2.keys():
        if not d1[mname]:
            extra.append(mname)
    msg = ""
    if missing:
        msg += "\n{} macros are missing:\n".format(len(missing))
        msg += "\n".join(missing)
    if extra:
        msg += "\n{} macros are extra:\n".format(len(extra))
        msg += "\n".join(extra)
    if differing:
        msg += "\n"
        msg += "\n".join(differing)
        msg += "\n"
        msg += "{} macros differ".format(len(differing))
    return msg


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

        self.macro_no_args = m.M4Macro(self.name, self.expand,
                                       self.file_defined)
        self.macro_with_args = m.M4Macro(self.name, expansion,
                                         self.file_defined,
                                         self.args, self.comments)

    def tearDown(self):
        self.name = None
        self.expand = None
        self.file_defined = None
        self.args = None
        self.comments = None
        self.macro_no_args = None
        self.macro_with_args = None

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
        # Valid macro
        self.assertIsInstance(self.macro_no_args, m.M4Macro)
        self.assertIsInstance(self.macro_with_args, m.M4Macro)

    def test_name(self):
        self.assertTrue(hasattr(self.macro_with_args, "name"))
        self.assertTrue(hasattr(self.macro_no_args, "name"))
        self.assertEqual(self.macro_with_args.name, self.name)
        self.assertEqual(self.macro_no_args.name, self.name)

    def test_expand(self):
        self.assertTrue(hasattr(self.macro_with_args, "expand"))
        self.assertTrue(hasattr(self.macro_no_args, "expand"))
        self.assertEqual(self.macro_with_args.expand(), self.expand)
        self.assertEqual(self.macro_no_args.expand(), self.expand)

    def test_file_defined(self):
        self.assertTrue(hasattr(self.macro_with_args, "file_defined"))
        self.assertTrue(hasattr(self.macro_no_args, "file_defined"))
        self.assertEqual(self.macro_with_args.file_defined, self.file_defined)
        self.assertEqual(self.macro_no_args.file_defined, self.file_defined)

    def test_nargs(self):
        self.assertTrue(hasattr(self.macro_with_args, "nargs"))
        self.assertTrue(hasattr(self.macro_no_args, "nargs"))
        self.assertEqual(self.macro_with_args.nargs, len(self.args))
        self.assertEqual(self.macro_no_args.nargs, 0)

    def test_args(self):
        self.assertTrue(hasattr(self.macro_with_args, "args"))
        self.assertTrue(hasattr(self.macro_no_args, "args"))
        self.assertEqual(self.macro_with_args.args, self.args)
        self.assertEqual(self.macro_no_args.args, [])

    def test_comments(self):
        self.assertTrue(hasattr(self.macro_with_args, "comments"))
        self.assertTrue(hasattr(self.macro_no_args, "comments"))
        self.assertEqual(self.macro_with_args.comments, self.comments)
        self.assertEqual(self.macro_no_args.comments, [])

    def test___repr__(self):
        representation_with_args = self.name + "(" + ", ".join(self.args) + ")"
        self.assertEqual(str(self.macro_with_args), representation_with_args)
        self.assertEqual(str(self.macro_no_args), self.name)

    def test___eq__(self):
        other_with_args = copy.deepcopy(self.macro_with_args)
        other_no_args = copy.deepcopy(self.macro_no_args)
        self.assertEqual(self.macro_with_args, other_with_args)
        self.assertEqual(self.macro_no_args, other_no_args)

    def test___ne__(self):
        other_with_args = copy.deepcopy(self.macro_with_args)
        other_no_args = copy.deepcopy(self.macro_no_args)
        other_with_args._file_defined = "some_other_file"
        other_no_args._file_defined = "some_other_file"
        self.assertNotEqual(self.macro_with_args, other_with_args)
        self.assertNotEqual(self.macro_no_args, other_no_args)


class TestMacroInPolicy(unittest.TestCase):

    def setUp(self):
        self.macros = {}
        # Create the necessary M4Macro with arguments
        self.name = "some_macro"
        expansion = "{expansion with arguments @@ARG0@@ and @@ARG1@@}"
        expand_defined = "{expansion with arguments arg0 and arg1}"
        self.expansion_used = "{expansion with arguments the first and the second}"
        file_defined = "some_file"
        self.args_defined = ["arg0", "arg1"]
        comments = ["# Some comment lines which are",
                    "# totally unnecessary"]
        self.macros[self.name] = m.M4Macro(self.name, expansion, file_defined,
                                           self.args_defined, comments)
        # Create the necessary M4Macro without arguments
        self.name2 = "other_macro"
        self.expansion2 = "{expansion}"
        file_defined2 = "some_file"
        self.macros[self.name2] = m.M4Macro(self.name2, self.expansion2,
                                            file_defined2)
        # Create the "invalid" invalid macro
        self.macros["invalid"] = None
        # Create the MacroInPolicy object with arguments
        self.file_used = "some_file.te"
        self.line_used = 5
        self.args_used = ["the first", "the second"]
        self.macro_usage_with_args = m.MacroInPolicy(self.macros,
                                                     self.file_used,
                                                     self.line_used, self.name,
                                                     self.args_used)
        # Create the MacroInPolicy object without arguments
        self.file_used2 = "some_file.te"
        self.line_used2 = 6
        self.macro_usage_no_args = m.MacroInPolicy(self.macros,
                                                   self.file_used2,
                                                   self.line_used2, self.name2)

    def tearDown(self):
        self.macros[self.name] = None
        self.macros[self.name2] = None
        self.macros = None
        self.name = None
        self.name2 = None
        self.expand_used = None
        self.expansion2 = None
        self.args_defined = None
        self.file_used = None
        self.file_used2 = None
        self.line_used = None
        self.line_used2 = None
        self.args_used = None
        self.macro_usage_with_args = None
        self.macro_usage_no_args = None

    def test_constructor(self):
        """Test the behaviour of the MacroInPolicy constructor"""
        # Invalid macros
        # Invalid macros dictionary
        with self.assertRaises(m.M4MacroError):
            m.MacroInPolicy(None, self.file_used, self.line_used, self.name,
                            self.args_used)
            # Invalid macro file_used
        with self.assertRaises(m.M4MacroError):
            m.MacroInPolicy(self.macros, None, self.line_used, self.name,
                            self.args_used)
            # Invalid macro line_used
        with self.assertRaises(m.M4MacroError):
            m.MacroInPolicy(self.macros, self.file_used, None, self.name,
                            self.args_used)
            # Invalid macro line_used (negative line number)
        with self.assertRaises(m.M4MacroError):
            m.MacroInPolicy(self.macros, self.file_used, -4, self.name,
                            self.args_used)
            # Invalid macro line_used (string)
        with self.assertRaises(m.M4MacroError):
            m.MacroInPolicy(self.macros, self.file_used, "4", self.name,
                            self.args_used)
            # Invalid macro name
        with self.assertRaises(m.M4MacroError):
            m.MacroInPolicy(self.macros, self.file_used, self.line_used,
                            None, self.args_used)
            # Invalid macro name
        with self.assertRaises(m.M4MacroError):
            m.MacroInPolicy(self.macros, self.file_used, self.line_used,
                            "", self.args_used)
            # Invalid macro arguments
        with self.assertRaises(m.M4MacroError):
            m.MacroInPolicy(self.macros, self.file_used, self.line_used,
                            self.name, None)
            # Invalid macro arguments (no args in usage, 2 args in definition)
        with self.assertRaises(m.M4MacroError):
            m.MacroInPolicy(self.macros, self.file_used, self.line_used,
                            self.name, [])
            # Invalid macro name (macro not in macros dictionary)
        with self.assertRaises(m.M4MacroError):
            m.MacroInPolicy(self.macros, self.file_used, self.line_used,
                            "missing", self.args_used)
            # Invalid macro name (dictionary value for key is None)
        with self.assertRaises(m.M4MacroError):
            m.MacroInPolicy(self.macros, self.file_used, self.line_used,
                            "invalid", self.args_used)
        # Valid macro
        self.assertIsInstance(self.macro_usage_with_args, m.MacroInPolicy)
        self.assertIsInstance(self.macro_usage_no_args, m.MacroInPolicy)

    def test_name(self):
        self.assertTrue(hasattr(self.macro_usage_with_args, "name"))
        self.assertTrue(hasattr(self.macro_usage_no_args, "name"))
        self.assertEqual(self.macro_usage_with_args.name, self.name)
        self.assertEqual(self.macro_usage_no_args.name, self.name2)

    def test_expansion(self):
        self.assertTrue(hasattr(self.macro_usage_with_args, "expansion"))
        self.assertTrue(hasattr(self.macro_usage_no_args, "expansion"))
        self.assertEqual(
            self.macro_usage_with_args.expansion, self.expansion_used)
        self.assertEqual(
            self.macro_usage_no_args.expansion, self.expansion2)

    def test_file_used(self):
        self.assertTrue(hasattr(self.macro_usage_with_args, "file_used"))
        self.assertTrue(hasattr(self.macro_usage_no_args, "file_used"))
        self.assertEqual(
            self.macro_usage_with_args.file_used, self.file_used)
        self.assertEqual(
            self.macro_usage_no_args.file_used, self.file_used2)

    def test_line_used(self):
        self.assertTrue(hasattr(self.macro_usage_with_args, "line_used"))
        self.assertTrue(hasattr(self.macro_usage_no_args, "line_used"))
        self.assertEqual(
            self.macro_usage_with_args.line_used, self.line_used)
        self.assertEqual(
            self.macro_usage_no_args.line_used, self.line_used2)

    def test_nargs(self):
        self.assertTrue(hasattr(self.macro_usage_with_args, "nargs"))
        self.assertTrue(hasattr(self.macro_usage_no_args, "nargs"))
        self.assertEqual(self.macro_usage_with_args.nargs,
                         len(self.args_defined))
        self.assertEqual(self.macro_usage_with_args.nargs,
                         len(self.args_used))
        self.assertEqual(self.macro_usage_no_args.nargs, 0)

    def test_args(self):
        self.assertTrue(hasattr(self.macro_usage_with_args, "args"))
        self.assertTrue(hasattr(self.macro_usage_no_args, "args"))
        self.assertEqual(self.macro_usage_with_args.args_descriptions,
                         self.args_defined)
        self.assertEqual(self.macro_usage_with_args.args, self.args_used)
        self.assertEqual(self.macro_usage_no_args.args, [])

    def test___repr__(self):
        representation = self.name +\
            "(" + ", ".join(self.args_used) + ")"
        self.assertEqual(str(self.macro_usage_with_args), representation)
        self.assertEqual(str(self.macro_usage_no_args), self.name2)

    def test___eq__(self):
        other_with_args = copy.deepcopy(self.macro_usage_with_args)
        other_no_args = copy.deepcopy(self.macro_usage_no_args)
        self.assertEqual(self.macro_usage_with_args, other_with_args)
        self.assertEqual(self.macro_usage_no_args, other_no_args)

    def test___ne__(self):
        other_with_args = copy.deepcopy(self.macro_usage_with_args)
        other_no_args = copy.deepcopy(self.macro_usage_no_args)
        other_with_args._file_used = "some_other_file"
        other_no_args._file_used = "some_other_file"
        self.assertNotEqual(self.macro_usage_with_args, other_with_args)
        self.assertNotEqual(self.macro_usage_no_args, other_no_args)
