#!/usr/bin/python2
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
"""Test various functions for correctness"""

import os.path
import policysource.policy as p
import policysource.macro as m
import logging
import sys
import copy


def test_expand_macros():
    print "Starting test \"expand_macros()\"..."
    macros = p.expand_macros(p.BASE_DIR_GLOBAL, p.POLICYFILES_GLOBAL)
    for key, value in macros.iteritems():
        print os.path.basename(value.file_defined) + ":\t" + str(value)
        print "\n".join(value.comments)
        print value.expand()
        print "\n"
    print "Macros: {}".format(len(macros))
    print "Finished test \"expand_macros()\".\n"


def test_find_macros():
    macros_in_policy = p.find_macros(p.BASE_DIR_GLOBAL, p.POLICYFILES_GLOBAL)
    if len(macros_in_policy) == 1099:
        print "PASSED test \"find_macros()\"."
        sys.exit(0)
    else:
        print "FAILED test \"find_macros()\"."
        sys.exit(1)


#    print "Starting test \"find_macros()\"..."
#    for m in macros_in_policy:
#        print m.file_used + ":{}\t".format(m.line_no) + str(m)
#        print m.expand()
#        print "\n%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
#    print "Macros: {}".format(len(macros_in_policy))
#    print "Finished test \"find_macros()\".\n"


def main():
    logging.basicConfig(level=logging.DEBUG)  # , format='%(message)s')
    # test_expand_macros()
    # return test_find_macros():
    m1 = m.M4Macro("x_file_perms",
                   "{ getattr execute execute_no_trans }", "global_macros")
    # TEST 0: Basic sanity check
    if m1 != m1:
        print "M4Macro.__eq__(self, other) is not correct."
    # TEST 1: Copying
    m2 = copy.deepcopy(m1)
    if m1 != m2:
        print "{} is a copy of {} but comparison failed!".format(m1, m2)
    # TEST 2
    m3 = m.M4Macro("x_file_perms",
                   "{ getattr execute execute_no_trans }", "global_macros")
    if m1 != m3:
        print "{} and {} should the same but comparison failed!".format(m1, m3)
    # TEST 3
    m4 = m.M4Macro("rw_file_perms",
                   "{ r_file_perms w_file_perms }", "global_macros")
    m5 = m.M4Macro("x_file_perms",
                   "{ getattr execute execute_no_trans }", "global_macros")
    if m4 == m5:
        print "{} and {} are different but comparison succeeded!".format(m4, m5)

    # TEST 4
    m6 = m.M4Macro("some_macro", "{ arg should be here @@ARG0@@ }",
                   "te_macros", ["some_argument"],
                   ["# some_macro(some_argument)", "#"])
    m7 = copy.deepcopy(m6)
    if m6 != m7:
        print "{} and {} should the same but comparison failed!".format(m6, m7)
    # TEST 5
    m8 = m.M4Macro("some_macro", "{ arg should be here @@ARG0@@ }",
                   "te_macros", ["some_argument"],
                   ["# some_macro(some_argument)", "#"])
    if m6 != m8:
        print "{} and {} should the same but comparison failed!".format(m6, m8)

if __name__ == "__main__":
    main()
