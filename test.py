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
import logging
import sys


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
    logging.basicConfig(level=logging.DEBUG) #, format='%(message)s')
    # test_expand_macros()
    if test_find_macros():
        return True
    else:
        return False

if __name__ == "__main__":
    main()
