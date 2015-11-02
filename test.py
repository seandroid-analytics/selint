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

import os
from os import path
import policysource
from policysource import policy

def test_expand_macros():
    print "Starting test \"expand_macros()\"..."
    macros = policysource.policy.expand_macros(policysource.policy.base_dir_global, policysource.policy.policyfiles_global)
    for key, value in macros.iteritems():
        print os.path.basename(value.file_defined) + ":\t" + str(value)
        print "\n".join(value.comments)
        print value.expand()
        print "\n"
    print "Macros: {}".format(len(macros))
    print "Finished test \"expand_macros()\".\n"

def main():
    test_expand_macros()

if __name__ == "__main__":
    main()
