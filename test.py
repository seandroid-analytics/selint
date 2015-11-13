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

import setools
import setools.policyrep
import os.path
import policysource.policy as p
import policysource.macro as m
import logging
import sys
import copy
import subprocess
from tempfile import mkdtemp


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
        return 0
    else:
        print "FAILED test \"find_macros()\"."
        return 1


#    print "Starting test \"find_macros()\"..."
#    for m in macros_in_policy:
#        print m.file_used + ":{}\t".format(m.line_no) + str(m)
#        print m.expand()
#        print "\n%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
#    print "Macros: {}".format(len(macros_in_policy))
#    print "Finished test \"find_macros()\".\n"

def test_selinux_policy():
    tmpdir = mkdtemp()
    policy_files = p.join_policy_files(p.BASE_DIR_GLOBAL, p.POLICYFILES_GLOBAL)
    policy_conf = os.path.join(tmpdir, "policy.conf")
    command = ['m4']
    extra_defs = ['mls_num_sens=1', 'mls_num_cats=1024',
            'target_build_variant=eng']
    for definition in extra_defs:
        command.extend(["-D", definition])
    command.extend(['-s'])
    command.extend(policy_files)
    try:
        with open(policy_conf, "w") as policyconf:
            subprocess.check_call(command, stdout=policyconf)
    except subprocess.CalledProcessError as e:
        print e.msg
        raise e
    else:
        policy = setools.policyrep.SELinuxPolicy(policy_conf)

    os.remove(policy_conf)
    os.rmdir(tmpdir)


def main():
    logging.basicConfig(level=logging.DEBUG)  # , format='%(message)s')
    # test_expand_macros()
    #sys.exit(test_find_macros())
    test_selinux_policy()


if __name__ == "__main__":
    main()
