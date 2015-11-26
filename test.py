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

import policysource.policy as p
import policysource.mapping as mp
import logging
import sys
import shutil


def test_source_policy():
    pol = p.SourcePolicy(p.BASE_DIR_GLOBAL, p.POLICYFILES_GLOBAL)
    if len(pol.macro_defs) != 61:
        print "Some macro definitions were not recognized!"
        print "Definitions recognized: {}".format(len(pol.macro_defs))
        return False
    if len(pol.macro_usages) != 1103:
        print "Some macro usages were not recognized!"
        print "Usages recognized: {}".format(len(pol.macro_usages))
        return False
    shutil.copyfile(pol._policyconf, "/home/bonazzf1/tmp/policy.conf")
    nallow = 0
    nauditallow = 0
    ndontaudit = 0
    nneverallow = 0
    ntypetrans = 0
    touched = set()
    #mapped = open("mapped.txt", "w")
    #notmapped = open("notmapped.txt", "w")
    for rule in pol.policy.terules():
        printedr = "{0.ruletype} {0.source} {0.target}:{0.tclass}".format(rule)
        if printedr in pol.mapping:
            touched.add(printedr)
            #mapped.write(str(rule) + "\n")
            # for tpl in pol.mapping[printedr]:
            #    mapped.write("\t{} {}:{}\n".format(tpl[0], tpl[1], tpl[2]))
            if rule.ruletype == "allow":
                nallow += 1
            if rule.ruletype == "auditallow":
                nauditallow += 1
            if rule.ruletype == "dontaudit":
                ndontaudit += 1
            if rule.ruletype == "neverallow":
                nneverallow += 1
            if rule.ruletype == "type_transition":
                ntypetrans += 1
        else:
            #notmapped.write(printedr + "\n")
            pass
    # mapped.close()
    # notmapped.close()
    nmapped_allow = 0
    nmapped_auditallow = 0
    nmapped_dontaudit = 0
    nmapped_neverallow = 0
    nmapped_typetrans = 0
    #nottouched = open("nottouched.txt", "w")
    for rule_name, rule in pol.mapping.iteritems():
        if rule_name.startswith("allow"):
            nmapped_allow += 1
        if rule_name.startswith("auditallow"):
            nmapped_auditallow += 1
        if rule_name.startswith("dontaudit"):
            nmapped_dontaudit += 1
        if rule_name.startswith("neverallow"):
            nmapped_neverallow += 1
        if rule_name.startswith("type_transition"):
            nmapped_typetrans += 1
        # if rule_name not in touched:
        #    nottouched.write("{} ".format(rule_name))
        #    for i in rule:
        #        nottouched.write("{}:{}\n".format(i[0], i[1]))
    # nottouched.close()
    print "{0}/{1} rules in mapping found".format(nallow + nauditallow +
                                                  ndontaudit + nneverallow +
                                                  ntypetrans, len(pol.mapping))
    print "Allow: {0}/{1}/{2}".format(
        nallow, pol.policy.allow_count, nmapped_allow)
    print "Auditallow: {0}/{1}/{2}".format(
        nauditallow, pol.policy.auditallow_count, nmapped_auditallow)
    print "Dontaudit: {0}/{1}/{2}".format(
        ndontaudit, pol.policy.dontaudit_count, nmapped_dontaudit)
    print "Neverallow: {0}/{1}/{2}".format(
        nneverallow, pol.policy.neverallow_count, nmapped_neverallow)
    print "Type transition: {0}/{1}/{2}".format(
        ntypetrans, pol.policy.type_transition_count, nmapped_typetrans)
    return True


def main():
    logging.basicConfig()  # level=logging.DEBUG)  # , format='%(message)s')
    if not test_source_policy():
        sys.exit(1)


if __name__ == "__main__":
    main()
