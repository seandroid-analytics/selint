#
# Written by Filippo Bonazzi
# Copyright (C) 2016 Aalto University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Plugin to analyse usage of TE macros and suggest new ones."""

import logging
import sys
import os
import os.path
import policysource
import policysource.policy
import policysource.mapping

# Do not make suggestions on rules coming from files in these paths
#
# e.g. to ignore AOSP:
# RULE_IGNORE_PATHS = ["external/sepolicy"]
RULE_IGNORE_PATHS = []  # ["external/sepolicy"]

# Do not try to reconstruct these macros
MACRO_IGNORE = ["recovery_only", "non_system_app_set",
                "userdebug_or_eng", "eng", "print"]

# Only suggest macros that match above this threshold [0-1]
SUGGESTION_THRESHOLD = 0.8

##############################################################################
####################### Do not touch below this line #########################
##############################################################################
# Global variable to hold the te_macros M4Macro objects
TE_MACROS_BY_NARG = None

# Global variable to hold the log
LOG = None

# Global variable to hold the mapper
MAPPER = None


def process_expansion(expansionstring):
    """Process a multiline macro expansion into a list of supported rules.

    The list contains AVRules and TErules objects from policysource.mapping .
    """
    # Split in lines
    m4expansion = expansionstring.splitlines()
    # Strip whitespace from every line
    m4expansion = [x.strip() for x in m4expansion]
    # Remove blank lines and comments
    m4expansion = [x for x in m4expansion if x and not x.startswith("#")]
    expansionlist = []
    for r in m4expansion:
        # Expand the attributes, sets etc. in each rule
        try:
            xpn = MAPPER.expand_rule(r)
        # TODO: fix logging properly by e.g. splitting in functions
        except ValueError as e:
            #LOG.debug("Could not expand rule \"%s\"", r)
            pass
        else:
            expansionlist.extend(xpn.values())
    return expansionlist


def expand_macros(policy, arg1, arg2=None, arg3=None):
    """Expand all te_macros that match the number of supplied arguments.

    Return a dictionary of macros {text:[rules]} where [rules] is a list of
    rules obtained by expanding all the rules found in the macro expansion
    taking into account attributes, permission sets etc.
    The list contains AVRule or TERule objects.

    e.g.:
    arg1 = "domain"
    arg2 = "dir_type"
    arg3 = "file_type"
    text = "file_type_trans(domain, dir_type, file_type)"
    [rules] = [
    "allow domain dir_type:dir { search read ioctl write getattr open add_name };",
    "allow domain file_type:dir { rename search setattr read create reparent ioctl write getattr rmdir remove_name open add_name };",
    "allow ...    ...      : ..."]
    """
    # The return dictionary
    retdict = {}
    # Generate a dictionary of te_macros grouped by number of arguments
    global TE_MACROS_BY_NARG
    if TE_MACROS_BY_NARG is None:
        TE_MACROS_BY_NARG = {}
        for m in policy.macro_defs.values():
            if m.file_defined.endswith("te_macros") and m.name not in MACRO_IGNORE:
                # m is a te_macro, add
                if m.nargs in TE_MACROS_BY_NARG:
                    TE_MACROS_BY_NARG[m.nargs].append(m)
                else:
                    TE_MACROS_BY_NARG[m.nargs] = [m]
    # Save the macro expansions
    expansions = {}
    # Expand all the macros that fit the number of supplied arguments
    # One argument
    if arg2 is None and arg3 is None:
        for m in TE_MACROS_BY_NARG[1]:
            text = m.name + "(" + arg1 + ")"
            expansions[text] = m.expand([arg1])
    # Two arguments
    if arg2 is not None and arg3 is None:
        for m in TE_MACROS_BY_NARG[2]:
            text = m.name + "(" + arg1 + ", " + arg2 + ")"
            expansions[text] = m.expand([arg1, arg2])
    # Three arguments
    if arg2 is not None and arg3 is not None:
        for m in TE_MACROS_BY_NARG[3]:
            text = m.name + "(" + arg1 + ", " + arg2 + ", " + arg3 + ")"
            expansions[text] = m.expand([arg1, arg2, arg3])
    # Expand all the macros
    for m_name, m in expansions.iteritems():
        retdict[m_name] = process_expansion(m)
    return retdict


def main(policy, config):
    # Check that we have been fed a valid policy
    if not isinstance(policy, policysource.policy.SourcePolicy):
        raise ValueError("Invalid policy")
    # Setup logging
    log = logging.getLogger(__name__)
    global LOG
    LOG = log

    # Create a global mapper to expand the rules
    global MAPPER
    MAPPER = policysource.mapping.Mapper(
        policy.policyconf, policy.attributes, policy.types, policy.classes)

    # Compute the absolute ignore paths
    FULL_BASE_DIR = os.path.abspath(os.path.expanduser(config.BASE_DIR_GLOBAL))
    FULL_IGNORE_PATHS = tuple(os.path.join(FULL_BASE_DIR, p)
                              for p in RULE_IGNORE_PATHS)

    # Suggestions: {frozenset(filelines): [suggestions]}
    suggestions = {}

    # Set of rules deriving from the expansion of all the recorded macro
    # usages
    full_usages_string = ""
    expanded_macrousages = set()

    # Prepare macro usages dictionary with macros grouped by name
    macrousages_dict = {}
    for m in policy.macro_usages:
        if m.macro.file_defined.endswith("te_macros") and\
                m.name not in MACRO_IGNORE:
            if m.name in macrousages_dict:
                macrousages_dict[m.name].append(m)
            else:
                macrousages_dict[m.name] = [m]
            # Prepare the string for expansion
            full_usages_string += str(m) + "\n"
    # Expand the string containing all macro usages
    full_usages_expansion = policy._expander.expand(full_usages_string)
    full_usages_list = process_expansion(full_usages_expansion)

    expansions = {}
    # Group rules by domain
    rules_by_domain = {}
    for dmn in policy.attributes["domain"]:
        rules_by_domain[dmn] = []
    for r_up_to_class in policy.mapping.rules:
        if r_up_to_class.startswith(policysource.mapping.AVRULES):
            dmn = r_up_to_class.split()[1]
            for d in rules_by_domain:
                # TODO: very crude, check that this does not introduce mistakes
                if dmn.startswith(d):
                    rules_by_domain[d].extend(
                        policy.mapping.rules[r_up_to_class])
    # print "Domains: {}".format(len(rules_by_domain))
    # print "\n".join(rules_by_domain.keys())
    # print "\n".join(policy.attributes["domain"])
    # print len(policy.attributes["domain"])
    # print "\n".join(policy.attributes["domain"])
    # print len(policy.types)
    # sys.exit(1)

    # Expand all macros with all possible arguments into the expansions dict
    for dmn, rules in rules_by_domain.iteritems():
        # TODO: change bruteforce into regex + query
        types = [x.rule.split()[2] for x in rules]
        # Handle the macros that expect the socket name without the tail
        #types.extend([x[:-7] for x in types if x.endswith("_socket")])
        # Expand all single-argument macros with the domain as argument
        expansions.update(expand_macros(policy, dmn))
        # Expand all two-argument macros with domain, type as arguments
        for x in types:
            expansions.update(expand_macros(policy, dmn, x))
        # Expand all three-argument macros with domain, type, type as arguments
        # for x in types:
        #    for y in types:
        #        expansions.update(expand_macros(policy, dmn, x, y))

    # Analyse each possible usage suggestions and assign it a score indicating
    # how well the suggested expansion fits in the existing set of rules.
    # If the score is sufficiently high, suggest using the macro.
    for possible_usage, expansion in expansions.iteritems():
        # Skip empty expansions
        if not expansion:
            continue
        # Gather the macro name and args from the string representation
        # TODO: unoptimal, consider ad-hoc structure
        i = possible_usage.index("(")
        name = possible_usage[:i]
        args = set(x.strip()
                   for x in possible_usage[i:].strip("()").split(","))
        # Compute the score for the macro suggestion
        score = 0
        # Save the existing rules that the macro suggestion matches exactly
        actual_rules = []
        missing_rules = []
        # For each rule in the macro
        for r in expansion:
            # If this rule does not come from one of the existing macros
            if r not in full_usages_list:
                # Compute the rule up to the class
                i = r.index(":")
                j = r.index(" ", i)
                rutc = r[:j]
                # If this actual rule is used in the policy
                if rutc in policy.mapping.rules and\
                        r in [x.rule for x in policy.mapping.rules[rutc]]:
                    # Get the MappedRule corresponding to this rule
                    rl = [x for x in policy.mapping.rules[rutc]
                          if x.rule == r][0]
                    # If this rule comes from an explictly ignored path, skip
                    if not rl.fileline.startswith(FULL_IGNORE_PATHS):
                        # Otherwise, this rule is a valid candidate
                        score += 1
                        actual_rules.append(rl)
                # If not, this rule is potentially missing
                else:
                    missing_rules.append(r)
        # Compute the overall score of the macro suggestion
        # ( Number of valid candidates / number of candidates )
        score = score / float(len(expansion))
        # If this is a perfect match
        if score == 1:
            # TODO: add to list of suggestion objects
            print "You could use \"{}\" in place of:".format(possible_usage)
            print "\n".join([str(x) for x in actual_rules])
            print
        elif score >= SUGGESTION_THRESHOLD:
            # Partial match
            # TODO: add to list of partial suggestions
            print "{}% of \"{}\" matches these lines:".format(score * 100,
                                                              possible_usage)
            print "\n".join([str(x) for x in actual_rules])
            print "{}% is missing:".format((1 - score) * 100)
            print "\n".join([str(x) for x in missing_rules])
            print
            continue
