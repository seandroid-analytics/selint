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
import os
import os.path
import policysource
import policysource.policy

# Do not make suggestions on rules coming from files in these paths
#
# e.g. to ignore AOSP:
# RULE_IGNORE_PATHS = ["external/sepolicy"]
RULE_IGNORE_PATHS = ["external/sepolicy"]

# Do not try to reconstruct these macros
MACRO_IGNORE = ["recovery_only", "non_system_app_set",
                "userdebug_or_eng", "eng", "print"]

# Only suggest macros that match above this threshold [0-1]
SUGGESTION_THRESHOLD = 1

##############################################################################
####################### Do not touch below this line #########################
##############################################################################
# Global variable to hold the te_macros M4Macro objects
TE_MACROS_BY_NARG = None

# Global variable to hold the log
LOG = None


def expand_macros(policy, arg1, arg2=None, arg3=None):
    """Expand all te_macros that match the number of supplied arguments.

    Return a dictionary of macros {text:[rules]} where [rules] is a list of
    rules obtained by expanding all the rules found in the macro expansion
    taking into account attributes, permission sets etc.

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
    # Create a mapper to expand the rules
    mapper = policysource.mapping.Mapper(
        policy.policyconf, policy.attributes, policy.types, policy.classes)
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
        # Split in lines
        m4expansion = m.splitlines()
        # Strip whitespace from every line
        m4expansion = [x.strip() for x in m4expansion]
        # Remove blank lines and comments
        m4expansion = [x for x in m4expansion if x and not x.startswith("#")]
        expansion = []
        for r in m4expansion:
            # Expand the attributes, sets etc. in each rule
            try:
                xpn = mapper.expand_rule(r)
            # TODO: fix logging properly by e.g. splitting in functions
            except ValueError as e:
                LOG.warning("Could not expand rule \"%s\"", r)
                expansion.append(r)
            else:
                expansion.extend(xpn.values())
        retdict[m_name] = expansion
    return retdict


def main(policy, config):
    # Check that we have been fed a valid policy
    if not isinstance(policy, policysource.policy.SourcePolicy):
        raise ValueError("Invalid policy")
    # Setup logging
    log = logging.getLogger(__name__)
    global LOG
    LOG = log

    # Compute the absolute ignore paths
    FULL_BASE_DIR = os.path.abspath(os.path.expanduser(config.BASE_DIR_GLOBAL))
    FULL_IGNORE_PATHS = tuple(os.path.join(FULL_BASE_DIR, p)
                              for p in RULE_IGNORE_PATHS)

    # Suggestions: {frozenset(filelines): [suggestions]}
    suggestions = {}

    # Prepare macro usages dictionary with macros grouped by name
    macrousages_dict = {}
    for m in policy.macro_usages:
        if m.macro.file_defined.endswith("te_macros"):
            if m.name in macrousages_dict:
                macrousages_dict[m.name].append(m)
            else:
                macrousages_dict[m.name] = [m]

    expansions = {}
    # Group rules by domain
    rules_by_domain = {}
    for r_up_to_class in policy.mapping:
        dmn = r_up_to_class.split()[1]
        if dmn in rules_by_domain:
            rules_by_domain[dmn].extend(policy.mapping[r_up_to_class])
        else:
            rules_by_domain[dmn] = list(policy.mapping[r_up_to_class])
    for dmn, rules in rules_by_domain.iteritems():
        types = [x.rule.replace(":", " ").split()[2] for x in rules]
        # Expand all single-argument macros with the domain as argument
        expansions.update(expand_macros(policy, dmn))
        # Expand all two-argument macros with domain, type as arguments
        for x in types:
            expansions.update(expand_macros(policy, dmn, x))
        # Expand all three-argument macros with domain, type, type as arguments
        for x in types:
            for y in types:
                expansions.update(expand_macros(policy, dmn, x, y))

    for possible_usage, expansion in expansions.iteritems():
        i = possible_usage.index("(")
        name = possible_usage[:i]
        args = set(x.strip()
                   for x in possible_usage[i:].strip("()").split(","))
        score = 0
        for r in expansion:
            r_up_to_class = r[:r.index(" ", r.index(":"))]
            if r_up_to_class in policy.mapping:
                score += 1
        score = score / float(len(expansion))
        if score == 1:
            suggest_this = True
            # Full match
            if name in macrousages_dict:
                for x in macrousages_dict[name]:
                    if set(x.args) == args:
                        suggest_this = False
                        break
            if suggest_this:
                # TODO: add to list of suggestion objects
                print "You could use {}".format(possible_usage)
        elif score >= SUGGESTION_THRESHOLD:
            # Partial match
            # TODO: add to list of partial suggestions
            pass
