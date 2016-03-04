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
import re
import policysource
import policysource.policy
import policysource.mapping
import setools

# Do not make suggestions on rules coming from files in these paths
#
# e.g. to ignore AOSP:
# RULE_IGNORE_PATHS = ["external/sepolicy"]
RULE_IGNORE_PATHS = []  # ["external/sepolicy"]

# Do not try to reconstruct these macros
MACRO_IGNORE = ["recovery_only", "non_system_app_set", "userdebug_or_eng",
                "eng", "print", "permissive_or_unconfined"]

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

# Regex for a valid argument in m4
VALID_ARG_R = r"[a-zA-Z0-9_-]+"


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
    # Compute expansions of single-argument macros
    # This is much faster than the second method
    for dmn in policy.attributes["domain"]:
        expansions.update(expand_macros(policy, dmn))
    # Bruteforcing multiple-argument macros would be too expensive.
    # Try a different approach
    total_rules = 0
    total_masks = 0
    for m in policy.macro_defs.values():
        # Skip single-argument macros, we have already covered them
        if m.nargs < 2:
            continue
        # Only consider te_macros not purposefully ignored
        if not m.file_defined.endswith("te_macros") or m.name in MACRO_IGNORE:
            continue
        args = []
        for i in xrange(m.nargs):
            # args.append("@@ARG{}@@".format(i))
            args.append(VALID_ARG_R)
        # Expand the macro using the placeholder arguments
        exp_regex = m.expand(args)
        rules = []
        # Get the Rule objects contained in the macro expansion
        for l in exp_regex.splitlines():
            # If this is a supported rule (not a comment, not a type def...)
            if l.startswith(policysource.mapping.ONLY_MAP_RULES):
                try:
                    tmp = MAPPER.rule_factory(l.strip())
                except ValueError as e:
                    LOG.debug(e)
                    LOG.debug("Could not expand rule \"%s\"", l)
                else:
                    rules.append(tmp)
        # Mark where the arguments go in the expansion
        # for r in rules:
        #    for a in args:
        #        if a in r.source:

        # Query the policy with regexes
        query_results_per_rule = {}
        total_masks += len(rules)
        for r in rules:
            # Reset self
            self_target = False

            print
            print r

            sr = r"[a-zA-Z0-9_-]+" in r.source
            tr = r"[a-zA-Z0-9_-]+" in r.target
            cr = r"[a-zA-Z0-9_-]+" in r.tclass
            # Handle class sets
            xtclass = MAPPER.expand_block(r.tclass, "class")
            # Handle self
            if r.target == "self":
                self_target = True
                xtarget = r"[a-zA-Z0-9_-]+"
                tr = True
            else:
                xtarget = r.target

            # Query for an AV rule
            if r.rtype in policysource.mapping.AVRULES:
                # Handle perms
                # This is a special permission block, expand it given the class
                # it applies to.
                if any(x in r.perms for x in "*~{}"):
                    if len(xtclass) > 1:
                        # If multiple classes are specified, this is a
                        # mistake and we can't do anything.
                        LOG.warning("Cannot compute permissions for rule: "
                                    "\"%s\"", r)
                        # Match a superset of an empty set - i.e. any perms
                        xperms = set()
                    else:
                        xperms = set(MAPPER.expand_block(
                            r.perms, "perms", for_class=xtclass[0]))
                else:
                    xperms = r.permset
                query = setools.terulequery.TERuleQuery(policy=policy.policy,
                                                        ruletype=[r.rtype],
                                                        source=r.source,
                                                        source_regex=sr,
                                                        target=xtarget,
                                                        target_regex=tr,
                                                        tclass=xtclass,
                                                        tclass_regex=cr,
                                                        perms=xperms,
                                                        perms_subset=True)
            # Query for a TE rule
            if r.rtype in policysource.mapping.TERULES:
                dr = r"[a-zA-Z0-9_-]+" in r.deftype
                query = setools.terulequery.TERuleQuery(policy=policy.policy,
                                                        ruletype=[r.rtype],
                                                        source=r.source,
                                                        source_regex=sr,
                                                        target=xtarget,
                                                        target_regex=tr,
                                                        tclass=xtclass,
                                                        tclass_regex=cr,
                                                        default=r.deftype,
                                                        default_regex=dr)
            # Filter all rules
            if self_target:
                results = [x for x in query.results() if x.source == x.target]
            else:
                results = list(query.results())
            # TODO: this doesn't go here, it may take away some valid rules
            # at this stage
            # results = [x for x in results if str(x) not in full_usages_list]
            # for rule in results:
            #    print rule
            # TODO: MARK
            print "Number of rules matching:"
            print len(results)
            total_rules += len(results)
            print "Number of distinct domains:"
            print len(set((x.source for x in results)))
            print "Number of distinct types:"
            print len(set((x.target for x in results)))

    print total_masks
    print total_rules
    sys.exit(0)
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


class MacroRecognizer(object):
    """Represents a generic argument macro expansion. Extracts the arguments
    from the regex-matching rules that are submitted to it."""

    def __init__(self, rules):
        self.rules = rules
        self.regexes = []
        for x in self.rules:
            pass


class ArgExtractor(object):
    """Extract macro arguments from an expanded rule according to a regex."""
    placeholder_r = r"@@ARG[0-9]+@@"

    def __init__(self, rule):
        """Initialise the ArgExtractor with the rule expanded with the named
        placeholders.

        e.g.: "allow @@ARG0@@ @@ARG3@@:notdevfile_class_set create_file_perms;"
        """
        self.rule = rule
        # Convert the rule to a regex that matches it and extracts the groups
        self.regex = re.sub(self.placeholder_r,
                            "(" + VALID_ARG_R + ")", self.rule)
        # Save the argument names as "argN"
        self.args = [x.strip("@").lower()
                     for x in re.findall(self.placeholder_r, self.rule)]

    def extract(self, rule):
        """Extract the named arguments from a matching rule."""
        match = re.match(self.regex, rule)
        retdict = {}
        if match:
            # The rule matches the regex: extract the matches
            groups = match.groups()
            for i in xrange(len(groups)):
                # Handle multiple occurrences of the same argument in a rule
                # If the occurrences don't all have the same value, this rule
                # does not actually match the placeholder rule
                if self.args[i] in retdict:
                    # If we have found this argument already
                    if retdict[self.args[i]] != groups[i]:
                        # If the value we just found is different
                        return None
                else:
                    retdict[self.args[i]] = groups[i]
            return retdict
        else:
            # The rule does not match the regex: why has it been passed in in
            # the first place?
            raise ValueError("Rule does not match ArgExtractor expression: "
                             "\"{}\"".format(self.regex))
