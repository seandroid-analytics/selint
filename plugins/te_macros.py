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
import time
import policysource
import policysource.policy
import policysource.mapping
import policysource.macro
import setools
from setools.terulequery import TERuleQuery as TERuleQuery

# Do not make suggestions on rules coming from files in these paths
#
# e.g. to ignore AOSP:
# RULE_IGNORE_PATHS = ["external/sepolicy"]
RULE_IGNORE_PATHS = []  # ["external/sepolicy"]

# Do not try to reconstruct these macros
MACRO_IGNORE = ["recovery_only", "non_system_app_set", "userdebug_or_eng",
                "print", "permissive_or_unconfined", "userfastboot_only",
                "notuserfastboot", "eng"]

# Only suggest macros that match above this threshold [0-1]
SUGGESTION_THRESHOLD = 0.8

##############################################################################
################# Do not edit configuration below this line ##################
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
            LOG.debug(e)
            LOG.debug("Could not expand rule \"%s\"", r)
        else:
            expansionlist.extend(xpn.values())
    return expansionlist


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
    "allow domain dir_type:dir { search read ioctl write getattr open
                                 add_name };",
    "allow domain file_type:dir { rename search setattr read create reparent
                                  ioctl write getattr rmdir remove_name open
                                  add_name };",
    "allow ...    ...      : ..."]
    """
    # The return dictionary
    retdict = {}
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
    """Suggest usages of te_macrosi where appropriate."""
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

    # Generate a dictionary of te_macros grouped by number of arguments
    global TE_MACROS_BY_NARG
    TE_MACROS_BY_NARG = {}
    for m in policy.macro_defs.values():
        if m.file_defined.endswith("te_macros") and m.name not in MACRO_IGNORE:
            # m is a te_macro, add
            if m.nargs in TE_MACROS_BY_NARG:
                TE_MACROS_BY_NARG[m.nargs].append(m)
            else:
                TE_MACROS_BY_NARG[m.nargs] = [m]

    # Suggestions: {frozenset(filelines): [suggestions]}
    suggestions = {}

    expansions = {}
    total_rules = 0
    total_masks = 0
    start = time.time()
    # Only consider te_macros not purposefully ignored
    selected_macros = [x for x in policy.macro_defs.values() if
                       x.file_defined.endswith("te_macros") and not
                       x.name in MACRO_IGNORE]
    for k, m in enumerate(selected_macros, start=1):
        print "Processing \"{}\" ({}/{})...".format(m, k, len(selected_macros))
        # Generate numbered placeholder arguments
        args = []
        for i in xrange(m.nargs):
            args.append("@@ARG{}@@".format(i))
        # Expand the macro using the placeholder arguments
        exp_regex = m.expand(args)
        rules = {}
        rules_to_suggest = []
        # Get the Rule objects contained in the macro expansion
        for l in exp_regex.splitlines():
            l = l.strip()
            # If this is a supported rule (not a comment, not a type def...)
            if l.startswith(policysource.mapping.ONLY_MAP_RULES):
                try:
                    # Substitute the positional placeholder arguments with a
                    # regex matching valid argument characters
                    l_r = re.sub(r"@@ARG[0-9]+@@", VALID_ARG_R, l)
                    # Generate the rule object corresponding to the rule with
                    # regex arguments
                    tmp = MAPPER.rule_factory(l_r)
                except ValueError as e:
                    LOG.debug(e)
                    LOG.debug("Could not expand rule \"%s\"", l)
                else:
                    if tmp.rtype in policysource.mapping.AVRULES:
                        # Handle class and permission sets
                        # For each class in the class set (len >= 1)
                        for c in MAPPER.expand_block(tmp.tclass, "class"):
                            # Compute the permission set for the class
                            permset = set(MAPPER.expand_block(tmp.perms,
                                                              "perms",
                                                              for_class=c))
                            # Compute the permission string from the set
                            if len(permset) > 1:
                                perms = "{ " + ", ".join(sorted(permset)) +\
                                    " }"
                            else:
                                perms = list(permset)[0]
                            # Calculate the new placeholder string
                            i = l.index(":") + 1
                            nl = l[:i] + c + " " + perms + ";"
                            # Save the new placeholder string to initialize
                            # MacroSuggestions
                            rules_to_suggest.append(nl)
                            # Add the rule to the dict of rules resulting from
                            # the macro expansion. This is inexact, because we
                            # are changing the effective number of rules by
                            # multiplexing the class sets; however, doing so
                            # allows us to escape countless problems and obtain
                            # more meaningful results.
                            rules[nl] = policysource.mapping.AVRule(
                                [tmp.rtype, tmp.source, tmp.target, c, perms])
                    elif tmp.rtype in policysource.mapping.TERULES:
                        # Handle class sets
                        # For each class in the class set (len >= 1)
                        blocks = MAPPER.get_rule_blocks(l)
                        for c in MAPPER.expand_block(tmp.tclass, "class"):
                            # Calculate the new placeholder string
                            i = l.index(":") + 1
                            nl = l[:i] + c + " " + blocks[4]
                            if len(blocks) == 6:
                                nl += " " + blocks[5]
                            nl += ";"
                            # Save the new placeholder string to initialize
                            # MacroSuggestions
                            rules_to_suggest.append(nl)
                            # Add the rule to the dict of rules resulting from
                            # the macro expansion. This is inexact, because we
                            # are changing the effective number of rules by
                            # multiplexing the class sets; however, doing so
                            # allows us to escape countless problems and obtain
                            # more meaningful results.
                            if tmp.is_name_trans:
                                rules[nl] = policysource.mapping.TERule(
                                    [tmp.rtype, tmp.source, tmp.target, c,
                                        tmp.deftype, tmp.objname])
                            else:
                                rules[nl] = policysource.mapping.TERule(
                                    [tmp.rtype, tmp.source, tmp.target, c,
                                        tmp.deftype])
        # Initialise a MacroSuggestion object for this macro with the
        # previously saved list of supported rules with positional placeholders
        ms = MacroSuggestion(m, rules_to_suggest)
        macro_suggestions = set([ms])

        # Query the policy with regexes
        total_masks += len(rules)
        for l, r in rules.iteritems():
            # Reset self
            self_target = False
            # Set whether a query parameter is a regex or a string
            sr = r"[a-zA-Z0-9_-]+" in r.source
            tr = r"[a-zA-Z0-9_-]+" in r.target
            cr = r"[a-zA-Z0-9_-]+" in r.tclass
            # Handle self
            if r.target == "self":
                self_target = True
                xtarget = r"[a-zA-Z0-9_-]+"
                tr = True
            else:
                xtarget = r.target
            # Query for an AV rule
            if r.rtype in policysource.mapping.AVRULES:
                query = TERuleQuery(policy=policy.policy, ruletype=[r.rtype],
                                    source=r.source, source_regex=sr,
                                    target=xtarget, target_regex=tr,
                                    tclass=[r.tclass], tclass_regex=cr,
                                    perms=r.permset, perms_subset=True)
            # Query for a TE rule
            elif r.rtype in policysource.mapping.TERULES:
                dr = r"[a-zA-Z0-9_-]+" in r.deftype
                query = TERuleQuery(policy=policy.policy, ruletype=[r.rtype],
                                    source=r.source, source_regex=sr,
                                    target=xtarget, target_regex=tr,
                                    tclass=[r.tclass], tclass_regex=cr,
                                    default=r.deftype, default_regex=dr)
            else:
                # We should have no other rules, as they are already filtered
                # when creating the list with the rule_factory method
                LOG.warning("Unsupported rule: \"%s\"", r)
                continue
            # Filter all rules
            if self_target:
                # Discard rules whose mask contained "self" as a target,
                # but whose result's source and target are different
                results = [x for x in query.results() if x.source == x.target]
            else:
                results = list(query.results())
            # print "Results:"
            # print "\n".join([str(x) for x in results])
            # print
            # Try to fill macro suggestions
            for res in results:
                newsugs = []
                for sug in macro_suggestions:
                    try:
                        sug.add_rule(str(res))
                    except ValueError as e:
                        LOG.debug(e)
                        LOG.debug("Mismatching rule: \"%s\"", res)
                        newsug = sug.fork_and_fit(str(res))
                        if newsug:
                            newsugs.append(newsug)
                    except RuntimeError as e:
                        # We should not get here: if we did, this rule did
                        # not match any rule in the macro
                        break
                if newsugs:
                    macro_suggestions.update(newsugs)
        # Discard suggestions whose score is too low
        macro_suggestions = [
            x for x in macro_suggestions if x.score >= SUGGESTION_THRESHOLD]
        part = time.time() - start
        print "Time spent on \"{}\": {}s".format(m, part)
        print "Number of suggestions: {}".format(len(macro_suggestions))
        print "\n".join([str(x) for x in macro_suggestions])
        print
    end = time.time()
    elapsed = end - start
    print "Time spent expanding macros: {}s".format(elapsed)
    print "Avg time/macro: {}s".format(elapsed / float(len(selected_macros)))
    print "Total queries: {}".format(total_masks)

    sys.exit(0)
    # Analyse each possible usage suggestions and assign it a score indicating
    # how well the suggested expansion fits in the existing set of rules.
    # If the score is sufficiently high, suggest using the macro.
    for possible_usage, expansion in expansions.iteritems():
        # Skip empty expansions
        if not expansion:
            continue
        # Gather the macro name and args from the string representation
        # i = policysource.macro.MacroInPolicy.parse_usage(possible_usage)
        # name = i[0]
        # args = set(i[1])
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


class MacroSuggestion(object):
    """A macro suggestion with an associated score.

    Represents a macro expansion as a list of rules.
    The score expresses the number of rules actually found in the policy."""

    def __init__(self, macro, placeholder_rules):
        self._macro = macro
        self._placeholder_rules = placeholder_rules
        self._extractors = {}
        for r in self._placeholder_rules:
            self._extractors[r] = ArgExtractor(r)
        self._rules = {}
        self._args = {}
        self._score = 0

    def add_rule(self, rule):
        """Mark a rule in the macro expansion as found in the policy."""
        already_taken = ""
        for r, e in self._extractors.iteritems():
            # If the supplied rule matches one of the rules in the macro,
            # and that rule "slot" is not already taken by another rule
            if r in self.rules:
                already_taken = self.rules[r]
                continue
            try:
                # Get the arguments
                args = e.extract(rule)
            except ValueError as e:
                continue
            else:
                # If there are any conflicting arguments, don't add this rule
                # i.e. arguments in the same position but with different values
                for a in args:
                    if a in self.args and args[a] != self.args[a]:
                        raise ValueError("Mismatching arguments: expected "
                                         "\"{}\", found \"{}\".".format(
                                             self.args[a], args[a]))
                # Add the new rule, associated with the corresponding
                # placeholder rule
                self.rules[r] = rule
                # Update the args dictionary
                self.args.update(args)
                # Update the score. The score is given by:
                # Ratio of successfully matched rules
                # *
                # Ratio of determined arguments
                # This way, a macro suggestion which does not provide the whole
                # set of args is penalised
                score = len(self.rules) / float(len(self._placeholder_rules))
                score *= len(self.args) / float(self.macro.nargs)
                self._score = score
                return
        # If we found a rule that matched, but was already taken, and then
        # found no suitable rule
        if already_taken:
            raise ValueError(
                "Slot already taken by \"{}\"!".format(already_taken))
        else:
            # If we got here, we found no matching rule
            raise RuntimeError("Invalid rule.")

    def fork_and_fit(self, rule):
        """Fork the current state of the macro suggestion, and modify it to fit
        a new rule which would not normally fit because of mismatching args.
        Remove the rule(s) that prevent it from fitting.

        Returns a new MacroSuggestion object, or None if the macro does not
        contain the rule."""
        # Create a new macro suggestion object for the same macro
        new = MacroSuggestion(self.macro, self.placeholder_rules)
        # Add the mismatching rule first
        try:
            new.add_rule(rule)
        except RuntimeError:
            # The macro does not contain this rule: no point in adding it
            return None
        # Try to add the old rules
        # The old rules are compatible between themselves by definition, since
        # they came from an accepted state of a macro suggestion. Therefore,
        # the order does not matter when adding them back: if adding a rule
        # fails, it does not impact the overall set of rules.
        for r in self.rules.values():
            try:
                new.add_rule(r)
            except ValueError as e:
                # TODO: log?
                pass
        return new

    @property
    def macro(self):
        """Get the M4Macro object relative to the macro being suggested."""
        return self._macro

    @property
    def placeholder_rules(self):
        """Get the list of valid rules contained in the macro expansion with
        numbered placeholder arguments."""
        return self._placeholder_rules

    @property
    def args(self):
        """Get the suggestion arguments.

        Returns a dictionary {positional name: value}, e.g.:
        args =  {"arg1": "mydomain", "arg2": "mytype"}
        """
        return self._args

    @property
    def rules(self):
        """Get the list of valid rules contained in the macro expansion with
        the suggestion arguments."""
        return self._rules

    @property
    def score(self):
        """Get the suggestion score [0,1].

        The score is given by:
        Ratio of successfully matched rules * Ratio of determined arguments
        This way, a macro suggestion which does not provide the whole set of
        args is penalised."""
        return self._score

    def __eq__(self, other):
        """Check whether this suggestion is a duplicate of another."""
        return self.rules == other.rules

    def __ne__(self, other):
        return self.rules != other.rules

    def __lt__(self, other):
        return set(self.rules) < set(other.rules)

    def __le__(self, other):
        return set(self.rules) <= set(other.rules)

    def __gt__(self, other):
        return set(self.rules) > set(other.rules)

    def __ge__(self, other):
        return set(self.rules) >= set(other.rules)

    def __repr__(self):
        return self.usage + ": " + str(self.score)

    def __hash__(self):
        return hash(str(self))

    @property
    def usage(self):
        """Get the suggested usage as a string."""
        usage = self.macro.name + "("
        for i in xrange(self.macro.nargs):
            argn = "arg" + str(i)
            if argn in self.args:
                usage += self.args[argn] + ", "
            else:
                usage += "<MISSING_ARG>, "
        return usage.rstrip(", ") + ")"


class ArgExtractor(object):
    """Extract macro arguments from an expanded rule according to a regex."""
    placeholder_r = r"@@ARG[0-9]+@@"

    def __init__(self, rule):
        """Initialise the ArgExtractor with the rule expanded with the named
        placeholders.

        e.g.: "allow @@ARG0@@ @@ARG0@@_tmpfs:file execute;"
        """
        self.rule = rule
        # Convert the rule to a regex that matches it and extracts the groups
        self.regex = re.sub(self.placeholder_r,
                            "(" + VALID_ARG_R + ")", self.rule)
        self.regex_blocks = policysource.mapping.Mapper.rule_parser(self.regex)
        # Save the argument names as "argN"
        self.args = [x.strip("@").lower()
                     for x in re.findall(self.placeholder_r, self.rule)]

    def extract(self, rule):
        """Extract the named arguments from a matching rule."""
        matches = self.match_rule(rule)
        retdict = {}
        if matches:
            # The rule matches the regex: extract the matches
            for i in xrange(len(matches)):
                # Handle multiple occurrences of the same argument in a rule
                # If the occurrences don't all have the same value, this rule
                # does not actually match the placeholder rule
                if self.args[i] in retdict:
                    # If we have found this argument already
                    if retdict[self.args[i]] != matches[i]:
                        # If the value we just found is different
                        # The rule does not actually match the regex
                        raise ValueError("Rule does not match ArgExtractor"
                                         "expression: \"{}\"".format(
                                             self.regex))
                else:
                    retdict[self.args[i]] = matches[i]
            return retdict
        else:
            # The rule does not match the regex
            raise ValueError("Rule does not match ArgExtractor expression: "
                             "\"{}\"".format(self.regex))

    def match_rule(self, rule):
        """Perform a rich comparison between the provided rule and the rule
        expected by the extractor.

        Return True if the rule satisfies (at least) all constraints imposed
        by the extractor."""
        matches = []
        try:
            # Parse the rule into blocks
            rule_blocks = policysource.mapping.Mapper.rule_parser(rule)
        except ValueError as e:
            # Malformed rule
            # TODO: log?
            return None
        else:
            # Shorter name -> shorter lines
            regex_blocks = self.regex_blocks
            # Match the rule block by block
            # Pre-check on the number of blocks
            if len(rule_blocks) != len(regex_blocks):
                return None
            ##################### Match block 0 (rtype) ######################
            # No macro arguments here, no regex match
            if rule_blocks[0] != regex_blocks[0]:
                return None
            ##################################################################
            ##################### Match block 1 (source) #####################
            if VALID_ARG_R in regex_blocks[1]:
                # The domain contains an argument, match the regex
                m = re.match(regex_blocks[1], rule_blocks[1])
                if m:
                    matches.append(m.group(1))
                else:
                    return None
            else:
                # The domain contains no argument, match the string
                if rule_blocks[1] != regex_blocks[1]:
                    return None
            ##################################################################
            ##################### Match block 2 (target) #####################
            if VALID_ARG_R in regex_blocks[2]:
                # The type contains an argument, match the regex
                m = re.match(regex_blocks[2], rule_blocks[2])
                if m:
                    matches.append(m.group(1))
                else:
                    return None
            else:
                # The type contains no argument, match the string
                if regex_blocks[2] == "self":
                    # Handle "self"
                    if rule_blocks[2] != rule_blocks[1]:
                        return None
                elif rule_blocks[2] != regex_blocks[2]:
                    return None
            ##################################################################
            ##################### Match block 3 (tclass) #####################
            if VALID_ARG_R in regex_blocks[3]:
                # The class contains an argument, match the regex
                # This should never happen, however
                m = re.match(regex_blocks[3], rule_blocks[3])
                if m:
                    matches.append(m.group(1))
                else:
                    return None
            else:
                # The class contains no argument
                if any(x in rule_blocks[3] for x in "{}"):
                    # This rule contains a class set
                    # Match a (super)set of what is required by the regex
                    rule_classes = set(rule_blocks[3].strip("{}").split())
                    if any(x in regex_blocks[3] for x in "{}"):
                        regex_classes = set(
                            regex_blocks[3].strip("{}").split())
                    else:
                        regex_classes = set([regex_blocks[3]])
                    if rule_classes < regex_classes:
                        # If the classes in the rule are not at least those in
                        # the regex
                        return None
                elif rule_blocks[3] != regex_blocks[3]:
                    # Simple class, match the string
                    return None
            ##################################################################
            ##################### Match block 4 (variable) ###################
            if rule_blocks[0] in policysource.mapping.AVRULES:
                ################ Match an AV rule ################
                # Block 4 is the permission set
                if any(x in rule_blocks[4] for x in "{}"):
                    # This rule contains a permission set
                    # Match a (super)set of what is required by the regex
                    rule_perms = set(rule_blocks[4].strip("{}").split())
                    if any(x in regex_blocks[4] for x in "{}"):
                        regex_perms = set(regex_blocks[4].strip("{}").split())
                    else:
                        regex_perms = set([regex_blocks[4]])
                    if rule_perms < regex_perms:
                        # If the perms in the rule are not at least those in
                        # the regex
                        return None
                elif rule_blocks[4] != regex_blocks[4]:
                    # Simple permission, match the string
                    return None
                ##################################################
            elif rule_blocks[0] == "type_transition":
                ################ Match a type_transition rule #################
                # Block 4 is the default type
                if VALID_ARG_R in regex_blocks[4]:
                    # The default type contains an argument, match the regex
                    m = re.match(regex_blocks[4], rule_blocks[4])
                    if m:
                        matches.append(m.group(1))
                    else:
                        return None
                else:
                    # The default type contains no argument, match the string
                    if rule_blocks[4] != regex_blocks[4]:
                        return None
                ##################################################
            ##################################################################
            ##################### Match block 5 (name trans) #################
            if rule_blocks[0] == "type_transition" and len(rule_blocks) == 6:
                # If this type transition has 6 fields, it is a name transition
                # Block 5 is the object name
                if VALID_ARG_R in regex_blocks[5]:
                    # The object name contains an argument, match the regex
                    m = re.match(regex_blocks[5], rule_blocks[5])
                    if m:
                        matches.append(m.group(1))
                    else:
                        return None
                else:
                    # The object name contains no argument, match the string
                    if rule_blocks[5] != regex_blocks[5]:
                        return None
            ##################################################################
            ######################## All blocks match ########################
            return matches
