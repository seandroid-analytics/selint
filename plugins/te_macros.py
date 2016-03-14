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
from timeit import default_timer
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
RULE_IGNORE_PATHS = ["external/sepolicy"]

# Do not try to reconstruct these macros
MACRO_IGNORE = ["recovery_only", "non_system_app_set", "userdebug_or_eng",
                "print", "permissive_or_unconfined", "userfastboot_only",
                "notuserfastboot", "eng", "binder_service", "net_domain",
                "unconfined_domain", "bluetooth_domain"]
#                "domain_trans", "domain_auto_trans",
#                "file_type_trans", "file_type_auto_trans", "r_dir_file",
#                "init_daemon_domain"]

# Only suggest macros that match above this threshold [0-1]
SUGGESTION_THRESHOLD = 0.8

# Truncate large macro processing to save time
TRUNCATE_MACROS = False

# Do not suggest these usages
# WARNING: Be careful what you put in here.
USAGES_IGNORE = []

##############################################################################
################# Do not edit configuration below this line ##################
##############################################################################

# Global variable to hold the log
LOG = None

# Global variable to hold the mapper
MAPPER = None

# Global variable to hold the full ignored paths
FULL_IGNORE_PATHS = None

# Global variable to hold the supported non-ignored rules mapping
NON_IGNORED_MAPPING = {}

# Regex for a valid argument in m4
VALID_ARG_R = r"[a-zA-Z0-9_-]+"


def process_macro(m, mapper):
    """Create a list of rules and an initial MacroSuggestion object from a
    M4Macro object.
    The list contains valid, supported rules with the macro arguments
    substituted by regular expressions; these will be used to query the policy
    for rules matching a rule coming from a possible macro usage.

    Returns a list of rules and a set of MacroSuggestions.
    Arguments:
    m      - the M4Macro object representing the macro to be processed
    mapper - a Mapper object initialised with appropriate arguments from the
             SourcePolicy policy.
    """
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
                tmp = mapper.rule_factory(l_r)
            except ValueError as e:
                LOG.debug(e)
                LOG.debug("Could not expand rule \"%s\"", l)
            else:
                if tmp.rtype in policysource.mapping.AVRULES:
                    # Handle class and permission sets
                    # For each class in the class set (len >= 1)
                    for c in mapper.expand_block(tmp.tclass, "class"):
                        # Compute the permission set for the class
                        permset = set(mapper.expand_block(tmp.perms, "perms",
                                                          for_class=c))
                        # Compute the permission text block from the set
                        if len(permset) > 1:
                            permblk = "{ " + " ".join(sorted(permset)) + " }"
                        else:
                            permblk = list(permset)[0]
                        # Calculate the new placeholder string
                        i = l.index(":") + 1
                        nl = l[:i] + c + " " + permblk + ";"
                        # Save the new placeholder string to later initialize
                        # MacroSuggestions
                        rules_to_suggest.append(nl)
                        # Add the rule to the dict of rules resulting from the
                        # macro expansion. This is inexact, because we are
                        # changing the effective number of rules in a macro by
                        # multiplexing the class sets; however, doing so allows
                        # us to escape countless problems and obtain more
                        # meaningful results.
                        # This is also inefficient because it raises the number
                        # of queries that we are going to perform for each rule
                        # in the macro, from 1 to N where N is the cardinality
                        # of the class set.
                        rules[nl] = policysource.mapping.AVRule(
                            [tmp.rtype, tmp.source, tmp.target, c, permblk])
                elif tmp.rtype in policysource.mapping.TERULES:
                    # Handle class sets
                    blocks = mapper.get_rule_blocks(l)
                    # For each class in the class set (len >= 1)
                    for c in mapper.expand_block(tmp.tclass, "class"):
                        # Calculate the new placeholder string
                        i = l.index(":") + 1
                        nl = l[:i] + c + " " + blocks[4]
                        # If this is a name transition, block 5 contains the
                        # object name: add it to the new placeholder string.
                        if len(blocks) == 6:
                            nl += " " + blocks[5]
                        nl += ";"
                        # Save the new placeholder string to later initialize
                        # MacroSuggestions
                        rules_to_suggest.append(nl)
                        # Add the rule to the dict of rules resulting from
                        # the macro expansion. This is inexact, because we
                        # are changing the effective number of rules by
                        # multiplexing the class sets; however, doing so
                        # allows us to escape countless problems and obtain
                        # more meaningful results.
                        # This is also inefficient because it raises the number
                        # of queries that we are going to perform for each rule
                        # in the macro, from 1 to N where N is the cardinality
                        # of the class set.
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
    return (rules, macro_suggestions)


def query_for_rule(policy, r):
    """Query a policy for rules matching a given rule.
    The rule may contain regex fields."""
    global NON_IGNORED_MAPPING
    # Mark whether a query parameter is a regex or a string
    sr = r"[a-zA-Z0-9_-]+" in r.source
    tr = r"[a-zA-Z0-9_-]+" in r.target
    cr = r"[a-zA-Z0-9_-]+" in r.tclass
    # Handle self
    if r.target == "self":
        # Override the target to match everything
        xtarget = r"[a-zA-Z0-9_-]+"
        tr = True
    else:
        xtarget = r.target
    # Query for an AV rule
    if r.rtype in policysource.mapping.AVRULES:
        query = TERuleQuery(policy=policy.policy, ruletype=[r.rtype],
                            source=r.source, source_regex=sr,
                            source_indirect=False,
                            target=xtarget, target_regex=tr,
                            target_indirect=False,
                            tclass=[r.tclass], tclass_regex=cr,
                            perms=r.permset, perms_subset=True)
    # Query for a TE rule
    elif r.rtype in policysource.mapping.TERULES:
        dr = r"[a-zA-Z0-9_-]+" in r.deftype
        query = TERuleQuery(policy=policy.policy, ruletype=[r.rtype],
                            source=r.source, source_regex=sr,
                            source_indirect=False,
                            target=xtarget, target_regex=tr,
                            target_indirect=False,
                            tclass=[r.tclass], tclass_regex=cr,
                            default=r.deftype, default_regex=dr)
    else:
        # We should have no other rules, as they are already filtered
        # when creating the list with the rule_factory method
        LOG.warning("Unsupported rule: \"%s\"", r)
        return None
    # Filter all rules
    if r.target == "self":
        # Discard rules whose mask contained "self" as a target,
        # but whose result's source and target are different
        results = [x for x in query.results() if x.source == x.target]
    else:
        results = list(query.results())
    filtered_results = []
    # Discard rules coming from explicitly ignored paths
    for x in results:
        x_str = str(x)
        rule = MAPPER.rule_factory(x_str)
        rutc = rule.up_to_class
        # Get the MappedRule(s) corresponding to this rutc
        rls = [y for y in policy.mapping.rules[rutc]]
        if len(rls) == 1:
            # If this rule comes from a single place, this is easy.
            # Drop the rule if the path it comes from is ignored
            if not rls[0].fileline.startswith(FULL_IGNORE_PATHS):
                filtered_results.append(x)
                NON_IGNORED_MAPPING[x_str] = [rls[0].fileline]
        else:
            # If this rule comes from multiple places, this is more complex.
            # Check that all rules that make up the specific rule we found
            # come from non-ignored paths. If not, drop the rule.
            if rule.rtype in policysource.mapping.AVRULES:
                # Check that the permission set of the "x" rule is covered by
                # non-ignored rules. If not, drop the rule.
                tmpset = set()
                for each in rls:
                    if not each.fileline.startswith(FULL_IGNORE_PATHS):
                        prmstr = MAPPER.rule_split_after_class(each.rule)[1]
                        tmpset.update(prmstr.strip(" {};").split())
                        if x_str in NON_IGNORED_MAPPING:
                            NON_IGNORED_MAPPING[x_str].append(each.fileline)
                        else:
                            NON_IGNORED_MAPPING[x_str] = [each.fileline]
                if tmpset >= rule.permset:
                    # The set of permissions created by non-ignored rules is
                    # sufficient
                    filtered_results.append(x)
                else:
                    NON_IGNORED_MAPPING.pop(x_str, None)
            elif rule.rtype in policysource.mapping.TERULES:
                # Check for every type_transition rule individually
                for each in rls:
                    if not each.fileline.startswith(FULL_IGNORE_PATHS):
                        filtered_results.append(x)
                        if x_str in NON_IGNORED_MAPPING:
                            NON_IGNORED_MAPPING[x_str].append(each.fileline)
                        else:
                            NON_IGNORED_MAPPING[x_str] = [each.fileline]
    return filtered_results


def main(policy, config):
    """Suggest usages of te_macros where appropriate."""
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
    global FULL_IGNORE_PATHS
    FULL_IGNORE_PATHS = tuple(os.path.join(FULL_BASE_DIR, p)
                              for p in RULE_IGNORE_PATHS)

    global NON_IGNORED_MAPPING

    # Save the suggestions
    global_suggestions = set()

    total_queries = 0
    begin = default_timer()
    part = begin
    # Only consider te_macros not purposefully ignored
    selected_macros = [x for x in policy.macro_defs.values() if
                       x.file_defined.endswith("te_macros") and not
                       x.name in MACRO_IGNORE]
    # Create a dictionary of selected macro usages
    macrousages_dict = {}
    for m in policy.macro_usages:
        if m.macro in selected_macros:
            macrousages_dict[str(m)] = m
    # Create a dictionary of filelines -> macro usages
    macrousages_filelines = {}
    for m in policy.macro_usages:
        fileline = m.file_used + ":" + str(m.line_used)
        if fileline in macrousages_filelines:
            macrousages_filelines[fileline].append(m)
        else:
            macrousages_filelines[fileline] = [m]

    macros_found = 0
    macros_used = 0
    for k, m in enumerate(selected_macros, start=1):
        print "Processing \"{}\" ({}/{})...".format(m, k, len(selected_macros))
        # Get the Rule objects contained in the macro expansion and the initial
        # list of macro suggestions
        rules, macro_suggestions = process_macro(m, MAPPER)
        if not rules:
            print "Macro \"{}\" does not expand to any supported".format(m) +\
                " rule. Consider adding it to the ignored macros."
        # Query the policy with regexes
        total_queries += len(rules)
        overall_rules = []
        for r in rules.values():
            results = query_for_rule(policy, r)
            if results:
                overall_rules.extend(results)
        # Try to fill macro suggestions
        selected_suggestions = set()
        tried_usages = set()
        # While there are new suggestions
        while macro_suggestions:
            # Select and remove a suggestion from the set
            sug = macro_suggestions.pop()
            newsugs = set()
            removal_candidates = set()
            # Try to match all rules from the query to this suggestion
            for rule in overall_rules:
                try:
                    sug.add_rule(rule)
                except ValueError as e:
                    newsug = sug.fork_and_fit(rule)
                    # If we have a new valid suggestion which has not been
                    # suggested before
                    if newsug and newsug.usage not in tried_usages \
                            and newsug not in selected_suggestions \
                            and newsug not in macro_suggestions:
                        newsugs.add(newsug)
                        tried_usages.add(newsug.usage)
                except RuntimeError as e:
                    # This rule does not match any rule in the macro
                    removal_candidates.add(rule)
                else:
                    tried_usages.add(sug.usage)
            # This suggestion is now exhausted: if acceptable, move to
            # selected_suggestions, otherwise do nothing with it
            if sug.score >= SUGGESTION_THRESHOLD:
                selected_suggestions.add(sug)
            # Filter the newsugs and add to macro_suggestions those that still
            # need to be processed. Completed ones go to selected_suggestions
            for newsug in newsugs:
                if newsug.score == 1:
                    selected_suggestions.add(newsug)
                else:
                    macro_suggestions.add(newsug)
            # Remove rules that do not match any rules in the macro
            # Happens e.g. in cases of multiple occurrences of the same arg,
            # where the regex version will pick up a rule but the numbered
            # placeholder version will reject it.
            for rem in removal_candidates:
                overall_rules.remove(rem)
        # Discard suggestions entirely made up of rules that already come from
        # a macro expansion
        for sug in selected_suggestions:
            added = False
            for x in sug.rules:
                for y in NON_IGNORED_MAPPING[str(x)]:
                    if y not in macrousages_filelines:
                        # We have at least one rule that does not come from a
                        # macro expansion
                        global_suggestions.add(sug)
                        added = True
                        break
                if added:
                    break
        # Print time info
        oldpart = part
        part = default_timer()
        LOG.info("Time spent on \"%s\": %ss", m, part - oldpart)
    # Check how many usages have been fully recognized
    if config.verbosity == 4:
        found_usages = [x.usage for x in global_suggestions if x.score == 1]
        for x, n in macrousages_dict.iteritems():
            if n.macro not in selected_macros:
                continue
            macros_used += 1
            if x not in found_usages:
                LOG.debug("Usage not found: \"%s\"", x)
            else:
                macros_found += 1
    # Discard suggestions which are a subset of another with the same score
    removal_candidates = []
    # For each suggestion
    for x in global_suggestions:
        # If suggestion x is found to be a strict subset of any other,
        # meaning that its rules are wholly contained in a bigger
        # suggestion with an equal or greater score, don't suggest it.
        # Macro_suggestions is originally a set when being filled up, and
        # suggestions are identified by the macro name and rules they
        # contain, so there will not be more than one macro suggestion with
        # the same macro name containing exactly the same rules: therefore
        # we are only interested in strict subsets (x < y), without "<=".
        if any(x < y for y in global_suggestions if x.score <= y.score):
            removal_candidates.append(x)
    for x in removal_candidates:
        global_suggestions.remove(x)
    # Discard suggestions whose usage is already in the policy
    # This must be done after removing suggestions which are subsets of
    # others
    global_suggestions = [
        x for x in global_suggestions if x.usage not in macrousages_dict]
    # Print output
    print
    for x in global_suggestions:
        print "These lines could be substituted by macro {}:".format(x)
        for r in x.rules:
            r_str = str(r)
            rule = MAPPER.rule_factory(r_str)
            rls = policy.mapping.rules[rule.up_to_class]
            for y in rls:
                # Don't print rules coming from explicitly ignored paths
                # We have to do this here as well, because the mapping contains
                # all paths and duplicate rules in different paths may exist.
                if y.fileline.startswith(FULL_IGNORE_PATHS):
                    continue
                y_rule = MAPPER.rule_factory(y.rule)
                if y_rule.rtype in policysource.mapping.AVRULES:
                    # If the rules have at least one permission in common
                    if y_rule.permset & rule.permset:
                        print y
                elif y_rule.rtype in policysource.mapping.TERULES:
                    # If the rules have the same default type, and possibly
                    # object name
                    if y_rule.deftype == rule.deftype:
                        if y_rule.objname or rule.objname:
                            # If either has an object name, it must be the same
                            if y_rule.objname and rule.objname:
                                if y_rule.objname == rule.objname:
                                    print y
                        else:
                            # If neither has an object name just print
                            print y
        print "Corresponding rules in the macro expansion:"
        print x.usage_expansion
        print
    # Print some information
    LOG.debug("Usages found: %d/%d", macros_found, macros_used)
    end = default_timer()
    elapsed = end - begin
    LOG.info("Time spent expanding macros: %ss", elapsed)
    LOG.info("Avg time/macro: %ss", elapsed / float(len(selected_macros)))
    LOG.debug("Total queries: %s", total_queries)


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
        self._rules_strings = {}
        self._args = {}
        self._score = 0

    def add_rule(self, rule):
        """Mark a rule in the macro expansion as found in the policy."""
        already_taken = ""
        for r, e in self._extractors.iteritems():
            try:
                # Get the arguments
                args = e.extract(rule)
            except ValueError:
                continue
            else:
                rulestr = str(rule)
                # If the supplied rule matches one of the rules in the macro,
                # and that rule "slot" is not already taken by another rule
                if r in self._rules:
                    already_taken = self._rules[r]
                    continue
                # If there are any conflicting arguments, don't add this rule
                # i.e. arguments in the same position but with different values
                for a in args:
                    if a in self.args and args[a] != self.args[a]:
                        raise ValueError("Mismatching arguments: expected "
                                         "\"{}\", found \"{}\".".format(
                                             self.args[a], args[a]))
                # Add the new rule, associated with the corresponding
                # placeholder rule
                self._rules[r] = rule
                self._rules_strings[r] = rulestr
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
        # If we found a rule that matched a slot which was already taken, and
        # no other empty slot
        if already_taken:
            raise ValueError(
                "Slot already taken by \"{}\"!".format(already_taken))
        else:
            # If we got here, we found no matching rule at all
            raise RuntimeError("Invalid rule: \"{}\"".format(rule))

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
        for r in self.rules:
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
        return self._rules.values()

    @property
    def score(self):
        """Get the suggestion score [0,1].

        The score is given by:
        Ratio of successfully matched rules * Ratio of determined arguments
        This way, a macro suggestion which does not provide the whole set of
        args is penalised."""
        return self._score

    @property
    def usage_expansion(self):
        """Return a multiline string containing the relevant rules of the macro
        expansion with the current args."""
        retstr = ""
        for x in self.placeholder_rules:
            # Double all curly brackets to make them literal
            expansion = re.sub(r"([{}])", r"\1\1", x)
            # Substitute @@ARGN@@ with {N} to format the argument for
            # Python string formatting
            expansion = re.sub(r"@@ARG([0-9]+)@@", r"{\1}", expansion)
            # Print the rule with the current arguments
            args = []
            for y in sorted(self.args):
                args.append(self.args[y])
            retstr += expansion.format(*args) + "\n"
        return retstr

    def __eq__(self, other):
        """Check whether this suggestion is a duplicate of another."""
        return self.macro.name == other.macro.name and\
            set(self._rules_strings) == set(other._rules_strings)

    def __ne__(self, other):
        return self.macro.name != other.macro.name or\
            set(self._rules_strings) != set(other._rules_strings)

    def __lt__(self, other):
        return set(self._rules_strings) < set(other._rules_strings)

    def __le__(self, other):
        return set(self._rules_strings) <= set(other._rules_strings)

    def __gt__(self, other):
        return set(self._rules_strings) > set(other._rules_strings)

    def __ge__(self, other):
        return set(self._rules_strings) >= set(other._rules_strings)

    def __repr__(self):
        return self.usage + " (" + str(self.score * 100) + "%)"

    def __hash__(self):
        return hash(self.usage)

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
        self.regex_blocks_c = {}
        # Save precompiled regex blocks
        for blk in self.regex_blocks:
            if VALID_ARG_R in blk:
                self.regex_blocks_c[blk] = re.compile(blk)
        # Save pre-computed rule permission set
        if self.regex_blocks[0] in policysource.mapping.AVRULES:
            if any(x in self.regex_blocks[4] for x in "{}"):
                self.regex_perms = set(
                    self.regex_blocks[4].strip("{}").split())
            else:
                self.regex_perms = set([self.regex_blocks[4]])
        else:
            self.regex_perms = None
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
        The rule must be passed in as a string.

        Return True if the rule satisfies (at least) all constraints imposed
        by the extractor."""
        matches = []
        rule_objname = None
        # Shorter name -> shorter lines
        regex_blocks = self.regex_blocks
        regex_blocks_c = self.regex_blocks_c
        # Only call the rule methods once, cache values locally
        rule_blocks = []
        rule_blocks.append(str(rule.ruletype))
        if rule_blocks[0] == "type_transition":
            if len(regex_blocks) == 6:
                # Name transition
                try:
                    rule_objname = str(rule.filename)
                except:
                    return None
        elif rule_blocks[0] not in policysource.mapping.AVRULES:
            # Not an allow rule, not a type_transition rule
            return None
        # Match the rule block by block
        ##################### Match block 0 (ruletype) ######################
        # No macro arguments here, no regex match
        if rule_blocks[0] != regex_blocks[0]:
            return None
        ##################################################################
        rule_blocks.append(str(rule.source))
        ##################### Match block 1 (source) #####################
        if regex_blocks[1] in regex_blocks_c:
            # The domain contains an argument, match the regex
            m = regex_blocks_c[regex_blocks[1]].match(rule_blocks[1])
            if m:
                matches.append(m.group(1))
            else:
                return None
        else:
            # The domain contains no argument, match the string
            if rule_blocks[1] != regex_blocks[1]:
                return None
        ##################################################################
        rule_blocks.append(str(rule.target))
        ##################### Match block 2 (target) #####################
        if regex_blocks[2] in regex_blocks_c:
            # The type contains an argument, match the regex
            m = regex_blocks_c[regex_blocks[2]].match(rule_blocks[2])
            if m:
                matches.append(m.group(1))
            else:
                return None
        else:
            # The type contains no argument, match the string
            if regex_blocks[2] == "self" and rule_blocks[2] != "self":
                # Handle "self" expansion case
                # TODO: check if this actually happens
                if rule_blocks[2] != rule_blocks[1]:
                    return None
            elif rule_blocks[2] != regex_blocks[2]:
                return None
        ##################################################################
        rule_blocks.append(str(rule.tclass))
        ##################### Match block 3 (tclass) #####################
        if regex_blocks[3] in regex_blocks_c:
            # The class contains an argument, match the regex
            # This should never happen, however
            m = regex_blocks_c[regex_blocks[3]].match(rule_blocks[3])
            if m:
                matches.append(m.group(1))
            else:
                return None
        else:
            # The class contains no argument
            # Match a (super)set of what is required by the regex
            if rule_blocks[3] != regex_blocks[3]:
                # Simple class, match the string
                return None
        ##################################################################
        ##################### Match block 4 (variable) ###################
        if rule_blocks[0] in policysource.mapping.AVRULES:
            ################ Match an AV rule ################
            # Block 4 is the permission set
            # Match a (super)set of what is required by the regex
            if not self.regex_perms <= rule.perms:
                # If the perms in the rule are not at least those in
                # the regex
                return None
            ##################################################
        elif rule_blocks[0] == "type_transition":
            ################ Match a type_transition rule #################
            # Block 4 is the default type
            rule_default = str(rule.default)
            if regex_blocks[4] in regex_blocks_c:
                # The default type contains an argument, match the regex
                m = regex_blocks_c[regex_blocks[4]].match(rule_default)
                if m:
                    matches.append(m.group(1))
                else:
                    return None
            else:
                # The default type contains no argument, match the string
                if rule_default != regex_blocks[4]:
                    return None
            ##################################################
        ##################################################################
        ##################### Match block 5 (name trans) #################
        if rule_objname:
            # If this type transition has 6 fields, it is a name transition
            # Block 5 is the object name
            if regex_blocks[5] in regex_blocks_c:
                # The object name contains an argument, match the regex
                m = regex_blocks_c[regex_blocks[5]].match(rule_objname)
                if m:
                    matches.append(m.group(1))
                else:
                    return None
            else:
                # The object name contains no argument, match the string
                if rule_objname.strip("\"") != regex_blocks[5].strip("\""):
                    return None
        ##################################################################
        ######################## All blocks match ########################
        return matches
