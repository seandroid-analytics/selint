#
# Written by Filippo Bonazzi
# Copyright (C) 2015 Aalto University
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
"""Plugin to analyse usage of global macros and suggest new ones."""

import itertools
import os
import os.path
import logging
import policysource
import policysource.policy
import policysource.mapping
from policysource.mapping import FileLine as FileLine

# Do not make suggestions on rules coming from files in these paths
#
# e.g. to ignore AOSP:
# RULE_IGNORE_PATHS = ["external/sepolicy"]
RULE_IGNORE_PATHS = ["external/sepolicy"]

# Only make suggestions for the following rule types
# SUPPORTED_RULE_TYPES = ("allow", "auditallow", "dontaudit", "neverallow")
SUPPORTED_RULE_TYPES = ("allow")

# Parameters for partial match macro suggestions
# Only suggest macros that match above this threshold [0-1]
SUGGESTION_THRESHOLD = 0.8
# Make up to this number of suggestions
SUGGESTION_MAX_NO = 3


class GlobalMacroSuggestion(object):
    """ """

    def __init__(self, macro_name, perm_set, rules, score):
        self.name = macro_name
        self.macro_perms = perm_set
        self.rules = rules
        self.score = score
        self.filelines = frozenset((r.fileline for r in rules))

    def __hash__(self):
        return hash(self.name + " ".join(self.filelines))

    def __repr__(self):
        return self.name + ":\n" + "\n".join(self.filelines)

    def __eq__(self, other):
        return self.name == other.name and self.filelines == other.filelines

    def __ne__(self, other):
        return not self == other

    def __lt__(self, other):
        return self.score < other.score

    def __le__(self, other):
        return self.score <= other.score

    def __gt__(self, other):
        return self.score > other.score

    def __ge__(self, other):
        return self.score >= other.score


def main(policy, config):
    # Check that we have been fed a valid policy
    if not isinstance(policy, policysource.policy.SourcePolicy):
        raise ValueError("Invalid policy")
    # Setup logging
    log = logging.getLogger(__name__)

    # Compute the absolute ignore paths
    FULL_BASE_DIR = os.path.abspath(os.path.expanduser(config.BASE_DIR_GLOBAL))
    FULL_IGNORE_PATHS = tuple(os.path.join(FULL_BASE_DIR, p)
                              for p in RULE_IGNORE_PATHS)

    # Suggestions: {frozenset(filelines): [suggestions]}
    suggestions = {}

    # Prepare macro definition dictionaries
    macroset_dict = {}
    macroset_labels = {}
    #all_elements = set()
    for m in policy.macro_defs:
        if policy.macro_defs[m].file_defined.endswith("global_macros"):
            exp = policy.macro_defs[m].expand()
            args = frozenset(x for x in exp.split() if x not in "{}")
            macroset_dict[m] = args
            macroset_labels[args] = m
            # all_elements.update(args)
    # Prepare macro usages dictionaries
    macrousages_dict = {}
    for m in policy.macro_usages:
        fileline = FileLine(m.file_used, m.line_used, "")
        if fileline in macrousages_dict:
            macrousages_dict[fileline].append(m)
        else:
            macrousages_dict[fileline] = [m]

    # Initialize a set fitter
    sf = SetFitter(macroset_dict)
    for r_up_to_class in policy.mapping:
        if r_up_to_class.startswith(SUPPORTED_RULE_TYPES):
            rules = policy.mapping[r_up_to_class]
            permset = set()
            # Merge the various permission sets deriving from different rules
            # applying to the same domain/type/class
            filtered_rules = []
            for r in rules:
                # Discard rules coming from ignored paths
                if r.fileline.f.startswith(FULL_IGNORE_PATHS):
                    continue
                filtered_rules.append(r)
                # Get the permissions from the rule
                permset.update(r.rule.perms)
            # If there are no rules left or the permset is empty, process
            # the next set of rules
            if not filtered_rules or not permset:
                continue
            # Get up to one full match (combination of one or more macros which
            # combined fit the permset exactly), and a list of macros that fit
            # the permset partially
            (winner, part) = sf.fit(permset)
            # TODO: refactor this next part, merge winner/part handling where
            # possible
            # If we have a winner, we have a full (multi)set match
            if winner:
                suggest_this = True
                # Check if the winner meets all requirements for being
                # suggested
                for r in filtered_rules:
                    # Check if there are macros used on this fileline at all
                    if r.fileline not in macrousages_dict:
                        # No macro used on this fileline, check the next
                        continue
                    macros_at_line = macrousages_dict[r.fileline]
                    # Check that no other macros are involved
                    for m in macros_at_line:
                        if not m.macro.file_defined.endswith("global_macros"):
                            # There are other macros at play, do not suggest
                            suggest_this = False
                            break
                    if not suggest_this:
                        # Also break out of the outer loop
                        break
                    # Do not suggest macro usages that are already in the
                    # policy
                    alreadyused = [x for x in winner if x.name in (
                        x.name for x in macros_at_line)]
                    for a in alreadyused:
                        # Remove already used macros from the winner
                        winner.remove(a)
                    if not winner:
                        # If the winner is now empty, we don't care about this
                        # suggestion anymore
                        suggest_this = False
                        break
                if suggest_this:
                    for x in winner:
                        g = GlobalMacroSuggestion(
                            x.name, x.values, filtered_rules, x.score)
                        if g.filelines not in suggestions:
                            suggestions[g.filelines] = [g]
                        elif g not in suggestions[g.filelines]:
                            suggestions[g.filelines].append(g)
            # Suggest close matches based on a threshold
            if part:
                suggest_this = True
                # Check if the partial suggestions meet all requirements
                # for being suggested
                for r in filtered_rules:
                    # Check if there are macros used on this fileline at all
                    if r.fileline not in macrousages_dict:
                        # No macro used on this fileline, check the next
                        continue
                    else:
                        # There are other macros at play, do not suggest
                        suggest_this = False
                        break
                if suggest_this:
                    # Select the top SUGGESTION_MAX_NO suggestions above
                    # SUGGESTION_THRESHOLD from the results
                    sgs = sorted(
                        [x for x in part if x.score >= SUGGESTION_THRESHOLD],
                        reverse=True)[:SUGGESTION_MAX_NO]
                    for x in sgs:
                        g = GlobalMacroSuggestion(
                            x.name, x.values, filtered_rules, x.score)
                        if g.filelines not in suggestions:
                            suggestions[g.filelines] = [g]
                        elif g not in suggestions[g.filelines]:
                            suggestions[g.filelines].append(g)
    # Print the suggestions
    for filelines, sgs in suggestions.iteritems():
        full = []
        part = []
        for x in sgs:
            if x.score == 1:
                full.append(x)
            else:
                part.append(x)
        part.sort(reverse=True)
        if full or part:
            print "The following macros match these lines:"
            print "\n".join((x.full for x in filelines))
        if full:
            # Print full match suggestion(s)
            print "Full match:"
            print ", ".join((x.name for x in full))
        if part:
            # Print partial match suggestion(s)
            print "Partial match:"
            print "\n".join(["{}: {}%".format(x.name, x.score * 100) for x in part])
        if full or part:
            print


class SetFitter(object):
    """Cover a given set with the minimum number of known sets.

    Pass the sets in as dict: {label: set}"""

    class RichSet(object):
        """A dict with an associated score for each element"""

        def __init__(self, name, values):
            self.name = name
            self.values = values
            self.tally = {}
            for elem in self.values:
                self.tally[elem] = 0
            self.nonzero = 0
            self.score = 0

        def contains(self, elem):
            return elem in self.values

        def incr(self, elem):
            if elem in self.tally:
                if self.tally[elem] == 0:
                    # First match, update score
                    self.nonzero += 1
                    self.score = self.nonzero / float(len(self.tally))
                self.tally[elem] += 1

        def print_full(self):
            print self.name + " ({}/{})".format(self.score, len(self.tally))
            for k, v in self.tally.iteritems():
                print k + " ({})".format(v)

        def __repr__(self):
            return self.name + ": " + str(self.score)

        def __eq__(self, other):
            return self.score == other.score

        def __ne__(self, other):
            return self.score != other.score

        def __lt__(self, other):
            return self.score < other.score

        def __le__(self, other):
            return self.score <= other.score

        def __gt__(self, other):
            return self.score > other.score

        def __ge__(self, other):
            return self.score >= other.score

    def __init__(self, d):
        """Initialise a SetFitter with a dictionary of the available sets.

        d    - A dictionary {name: set} with the available sets accessible by
               name.
       """
        self.d = d

    def fit(self, s):
        """Fit a set with the pre-supplied available sets."""
        # Initialise a new list of rich sets
        rich_sets = [
            SetFitter.RichSet(key, value) for key, value in self.d.iteritems()]
        # Fit the set
        for elem in s:
            for each in rich_sets:
                each.incr(elem)
        ones = []
        part = []
        for x in rich_sets:
            if x.score == 1:
                ones.append(x)
            else:
                part.append(x)
        # part.sort(reverse=True)
        # Compute all combinations of full macros
        combinations = []
        for i in xrange(1, len(ones) + 1):
            combinations.extend(itertools.combinations(ones, i))
        # Find the one that leaves the smallest extra set
        extra_dim = {}
        for c in combinations:
            # Set of macro combinations e.g. [r_file, w_file]
            # The combination is a tuple, make it a set
            c = set(c)
            # The set of permissions that results from the combination
            c_set = set()
            for x in c:
                c_set.update(x.values)
            # Compute the extra permissions in the set that are not covered by
            # the expansion of the selected combination of macros
            extra = s - c_set
            # Index the combinations by score (number of extra elements, lower
            # is better)
            if len(extra) in extra_dim:
                extra_dim[len(extra)].append(c)
            else:
                extra_dim[len(extra)] = [c]
        # Find the smallest combination of macros that leaves the smallest
        # number of extra permissions
        if extra_dim:
            m = min(extra_dim)
            winner = min(extra_dim[m], key=len)
        else:
            winner = []
        return (winner, part)
