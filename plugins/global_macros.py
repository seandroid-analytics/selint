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
"""TODO: file docstring"""

import policysource
import policysource.policy

SUGGESTION_THRESHOLD = 0.75
SUGGESTION_MAX_NO = 3


def main(policy):
    if not isinstance(policy, policysource.policy.SourcePolicy):
        raise ValueError("Invalid policy")

    # Prepare macro definition dictionaries
    macroset_dict = {}
    macroset_labels = {}
    all_elements = set()
    for m in policy.macro_defs:
        if policy.macro_defs[m].file_defined.endswith("global_macros"):
            exp = policy.macro_defs[m].expand()
            args = frozenset(x for x in exp.split() if x not in "{}")
            macroset_dict[m] = args
            macroset_labels[args] = m
            all_elements.update(args)
    # Prepare macro usages dictionaries
    macrousages_dict = {}
    for m in policy.macro_usages:
        fileline = "{}:{}".format(m.file_used, m.line_used)
        if fileline in macrousages_dict:
            macrousages_dict[fileline].append(m)
        else:
            macrousages_dict[fileline] = [m]

    # Initialize a set fitter
    sf = SetFitter(macroset_dict)
    for r_up_to_class in policy.mapping:
        if r_up_to_class.startswith("allow "):
            ruleset = policy.mapping[r_up_to_class]
            permset = set()
            # Merge the various permission sets deriving from different rules
            # applying to the same domain/type/class
            for r in ruleset:
                # Get the permission string from the rule
                # The rule is the first element of r (rule, file, line)
                # Cut everything before the class, the space and strip the
                # final semicolon
                permstring = r[0][len(r_up_to_class) + 1:].rstrip(";")
                # Tokenize the permission string and update the permission set
                permset.update(x for x in permstring.split() if x not in "{}")
            # Get a list of RichSets sorted by decreasing score
            # The score indicates how well the permset covers them
            results = sf.fit(permset)
            # Get the RichSets that are fully covered
            ones = [x for x in results if x.score == 1]
            # If there is at least one, we have at least one full match
            if len(ones) > 0:
                # Suggest using the biggest set
                s = max([x.values for x in ones])
                s_name = macroset_labels[s]
                suggest_this = True
                # Check whether this macro was originally in the policy
                # If it already was, no point in suggesting it
                for r in ruleset:
                    r_fileline = "{}:{}".format(r[1], r[2])
                    # If there is an usage of this macro on one of the lines
                    # that contribute to this set of permissions
                    if r_fileline not in macrousages_dict:
                        continue
                    macros_at_line = macrousages_dict[r_fileline]
                    if s_name in [x.name for x in macros_at_line]:
                        suggest_this = False
                        break
                    for m in macros_at_line:
                        if not m.macro.file_defined.endswith("global_macros"):
                            # There are other macros at play, do not suggest
                            suggest_this = False
                            break
                    if not suggest_this:
                        break
                    for m in macros_at_line:
                        if macroset_dict[m.name] > s:
                            suggest_this = False
                            break
                    if not suggest_this:
                        break
                if suggest_this:
                    print "Macro \"{}\" could be used at:".format(s_name)
                    print "\n".join(["{}:{}".format(r[1], r[2]) for r in ruleset])
                    extras = permset - s
                    perms = [s_name]
                    perms.extend(extras)
                    print "The new rule would be:"
                    print r_up_to_class + " { " + " ".join(perms) + " };"
                    print
            # Suggest close matches based on a threshold
            else:
                suggestions = sorted(
                    [x for x in results if x.score >= SUGGESTION_THRESHOLD],
                    reverse=True)[:SUGGESTION_MAX_NO]
                if len(suggestions):
                    print "The following macros match these lines:"
                    print "\n".join(["{}:{}".format(r[1], r[2]) for r in ruleset])
                    print "\n".join(["{}: {}%".format(x.name, x.score * 100) for x in suggestions])
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
            #   TODO: compute score here everytime we add
            if elem in self.tally:
                self.tally[elem] += 1
            else:
                raise ValueError("Invalid element")
            i = 0
            for s in self.tally.values():
                if s != 0:
                    i += 1
            self.nonzero = i

        def compute_score(self):
            """Compute the set score."""
            self.score = self.nonzero / float(len(self.tally))

        def print_full(self):
            print self.name + " ({}/{})".format(self.score, len(self.tally))
            for k, v in self.tally.iteritems():
                print k + " ({})".format(v)

        def __repr__(self):
            return self.name + ": " + self.score

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
        self.d = d

    def fit(self, s):
        """Fit a set."""
        rich_sets = [SetFitter.RichSet(key, value)
                     for key, value in self.d.iteritems()]

        for elem in s:
            for each in rich_sets:
                if each.contains(elem):
                    each.incr(elem)

        for each in rich_sets:
            each.compute_score()
        return sorted(rich_sets, reverse=True)
