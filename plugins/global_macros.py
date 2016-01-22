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


def main(policy):
    if not isinstance(policy, policysource.policy.SourcePolicy):
        raise ValueError("Invalid policy")

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

    for r_up_to_class in policy.mapping:
        if r_up_to_class.startswith("allow "):
            rls = policy.mapping[r_up_to_class]
            permset = set()
            for r in rls:
                permstring = r[0][len(r_up_to_class) + 1:].rstrip(";")
                permset.update(x for x in permstring.split() if x not in "{}")
            # TODO: insert set cover algorithm here to cover
            # X: all_elements
            # F: macroset_list
            #
            # TODO: maybe better bins algorithm?
            sf = SetFitter(macroset_dict)
            results = sf.fit(permset)
            ones = [x for x in results if x.score == 1]
            if len(ones) > 0:
                print "\n"
                print policy.mapping[r_up_to_class]
                s = max([macroset_dict[x.name] for x in ones])
                if bool(permset - s):
                    print macroset_labels[s] + " + { " + " ".join(permset - s) + " }"
                else:
                    print macroset_labels[s]
            else:
                first = True
                for s in results:
                    if s.score > 0.7:
                        if first:
                            print "\n"
                            print policy.mapping[r_up_to_class]
                            first = False
                        print "{0}: {1}".format(s.name, str(s.score))


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
        # return [ (x.name, x.score) for x in sorted(rich_sets, reverse=True)]
        return sorted(rich_sets, reverse=True)
