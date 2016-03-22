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
"""Assign a score to OEM rules depending on various criteria such as source and
target types, permission sets, ... ."""

import sys
import os.path
import config.dangerous_rules as plugin_conf
import policysource
import policysource.mapping


def main(policy, config):
    # Compute the absolute ignore paths
    FULL_BASE_DIR = os.path.abspath(os.path.expanduser(config.BASE_DIR_GLOBAL))
    FULL_IGNORE_PATHS = tuple(os.path.join(FULL_BASE_DIR, p)
                              for p in plugin_conf.RULE_IGNORE_PATHS)

    mapper = policysource.mapping.Mapper(
        policy.policyconf, policy.attributes, policy.types, policy.classes)
    printouts = []
    for rls in policy.mapping.rules.values():
        for r in rls:
            score = 0
            # If this rule comes from an ignored path or its type is not
            # supported, ignore it
            if r.fileline.startswith(FULL_IGNORE_PATHS)\
                    or not r.rule.startswith(plugin_conf.SUPPORTED_RULE_TYPES)\
                    or str(r) in plugin_conf.IGNORED_RULES:
                continue
            # Generate the corresponding AV/TErule object
            rule = mapper.rule_factory(r.rule)
            # START of additive scoring system
            # Match the source
            for crit in plugin_conf.TYPES:
                if rule.source in plugin_conf.TYPES[crit]:
                    score += plugin_conf.SCORE[crit]
                    break
            if rule.rtype in policysource.mapping.AVRULES:
                if rule.tclass in plugin_conf.CAPABILITIES:
                    # The rule allows a capability: the second type is always going
                    # to be "self", and as such is meaningless for scoring
                    # purposes. Add the capability score instead
                    score += plugin_conf.SCORE[rule.tclass]
                else:
                    # This is a normal allow rule, match the target
                    for crit in plugin_conf.TYPES:
                        if rule.target in plugin_conf.TYPES[crit]:
                            score += plugin_conf.SCORE[crit]
                            break
            elif rule.rtype == "type_transition":
                # This is a type transition: the target type does not mean much
                # Match the default type instead
                for crit in plugin_conf.TYPES:
                    if rule.deftype in plugin_conf.TYPES[crit]:
                        score += plugin_conf.SCORE[crit]
                        break
            # END of additive scoring system, START of multiplicative
            # Match the permissions
            if rule.rtype in policysource.mapping.AVRULES:
                perm_score = 0
                # Compute score for the permission set
                for crit in plugin_conf.PERMS:
                    # If the rule has any permission in common with set "crit"
                    if rule.permset & plugin_conf.PERMS[crit]:
                        # Update the permission coefficient for the rule to
                        # the one of the "crit" set, if not already higher
                        if perm_score < plugin_conf.SCORE[crit]:
                            perm_score = plugin_conf.SCORE[crit]
                if perm_score:
                    score *= perm_score
            # Normalise score
            score /= float(plugin_conf.MAXIMUM_SCORE)
            # Print rule
            if score >= plugin_conf.SCORE_THRESHOLD:
                printouts.append("{:.2f}: {}".format(score, r))
    print "\n".join(sorted(printouts, reverse=plugin_conf.REVERSE_SORT))
