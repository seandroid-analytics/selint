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
    for rls in policy.mapping.rules.values():
        for r in rls:
            score = 0
            if r.fileline.startswith(FULL_IGNORE_PATHS)\
                    or r.rule.startswith("neverallow "):
                # Ignore this rule
                continue
            rule = mapper.rule_factory(r.rule)
            # Match the source
            for crit in plugin_conf.TYPES:
                if rule.source in plugin_conf.TYPES[crit]:
                    score += plugin_conf.SCORE[crit]
                    break
            # Match the target
            for crit in plugin_conf.TYPES:
                if rule.target in plugin_conf.TYPES[crit]:
                    score += plugin_conf.SCORE[crit]
                    break
            # TODO: do something with default types in type_transition rule
            # Match the permissions
            if rule.rtype in policysource.mapping.AVRULES:
                perm_score = 0
                for crit in plugin_conf.PERMS:
                    if rule.permset & plugin_conf.PERMS[crit]:
                        if perm_score < plugin_conf.SCORE[crit]:
                            perm_score = plugin_conf.SCORE[crit]
                if perm_score:
                    score *= perm_score
            # Normalise score
            score /= float(plugin_conf.MAXIMUM_SCORE)
            # Print rule
            if score >= plugin_conf.SCORE_THRESHOLD:
                print "{:.2f}: {}".format(score, r)
