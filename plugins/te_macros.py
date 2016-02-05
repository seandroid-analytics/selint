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

    # TODO: same as for global_macros, merge this part in policysource?
    # Prepare macro usages dictionaries
    macrousages_dict = {}
    for m in policy.macro_usages:
        fileline = FileLine(m.file_used, m.line_used, "")
        if fileline in macrousages_dict:
            macrousages_dict[fileline].append(m)
        else:
            macrousages_dict[fileline] = [m]

    rules_by_domain = {}
    # TODO: pass actual Rule from SETools inside MappedRule
    for r_up_to_class in policy.mapping:
        dmn = r_up_to_class.split()[1]
        if dmn in rules_by_domain:
            rules_by_domain[dmn].extend(policy.mapping[r_up_to_class])
        else:
            rules_by_domain[dmn] = list(policy.mapping[r_up_to_class])
