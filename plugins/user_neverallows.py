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
u"""Verify that custom user-defined neverallow rules are obeyed."""

# Necessary for Python 2/3 compatibility
from __future__ import absolute_import
from __future__ import division
from future.utils import iteritems

# import logging
import plugins.config.user_neverallows as plugin_conf
import policysource
import policysource.mapping

# Required by selint
REQUIRED_RULES = plugin_conf.SUPPORTED_RULE_TYPES


def get_user_rules(expander, mapper):
    u"""Get the user-supplied rules from the configuration file.

    Return a dictionary {RUTC: AVRule}"""
    supplied_rules = {}
    for r in plugin_conf.NEVERALLOWS:
        # Convert the rules to unicode
        if not isinstance(r, unicode):
            r = r.decode("utf-8")
        # Expand the possible global_macros in the rule
        exp_r = expander.expand(r)
        # If the expansion failed, process the next rule
        if not exp_r:
            continue
        # Generate a dictionary {rutc: full} containing all rules deriving from
        # the attribute, set and complement expansion in the rule.
        resulting_rules = mapper.expand_rule(exp_r)
        # Generate an AVRule object from the string representation of each rule
        # Generate a dictionary {allow: AVRule}, where the key is the allow
        # rule corresponding to the neverallow, and the value is the full
        # neverallow rule as an AVRule object
        for (k, v) in iteritems(resulting_rules):
            supplied_rules[k[5:]] = mapper.rule_factory(v)
    return supplied_rules


def main(policy, config):
    u"""Check that the policy obeys custom user-defined neverallow rules."""
    # Check that we have been fed a valid policy
    if not isinstance(policy, policysource.policy.SourcePolicy):
        raise ValueError(u"Invalid policy")
    # Setup logging
    # log = logging.getLogger(__name__)

    mapper = policysource.mapping.Mapper(
        policy.policyconf, policy.attributes, policy.types, policy.classes)
    # Process the user-submitted neverallow rules into a dictionary of
    # {RUTC: AVRule} for easier handling
    user_rules = get_user_rules(policy._expander, mapper)
    # Check the rules
    for rutc, rls in iteritems(policy.mapping.rules):
        if not rutc.startswith(plugin_conf.SUPPORTED_RULE_TYPES):
            continue
        # If an allow rule matches some user-specified neverallow rule
        if rutc in user_rules:
            allowed_perms = set()
            for r in rls:
                # Generate the AVrule object for the allow rule coming from
                # the policy
                rule = mapper.rule_factory(r.rule)
                # Combine the permissions
                allowed_perms.update(rule.permset)
            # If the rule allows any permission in the neverallow, report it
            if allowed_perms & user_rules[rutc].permset:
                print(u"Rule grants neverallowed permissions: \"{}\"".format(
                    u" ".join(allowed_perms & user_rules[rutc].permset)))
                full_rule = rutc + " "
                if len(allowed_perms) > 1:
                    full_rule += u"{ " + u" ".join(allowed_perms) + u" };"
                else:
                    full_rule += u" ".join(allowed_perms) + u";"
                print(u"  " + full_rule)
                for r in rls:
                    print(u"    " + str(r))
