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
u"""Assign a score to OEM rules depending on various criteria such as source and
target types, permission sets, ... ."""

# Necessary for Python 2/3 compatibility
from __future__ import absolute_import
from __future__ import division
from future.utils import itervalues

import logging
import os.path
import plugins.config.risky_rules as plugin_conf
import policysource
import policysource.mapping


def score_terule(rule):
    u"""Assign a score to a TE rule depending on the scoring system."""
    score = 0
    # START of the additive scoring system
    # Match the source
    # For each bucket
    for crit in plugin_conf.TYPES:
        # If the source is in the bucket
        if rule.source in plugin_conf.TYPES[crit]:
            # Assign a score depending on the scoring system:
            # Risk
            if plugin_conf.SCORING_SYSTEM == u"risk":
                # Simply add the risk score
                score += plugin_conf.SCORE_RISK[crit]
            # Trust, low
            elif plugin_conf.SCORING_SYSTEM in (u"trust_lh", u"trust_ll"):
                # Add the score with inverted weight wrt the max type value
                # i.e. give a "high" score to a type marked with a "low" score
                score += (plugin_conf.MAXIMUM_SCORE / 2) \
                    - plugin_conf.SCORE_TRUST[crit]
            # Trust, high
            elif plugin_conf.SCORING_SYSTEM in (u"trust_hl", u"trust_hh"):
                # Simply add the trust score
                score += plugin_conf.SCORE_TRUST[crit]
            break
    # This is a type transition: the target type does not mean much
    # Match the default type instead
    # For each bucket
    for crit in plugin_conf.TYPES:
        # If the default type is in the bucket
        if rule.deftype in plugin_conf.TYPES[crit]:
            # Assign a score depending on the scoring system:
            # Risk
            if plugin_conf.SCORING_SYSTEM == u"risk":
                # Simply add the risk score
                score += plugin_conf.SCORE_RISK[crit]
            # Trust, low
            elif plugin_conf.SCORING_SYSTEM in (u"trust_hl", u"trust_ll"):
                # Add the score with inverted weight wrt the max type value
                # i.e. give a "high" score to a type marked with a "low" score
                score += (plugin_conf.MAXIMUM_SCORE / 2) \
                    - plugin_conf.SCORE_TRUST[crit]
            # Trust, high
            elif plugin_conf.SCORING_SYSTEM in (u"trust_lh", u"trust_hh"):
                # Simply add the trust score
                score += plugin_conf.SCORE_TRUST[crit]
            break
    # END of the additive scoring system
    # Normalise score
    score /= plugin_conf.MAXIMUM_SCORE
    return score


def score_avrule(rule):
    u"""Assign a score to an AV rule depending on the scoring system."""
    score = 0
    # START of the additive scoring system
    # Match the source
    # For each bucket
    for crit in plugin_conf.TYPES:
        # If the source is in the bucket
        if rule.source in plugin_conf.TYPES[crit]:
            # Assign a score depending on the scoring system:
            # Risk
            if plugin_conf.SCORING_SYSTEM == u"risk":
                # Simply add the risk score
                score += plugin_conf.SCORE_RISK[crit]
            # Trust, low
            elif plugin_conf.SCORING_SYSTEM in (u"trust_lh", u"trust_ll"):
                # Add the score with inverted weight wrt the max type value
                # i.e. give a "high" score to a type marked with a "low" score
                score += (plugin_conf.MAXIMUM_SCORE / 2) \
                    - plugin_conf.SCORE_TRUST[crit]
            # Trust, high
            elif plugin_conf.SCORING_SYSTEM in (u"trust_hl", u"trust_hh"):
                # Simply add the trust score
                score += plugin_conf.SCORE_TRUST[crit]
            break
    # Match the target
    # Risk
    if plugin_conf.SCORING_SYSTEM == u"risk":
        # If the rule allows a capability, the second type is always going to
        # be "self", and as such meaningless for scoring purposes.
        if rule.tclass in plugin_conf.CAPABILITIES:
            # Add the score for the capability instead
            score += plugin_conf.SCORE[rule.tclass]
        else:
            # This is a normal allow rule, match the target
            for crit in plugin_conf.TYPES:
                if rule.target in plugin_conf.TYPES[crit]:
                    score += plugin_conf.SCORE_RISK[crit]
                    break
    else:
        # Trust
        for crit in plugin_conf.TYPES:
            if rule.target in plugin_conf.TYPES[crit]:
                # Trust, low
                if plugin_conf.SCORING_SYSTEM in (u"trust_hl", u"trust_ll"):
                    # Add the score with inverted weight wrt the max type value
                    # i.e. give a "high" score to a type marked with "low"
                    score += (plugin_conf.MAXIMUM_SCORE / 2) \
                        - plugin_conf.SCORE_TRUST[crit]
                # Trust, high
                if plugin_conf.SCORING_SYSTEM in (u"trust_lh", u"trust_hh"):
                    # Simply add the trust score
                    score += plugin_conf.SCORE_TRUST[crit]
    # END of additive scoring system
    # START of multiplicative, if applicable
    if plugin_conf.SCORING_SYSTEM == u"risk":
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
    # END of multiplicative scoring system
    # Normalise score
    score /= plugin_conf.MAXIMUM_SCORE
    return score


def score_rule(rule):
    u"""Assign a score to a generic rule."""
    if rule.rtype in policysource.mapping.AVRULES:
        return score_avrule(rule)
    elif rule.rtype in policysource.mapping.TERULES:
        return score_terule(rule)
    else:
        # This should not happen
        return None


def main(policy, config):
    u"""Score OEM rules depending on a scoring system."""
    # Check that we have been fed a valid policy
    if not isinstance(policy, policysource.policy.SourcePolicy):
        raise ValueError(u"Invalid policy")
    # Setup logging
    log = logging.getLogger(__name__)
    # Check that we are using a supported scoring system
    if plugin_conf.SCORING_SYSTEM not in (u"risk", u"trust_hl", u"trust_lh",
                                          u"trust_hh", u"trust_ll"):
        log.critical(u"Unsupported scoring system \"%s\". Aborting...",
                     plugin_conf.SCORING_SYSTEM)
        return
    else:
        log.info(u"Scoring rules with \"%s\" scoring system...",
                 plugin_conf.SCORING_SYSTEM)
    # Compute the absolute ignore paths
    FULL_IGNORE_PATHS = tuple(os.path.join(config.FULL_BASE_DIR, p)
                              for p in plugin_conf.RULE_IGNORE_PATHS)

    mapper = policysource.mapping.Mapper(
        policy.policyconf, policy.attributes, policy.types, policy.classes)
    printouts = []
    # Score the rules
    for rls in itervalues(policy.mapping.rules):
        for r in rls:
            # If this rule comes from an ignored path or its type is not
            # supported, ignore it
            if r.fileline.startswith(FULL_IGNORE_PATHS)\
                    or not r.rule.startswith(plugin_conf.SUPPORTED_RULE_TYPES)\
                    or str(r) in plugin_conf.IGNORED_RULES:
                continue
            # Generate the corresponding AV/TErule object
            rule = mapper.rule_factory(r.rule)
            # Get the score for the rule, according to the scoring system
            score = score_rule(rule)
            # Print rule
            if score >= plugin_conf.SCORE_THRESHOLD:
                printouts.append(u"{:.2f}: {}".format(score, r))
    print(u"\n".join(sorted(printouts, reverse=plugin_conf.REVERSE_SORT)))
