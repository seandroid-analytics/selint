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
u"""Report rules matching some criteria specified in the configuration file.
Specifically, this plugin provides 3 functionalities, described here.

# Functionality 1
Detect missing rules from a (ordered) tuple of rules.
Some rules are expected to be found together: type_transition rules require
specific associated allow rules to be meaningful, etc.
This functionality looks for rules matching the first rule in a tuple specified
in the configuration file, and verifies that all other rules in the tuple are
actually present: if not, they are reported.

Rules can be matched using simple placeholders: see the configuration file for
examples.

# Functionality 2
Detect rules containing debug types.
The user can define some types as "debug types" in the configuration file, and
this functionality will report any rule found in the policy using those types.

# Functionality 3
Detect rules that grant some permission over some class without granting some
necessary or required permission, e.g. a rule which grants "write" but not
"open" over a "file" class, without granting "use" over the corresponding "fd"
class.

More precisely, this functionality reports rules that grant at least one
permission over an object of class F from set F_A, without granting at least
all permissions in set F_B or some extra permissions on some other class.
All these permission sets can be specified by the user in the configuration
file.

"""

# Necessary for Python 2/3 compatibility
from __future__ import absolute_import
from builtins import range
from future.utils import iteritems

import logging
import re
import os.path
from setools.terulequery import TERuleQuery as TERuleQuery
import plugins.config.unnecessary_rules as plugin_conf
import policysource
import policysource.mapping

# Required by selint
REQUIRED_RULES = plugin_conf.SUPPORTED_RULE_TYPES

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


def query_for_rule(policy, r):
    u"""Query a policy for rules matching a given rule.
    The rule may contain regex fields."""
    # Mark whether a query parameter is a regex or a string
    sr = r"[a-zA-Z0-9_-]+" in r.source
    tr = r"[a-zA-Z0-9_-]+" in r.target
    cr = r"[a-zA-Z0-9_-]+" in r.tclass
    # Handle self
    if r.target == u"self":
        # Override the target to match everything
        xtarget = VALID_ARG_R
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
        LOG.warning(u"Unsupported rule: \"%s\"", r)
        return None
    # Filter all rules
    if r.target == u"self":
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
                        tmpset.update(prmstr.strip(u" {};").split())
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


def substitute_args(rule, args):
    u"""Substitute placeholder arguments in a rule with their actual values.

    The rule must be passed in as a string.
    e.g.
    rule = "allow @@ARG0@@ sometype:class perm;"
    args = {"arg0": "somedomain"}
    -> returns "allow somedomain sometype:class perm;"
    """
    modified_args = {}
    for (k, v) in iteritems(args):
        modified_args[u"@@" + k.upper() + u"@@"] = v
    for (k, v) in iteritems(modified_args):
        rule = rule.replace(k, v)
    return rule


def accumulate_perms(rutc, rules):
    u"""Accumulate the permissions found in rules having a common subprefix up
    to the class (rutc)."""
    found_perms = set()
    for x in rules:
        # If a rule comes from an ignored path, not only ignore it, but
        # ignore the whole rutc
        if x.fileline.startswith(FULL_IGNORE_PATHS):
            found_perms = None
            break
        # Get the permission string, strip it, split it, burn it, rip it,
        # drag and drop it, zip - unzip it and update the permission set
        found_perms.update(x.rule[len(rutc):].strip(u" {};").split())
    return found_perms


def main(policy, config):
    u"""Find unnecessary or missing rules in the policy."""
    # Check that we have been fed a valid policy
    if not isinstance(policy, policysource.policy.SourcePolicy):
        raise ValueError(u"Invalid policy")
    # Setup logging
    log = logging.getLogger(__name__)
    global LOG
    LOG = log

    # Compute the absolute ignore paths
    global FULL_IGNORE_PATHS
    FULL_IGNORE_PATHS = tuple(os.path.join(config.FULL_BASE_DIR, p)
                              for p in plugin_conf.RULE_IGNORE_PATHS)

    # Create a global mapper to expand the rules
    global MAPPER
    MAPPER = policysource.mapping.Mapper(
        policy.policyconf, policy.attributes, policy.types, policy.classes)

    # Compile the regex for speed
    rule_w_placeholder_r = re.compile(
        r".*" + ArgExtractor.placeholder_r + r".*")
    # Functionality 1
    # Look for missing rules in predetermined tuples
    print(u"Checking for missing rules")
    for t in plugin_conf.RULES_TUPLES:
        log.debug(u"Checking tuple containing these rules:")
        for x in t:
            log.debug(x)
        placeholder_sub = False
        # Ignore tuples with a single element. We should not have any, anyway
        if len(t) < 2:
            continue
        # Ignore tuples that begin with an unsupported rule
        if not t[0].startswith(policysource.mapping.ONLY_MAP_RULES):
            continue
        # If the first rule in the tuple contains at least one placeholder
        if rule_w_placeholder_r.match(t[0]):
            placeholder_sub = True
            # Initialise an extractor with the placeholder rule
            e = ArgExtractor(t[0])
            # Substitute the positional placeholder arguments with a
            # regex matching valid argument characters
            l_r = re.sub(r"@@ARG[0-9]+@@", VALID_ARG_R, t[0])
            tmp = MAPPER.rule_factory(l_r)
            # Get the rules matching the query for the rule with regexes
            # N.B. this already discards rules coming from ignored paths
            rules = query_for_rule(policy, tmp)
            if not rules:
                continue
            log.debug(u"Found rules:")
            for x in rules:
                log.debug(str(x))
        else:
            # If the first rule contains no placeholder, simply use it as a
            # string
            rules = [t[0]]
        # For each rule matching the query
        for r in rules:
            # Skip rules purposefully ignored by the user
            if r in plugin_conf.IGNORED_RULES:
                continue
            # For each additional rule in the tuple, check that it is in the
            # policy, substituting placeholders if necessary.
            missing_rules = []
            if placeholder_sub:
                # Get the arguments from the rule
                args = e.extract(r)
            # For each additional rule in the tuple
            for each_rule in t[1:]:
                # Ignore unsupported rules
                if not each_rule.startswith(policysource.mapping.ONLY_MAP_RULES):
                    continue
                if placeholder_sub:
                    nec_rule = substitute_args(each_rule, args)
                else:
                    nec_rule = each_rule
                nec_rule_full = MAPPER.rule_factory(nec_rule)
                # Shorter variable name
                nrfutc = nec_rule_full.up_to_class
                # If the rule up to the class is in the mapping
                if nrfutc in policy.mapping.rules:
                    # Check if the rule is actually present by possibly
                    # combining the existing rules in the mapping
                    if nec_rule_full.rtype in policysource.mapping.AVRULES:
                        # If we are looking for an allow rule, combine
                        # existing allow rules and check if the resulting
                        # rule is a superset of the rule we are looking
                        # for
                        permset = set()
                        for x in policy.mapping.rules[nrfutc]:
                            x_f = MAPPER.rule_factory(x.rule)
                            permset.update(x_f.permset)
                        # If not a subset, print the rule and the missing
                        # permissions
                        if not nec_rule_full.permset <= permset:
                            missing = u" (missing \""
                            missing += u" ".join(nec_rule_full.permset -
                                                 permset)
                            missing += u"\")"
                            missing_rules.append(nec_rule + missing)
                    if nec_rule_full.rtype in policysource.mapping.TERULES:
                        # If we are looking for a TE rule, check for an
                        # identical match
                        if nec_rule not in policy.mapping.rules[nrfutc]:
                            missing_rules.append(nec_rule)
                # If the rule is not even in the mapping
                else:
                    # The rule is completely missing from the policy
                    missing_rules.append(nec_rule)
            if missing_rules:
                # TODO: print fileline
                rutc = MAPPER.rule_split_after_class(str(r))[0]
                print(u"Rule:")
                if len(policy.mapping.rules[rutc]) > 1:
                    print(u"  " + str(r))
                    print(u"made up of rules:")
                    for x in policy.mapping.rules[rutc]:
                        print(u"  " + str(x))
                else:
                    print(u"  " + str(policy.mapping.rules[rutc][0]))
                print(u"is missing associated rule(s):")
                for x in missing_rules:
                    print(u"  " + str(x))
    # Functionality 2
    # Look for debug types
    print(u"Checking for rules containing debug types")
    for rutc in policy.mapping.rules:
        for dbt in plugin_conf.DEBUG_TYPES:
            if dbt and dbt in rutc:
                print(u"Rule contains debug type \"{}\":".format(dbt))
                for each in policy.mapping.rules[rutc]:
                    eachstr = str(each)
                    # Skip rules purposefully ignored by the user
                    if eachstr not in plugin_conf.IGNORED_RULES:
                        print(u"  " + eachstr)

    # Functionality 3
    # Look for rules not granting minimum permissions
    print(u"Checking for rules not granting minimum required permissions")
    # Check that the configuration value of REQUIRED_PERMS is valid
    if hasattr(plugin_conf, u"REQUIRED_PERMS") and \
            isinstance(plugin_conf.REQUIRED_PERMS, dict) and\
            plugin_conf.REQUIRED_PERMS:
        # The REQUIRED_PERMS dictionary exists and is not empty
        rmv = []
        for (k, v) in iteritems(plugin_conf.REQUIRED_PERMS):
            if not(isinstance(k, str) and isinstance(v, tuple) and
                   isinstance(v[0], set) and isinstance(v[1], set) and
                   isinstance(v[2], dict)):
                # If the format is invalid
                log.error("Ignoring invalid REQUIRED_PERMS value \"%s\"", k)
                log.error("  %s", v)
                rmv.append(k)
        for rm in rmv:
            del plugin_conf.REQUIRED_PERMS[rm]
    for rutc in policy.mapping.rules:
        # Filter the rules by type (beginning of the "rule up to class")
        if not rutc.startswith(u"allow"):
            continue
        # Get the rule class and pre-class part
        pre_cls, cls = rutc.split(u":")
        # Check if there are any constraint for this class
        if cls not in plugin_conf.REQUIRED_PERMS:
            # If not, skip this rule
            continue
        # Get the "interesting" perms and the minimum perms required by them
        perms, req_perms, add_perms = plugin_conf.REQUIRED_PERMS[cls]
        # Accumulate the permissions granted by all the rules under "rutc"
        found_perms = accumulate_perms(rutc, policy.mapping.rules[rutc])
        # If found_perms has been set to None, skip this rule
        if found_perms is None:
            continue
        report = False
        all_extras_granted = True
        # If a rule for this class grants some permission from the first
        # set, but does not grant at least the required permission(s)
        if found_perms & perms and not found_perms >= req_perms:
            # Check if it grants the additional permissions over additional
            # classes instead
            # Preliminarily mark the rule to be reported: correct this if the
            # rule grants all extra required permissions
            report = True
            for k, v in iteritems(add_perms):
                # Check if the found additional permissions (found_ap) are a
                # superset of the required additional permissions (v)
                found_ap = None
                # Search for the new rule composed of OLD_RULE:new class
                new_rutc = pre_cls + ":" + k
                if new_rutc in policy.mapping.rules:
                    found_ap = accumulate_perms(
                        rutc, policy.mapping.rules[new_rutc])
                if found_ap is None or not found_ap >= v:
                    # If new_rutc is not in the mapping, or if all its rules
                    # come from ignored paths, or the set of found
                    # permissions is not a superset of the required
                    # permissions, mark false and break
                    all_extras_granted = False
                    break
            # If all extra required permissions have been granted, do not
            # report the rule
            if all_extras_granted:
                report = False
        if report:
            res_str = rutc + u" "
            if len(found_perms) > 1:
                res_str += u"{ " + u" ".join(found_perms) + u" };"
            else:
                res_str += u" ".join(found_perms) + u";"
            # Skip rules purposefully ignored by the user
            if res_str in plugin_conf.IGNORED_RULES:
                continue
            print(u"Permissions in rule:")
            print(res_str)
            rutc = MAPPER.rule_split_after_class(res_str)[0]
            for each in policy.mapping.rules[rutc]:
                print(u"  " + each.fileline)
            print(u"require additional permissions: "
                  u"\"{}\"".format(u" ".join(req_perms - found_perms)))
            print(u"or permissions over different classes:")
            for k, v in iteritems(add_perms):
                extra_str = u"\"" + k + u" "
                if len(v) > 1:
                    extra_str += u"{ " + u" ".join(v) + u" }\""
                else:
                    extra_str += u" ".join(v) + u"\""
                print(u" " + extra_str)
            print(u"")


class ArgExtractor(object):
    u"""Extract macro arguments from an expanded rule according to a regex."""
    placeholder_r = r"@@ARG[0-9]+@@"

    def __init__(self, rule):
        u"""Initialise the ArgExtractor with the rule expanded with the named
        placeholders.

        e.g.: "allow @@ARG0@@ @@ARG0@@_tmpfs:file execute;"
        """
        self.rule = rule
        # Convert the rule to a regex that matches it and extracts the groups
        self.regex = re.sub(self.placeholder_r,
                            u"(" + VALID_ARG_R + u")", self.rule)
        self.regex_blocks = policysource.mapping.Mapper.rule_parser(self.regex)
        self.regex_blocks_c = {}
        # Save precompiled regex blocks
        for blk in self.regex_blocks:
            if VALID_ARG_R in blk:
                self.regex_blocks_c[blk] = re.compile(blk)
        # Save pre-computed rule permission set
        if self.regex_blocks[0] in policysource.mapping.AVRULES:
            if any(x in self.regex_blocks[4] for x in u"{}"):
                self.regex_perms = set(
                    self.regex_blocks[4].strip(u"{}").split())
            else:
                self.regex_perms = set([self.regex_blocks[4]])
        else:
            self.regex_perms = None
        # Save the argument names as "argN"
        self.args = [x.strip(u"@").lower()
                     for x in re.findall(self.placeholder_r, self.rule)]

    def extract(self, rule):
        u"""Extract the named arguments from a matching rule."""
        matches = self.match_rule(rule)
        retdict = {}
        if matches:
            # The rule matches the regex: extract the matches
            for i in range(len(matches)):
                # Handle multiple occurrences of the same argument in a rule
                # If the occurrences don't all have the same value, this rule
                # does not actually match the placeholder rule
                if self.args[i] in retdict:
                    # If we have found this argument already
                    if retdict[self.args[i]] != matches[i]:
                        # If the value we just found is different
                        # The rule does not actually match the regex
                        raise ValueError(u"Rule does not match ArgExtractor"
                                         u"expression: \"{}\"".format(
                                             self.regex))
                else:
                    retdict[self.args[i]] = matches[i]
            return retdict
        else:
            # The rule does not match the regex
            raise ValueError(u"Rule does not match ArgExtractor expression: "
                             u"\"{}\"".format(self.regex))

    def match_rule(self, rule):
        u"""Perform a rich comparison between the provided rule and the rule
        expected by the extractor.
        The rule must be passed in as a setools AV/TERule object.

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
        if rule_blocks[0] == u"type_transition":
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
            if regex_blocks[2] == u"self" and rule_blocks[2] != u"self":
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
        elif rule_blocks[0] == u"type_transition":
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
                if rule_objname.strip(u"\"") != regex_blocks[5].strip(u"\""):
                    return None
        ##################################################################
        ######################## All blocks match ########################
        return matches
