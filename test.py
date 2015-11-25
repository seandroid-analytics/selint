#!/usr/bin/python2
#
#    Written by Filippo Bonazzi
#    Copyright (C) 2015 Aalto University
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
"""Test various functions for correctness"""

import setools
import setools.policyrep
import os.path
import policysource.policy as p
import policysource.macro as m
import logging
import sys
import copy
import subprocess
from tempfile import mkdtemp
import re
import shutil


def get_rule_blocks(rule):
    """Split the supplied rule in the component blocks.

    Returns a list of blocks.
    e.g. ["rule type", "subject", "object", "class", "perms"]"""
    if rule.count("{") != rule.count("}"):
        raise ValueError("Mismatched separators in \"{}\"".format(rule))
    nest_lvl = 0
    block = ""
    rule_type, rule_early_split = rule.split(" ", 1)
    blocks = [rule_type]
    complement_next_block = False
    for char in rule_early_split.rstrip(';').replace(":", " "):
        # If the previous character was the complement character,
        # but the current one is not the started of a complementable block
        if complement_next_block and not re.match(r"[a-zA-Z{]", char):
            raise ValueError("Bad complement sign in \"{}\"".format(rule))
        if char == "~":
            # Found a complement sign
            if nest_lvl != 0:
                raise ValueError(
                    "Nested complement group in \"{}\"".format(rule))
            else:
                complement_next_block = True
        elif char == "{":
            # Found a left separator
            nest_lvl += 1
            if nest_lvl == 1:
                if block:
                    # If we have a previous block, add it to the list
                    blocks.append(block.strip())
                if complement_next_block:
                    block = "~{"
                    complement_next_block = False
                else:
                    block = "{"
        elif char == "}":
            if nest_lvl > 0:
                nest_lvl -= 1
                if nest_lvl == 0:
                    blocks.append(block + "}")
                    block = ""
            else:
                # We found a rsep but no corresponding lsep
                raise ValueError(
                    "Mismatched separators in \"{}\"".format(rule))
        else:
            # Generic character
            if nest_lvl > 0:
                # If we are inside a block, add the char to the current block
                if char != " " or not block.endswith(" "):
                    block += char
            elif char == " ":
                # If we are outside a block, the space is the separator
                if block:
                    blocks.append(block.strip())
                    block = ""
            else:
                # If this is not a space, add it to the current block
                # If the previous character was the complement, complement this
                # block
                if complement_next_block:
                    block = "~"
                    complement_next_block = False
                block += char
    # If we didn't complete our previous block
    if block:
        blocks.append(block.strip())
    return blocks


def expand_block(block, block_type, attributes=None, types=None, classes=None, for_class=None):
    """Expand a rule block given its semantic role.

    Expands attributes, sets ({...}), subtract (-), complement (~),
    complementary sets (~{...}) and wildcard (*)."""
    # The list of alternatives for the block
    options = None
    if block.startswith("{"):
        ############### Complex block ###############
        if block_type == "type" and not attributes:
            raise ValueError("Bad block type")
        add = set()
        remove = set()
        words = block.strip("{}").split()
        # Iterate over all words in the block
        for word in words:
            if word.startswith("-"):
                # Handle subtraction of both attributes and simple types
                if block_type == "type" and word.lstrip("-") in attributes:
                    remove.update(attributes[word.lstrip("-")])
                remove.add(word.lstrip("-"))
            else:
                # Handle attributes and types
                if block_type == "type" and word in attributes:
                    add.update(attributes[word])
                add.add(word)
        # Return all items minus the ones that were subtracted
        options = sorted(add.difference(remove))
        ##############################################
    elif block.startswith("~") or block == "*":
        ####### Complement or catch-all block ########
        # Add the whole list of items, then remove the complement
        if block_type == "type" and types:
            add = types
        elif block_type == "class" and classes:
            add = set(classes.keys())
        elif block_type == "perms" and classes and for_class:
            add = classes[for_class]
        else:
            raise ValueError("Bad block type")
        # Remove the complement
        remove = set(block.strip("~{}").split())
        # Return all items minus the ones that were complemented
        options = sorted(add.difference(remove))
        ##############################################
    else:
        ################ Simple block ################
        if block_type == "type" and block in attributes:
            # Handle attributes
            options = sorted(attributes[block].union([block]))
        else:
            # Return the simple block
            options = [block]
        ##############################################
    return options


def expand_avrule(blocks, policy):
    """Return a dictionary of rules expanded from a list of AVRule blocks.

    The dictionary maps ("ruletype subject object:class", full rule repr)."""
    if len(blocks) != 5:
        raise ValueError("Invalid rule")
    # The rule type is static
    rtype = blocks[0]
    # The first option is the rule name, to follow the blocks[] notation
    options = [blocks[0]]
    # Get the options for the subject
    sub = expand_block(blocks[1], "type", attributes=policy.attributes,
                       types=policy.types)
    options.append(sub)
    # Get the options for the object
    obj = expand_block(blocks[2], "type", attributes=policy.attributes,
                       types=policy.types)
    options.append(obj)
    # Get the options for the class
    cls = expand_block(blocks[3], "class", classes=policy.classes)
    options.append(cls)
    # Expand the rule up to the class
    rules = {}
    if "self" in options[2]:
        # If the rule has target "self", expand the object to the proper
        # subject
        for cls in options[3]:
            perms = expand_block(blocks[4], "perms",
                                 classes=policy.classes,
                                 for_class=cls)
            if len(perms) > 1:
                permstr = "{ " + " ".join(perms) + " };"
            else:
                permstr = perms[0] + ";"
            for sub in options[1]:
                base = rtype + " " + sub + " " + sub + ":" + cls
                full = base + " " + permstr
                rules[base] = full
    else:
        # Expand the rule fully
        for cls in options[3]:
            perms = expand_block(blocks[4], "perms",
                                 classes=policy.classes,
                                 for_class=cls)
            if len(perms) > 1:
                permstr = "{ " + " ".join(perms) + " };"
            else:
                permstr = perms[0] + ";"
            for sub in options[1]:
                for obj in options[2]:
                    base = rtype + " " + sub + " " + obj + ":" + cls
                    full = base + " " + permstr
                    rules[base] = full
    return rules


def expand_terule(blocks, policy):
    """Return a dictionary of rules expanded from a list of TERule blocks.

    The dictionary maps ("ruletype source target:class", full rule repr)."""
    if len(blocks) == 6:
        # It's a name transition: add default type and object name
        add = blocks[4] + blocks[5] + ";"
    elif len(blocks) == 5:
        # It's a simple type transition: add only the default type
        add = blocks[4] + ";"
    else:
        # Invalid number of blocks
        raise ValueError("Invalid rule")
    # The rule type is static
    rtype = blocks[0]
    # The first option is the rule name, to follow the blocks[] notation
    options = [blocks[0]]
    # Get the options for the subject
    sub = expand_block(blocks[1], "type", attributes=policy.attributes,
                       types=policy.types)
    options.append(sub)
    # Get the options for the object
    obj = expand_block(blocks[2], "type", attributes=policy.attributes,
                       types=policy.types)
    options.append(obj)
    # Get the options for the class
    cls = expand_block(blocks[3], "class", classes=policy.classes)
    options.append(cls)
    # Expand the rule up to the class
    rules = {}
    for sub in options[1]:
        for obj in options[2]:
            for cls in options[3]:
                base = rtype + " " + sub + " " + obj + ":" + cls
                full = base + " " + add
                rules[base] = full
    return rules


def expand_rule(rule, policy):
    """ Attributes must be a dictionary of (attribute, [types])"""
    blocks = get_rule_blocks(rule)
    if blocks[0] in ("allow", "auditallow", "dontaudit", "neverallow"):
        rules = expand_avrule(blocks, policy)
    elif blocks[0] in ("type_transition", "type_change", "type_member", "typebounds"):
        rules = expand_terule(blocks, policy)
    else:
        raise ValueError("Unsupported rule")
    return rules


def test_source_policy():
    pol = p.SourcePolicy(p.BASE_DIR_GLOBAL, p.POLICYFILES_GLOBAL)
    if len(pol.macro_defs) != 61:
        print "Some macro definitions were not recognized!"
        print "Definitions recognized: {}".format(len(pol.macro_defs))
        return False
    if len(pol.macro_usages) != 1103:
        print "Some macro usages were not recognized!"
        print "Usages recognized: {}".format(len(pol.macro_usages))
        return False
    shutil.copyfile(pol._policyconf, "/home/bonazzf1/tmp/policy.conf")
    ##### Reparse #####
    mapping = {}
    group = []
    current_file = ""
    current_line = ""
    with open("/home/bonazzf1/tmp/policy.conf") as policy_conf:
        file_content = policy_conf.read().splitlines()
    for line in file_content:
        # Remove extra whitespace
        line = line.strip()
        # Skip blank lines
        if not line:
            continue
        # If this line is not a comment
        if not line.startswith("#"):
            if not group and not line.startswith(("allow", "auditallow", "dontaudit", "neverallow", "type_transition")):
                # If this rule is new and not one of those we are looking for
                continue
            else:
                # If we have something in the group or a new valid rule
                # Remove possible in-line comments
                if "#" in line:
                    line = re.sub(r'\s*#.*', '', line)
                # Append the current line to the group
                group.append(line)
                # If we have not found the end of the rule yet, read next line
                if not line.endswith(';'):
                    continue
                # We have found the end of the rule, process it
                original_rule = " ".join(" ".join(group).split())
                # Expand the rule
                try:
                    rules = expand_rule(original_rule, pol)
                except (ValueError, IndexError) as e:
                    # TODO:log
                    print e
                    print "Could not expand rule \"{}\"".format(original_rule)
                else:
                    for rule in rules.keys():
                        # Record the file/line mapping for each rule
                        tpl = (rules[rule], current_file, current_line)
                        if not rule in mapping:
                            mapping[rule] = [tpl]
                        elif not tpl in mapping[rule]:
                            mapping[rule].append(tpl)
                # Empty the group
                del group[:]
                # Read the next line
                continue
        # Check if this line marks the start of a new file
        elif line.startswith(r'#line 1 "'):
            # If it does, process it and skip to the next line right away
            current_file = re.match(r'#line 1 "([^"]+)"', line).group(1)
            current_line = 1
        # Check if this line marks a new line in the current file
        elif line.startswith(r'#line '):
            # If it does, process it and skip to the next line right away
            current_line = int(re.match(r'#line ([0-9]+)', line).group(1))
    #mapfile = open("mapfile", "w")
    # for m in mapping:
    #    mapfile.write(str(m) + "\n\t" + str(mapping[m]) + "\n")
    # mapfile.close()
    ##### END Reparse #####
    nallow = 0
    nauditallow = 0
    ndontaudit = 0
    nneverallow = 0
    ntypetrans = 0
    touched = set()
    #mapped = open("mapped.txt", "w")
    #notmapped = open("notmapped.txt", "w")
    for rule in pol.policy.terules():
        printedr = "{0.ruletype} {0.source} {0.target}:{0.tclass}".format(rule)
        if printedr in mapping:
            touched.add(printedr)
            #mapped.write(str(rule) + "\n")
            # for tpl in mapping[printedr]:
            #    mapped.write("\t{} {}:{}\n".format(tpl[0], tpl[1], tpl[2]))
            if rule.ruletype == "allow":
                nallow += 1
            if rule.ruletype == "auditallow":
                nauditallow += 1
            if rule.ruletype == "dontaudit":
                ndontaudit += 1
            if rule.ruletype == "neverallow":
                nneverallow += 1
            if rule.ruletype == "type_transition":
                ntypetrans += 1
        else:
            #notmapped.write(printedr + "\n")
            pass
    # mapped.close()
    # notmapped.close()
    nmapped_allow = 0
    nmapped_auditallow = 0
    nmapped_dontaudit = 0
    nmapped_neverallow = 0
    nmapped_typetrans = 0
    #nottouched = open("nottouched.txt", "w")
    for rule_name, rule in mapping.iteritems():
        if rule_name.startswith("allow"):
            nmapped_allow += 1
        if rule_name.startswith("auditallow"):
            nmapped_auditallow += 1
        if rule_name.startswith("dontaudit"):
            nmapped_dontaudit += 1
        if rule_name.startswith("neverallow"):
            nmapped_neverallow += 1
        if rule_name.startswith("type_transition"):
            nmapped_typetrans += 1
        # if rule_name not in touched:
        #    nottouched.write("{} ".format(rule_name))
        #    for i in rule:
        #        nottouched.write("{}:{}\n".format(i[0], i[1]))
    # nottouched.close()
    print "{0}/{1} rules in mapping found".format(nallow + nauditallow +
                                                  ndontaudit + nneverallow +
                                                  ntypetrans, len(mapping))
    print "Allow: {0}/{1}/{2}".format(
        nallow, pol.policy.allow_count, nmapped_allow)
    print "Auditallow: {0}/{1}/{2}".format(
        nauditallow, pol.policy.auditallow_count, nmapped_auditallow)
    print "Dontaudit: {0}/{1}/{2}".format(
        ndontaudit, pol.policy.dontaudit_count, nmapped_dontaudit)
    print "Neverallow: {0}/{1}/{2}".format(
        nneverallow, pol.policy.neverallow_count, nmapped_neverallow)
    print "Type transition: {0}/{1}/{2}".format(
        ntypetrans, pol.policy.type_transition_count, nmapped_typetrans)
    return True


def main():
    logging.basicConfig()  # level=logging.DEBUG)  # , format='%(message)s')
    if not test_source_policy():
        sys.exit(1)


if __name__ == "__main__":
    main()
