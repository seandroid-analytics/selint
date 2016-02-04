#
#    Written by Filippo Bonazzi
#    Copyright (C) 2016 Aalto University
#
#    This file is part of the policysource library.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Lesser General Public License as
#    published by the Free Software Foundation, either version 2.1 of
#    the License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public
#    License along with this program.  If not, see
#    <http://www.gnu.org/licenses/>.
#
"""Class that maps every rule in a SEAndroid policy to the file and line where
it was defined."""

import logging
import re

# TODO: source from config file
# ONLY_MAP_RULES = ("allow", "auditallow", "dontaudit", "neverallow", "type_transition")
# Only map allow for speed, since we are only analysing allow rules for now
# TODO: remove this if/when we need to analyse more rules
ONLY_MAP_RULES = ("allow")


class FileLine(object):
    """Represent a line in a file."""

    def __init__(self, f, l, text):
        self.f = f
        self.l = int(l)
        self.text = text
        self._representation = f + ":" + str(l)
        self.full = self._representation + ": " + self.text

    def __repr__(self):
        return self._representation

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, other):
        return self.f == other.f and self.l == other.l

    def __ne__(self, other):
        return not self == other

    def __lt__(self, other):
        if self.f == other.f:
            return self.l < other.l
        else:
            return self.f < other.f

    def __le__(self, other):
        if self.f == other.f:
            return self.l <= other.l
        else:
            return self.f <= other.f

    def __gt__(self, other):
        if self.f == other.f:
            return self.l > other.l
        else:
            return self.f > other.f

    def __ge__(self, other):
        if self.f == other.f:
            return self.l >= other.l
        else:
            return self.f >= other.f


class MappedRule(object):
    """A rule with associated origin file/line information."""

    def __init__(self, rule, mask, fileline):
        """Initialize a MappedRule.

        rule     - the full rule as a string
        mask     - the base rule as "ruletype subject object:class"
        fileline - the FileLine object representing the original line
        """
        self.rule = rule
        self.mask = mask
        self._fileline = fileline

    def __hash__(self):
        return hash(str(self))

    def __repr__(self):
        return str(self.fileline) + self.rule

    @property
    def fileline(self):
        return self._fileline


class Mapper(object):
    """Class implementing the element to origin file/line mapper."""
    supported_rules = ONLY_MAP_RULES
    # TODO: source from config file?
    AVRULES = ("allow", "auditallow", "dontaudit", "neverallow")
    TERULES = ("type_transition", "type_change",
               "type_member", "typebounds")
    # Valid characters to follow a complement sign ("~"), used when parsing a
    # rule into blocks. Tested the "char in complementable" approach to be
    # 15 times faster than the regex re.match(r'a-zA-Z{', char) approach.
    complementable = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{"

    def __init__(self, policy_conf, attributes, types, classes):
        # Check validity of the policy
        if not policy_conf or not attributes or not types or not classes:
            raise ValueError("Bad parameters.")
        # Setup logger
        self.log = logging.getLogger(self.__class__.__name__)
        # Initialise necessary data
        self.policy_conf = policy_conf
        self.attributes = attributes
        self.types = types
        self.classes = classes

    def get_mapping(self):
        """Parse the policy and map every supported rule to its origin
        file/line.

        Return a dictionary (base, [MappedRule]) where the key is
        the rule as "rule_type subject object:class", and the value is a list
        of MappedRule objects for each full rule matching the base rule."""
        # Initialise variables
        mapping = {}
        group = []
        current_file = ""
        current_line = 0
        previous_line_is_syncline = False
        new_file_syncline = re.compile(r'#line 1 "([^"]+)"')
        new_line_syncline = re.compile(r'#line ([0-9]+)')
        # Read policy.conf file
        with open(self.policy_conf) as policy_conf:
            file_content = policy_conf.read().splitlines()
        # Process each line in the policy.conf file
        for line in file_content:
            # If the previous line was not a syncline, this may be a
            # regular non-macro line or a syncline itself
            if not previous_line_is_syncline:
                # Check if this line marks the start of a new file
                if line.startswith(r'#line 1 "'):
                    # If it does, save the current file/line information
                    current_file = new_file_syncline.match(line).group(1)
                    current_line = 1
                    # Mark that we encountered a syncline
                    previous_line_is_syncline = True
                    # Process the next line
                    continue
                # Check if this line marks a new line in the current file
                if line.startswith(r'#line '):
                    # If it does, save the current line information
                    current_line = int(new_line_syncline.match(line).group(1))
                    # Mark that we encountered a syncline
                    previous_line_is_syncline = True
                    # Process the next line
                    continue
                # If this is just a regular line, increase the line number
                current_line += 1
            # Mark that this is not a syncline and continue processing
            previous_line_is_syncline = False
            # Remove extra whitespace
            line = line.strip()
            # Skip blank lines and comments
            if not line or line.startswith("#"):
                continue
            # If we have no previous text saved in "group", this is a new rule.
            # If this is not one of the rules we are looking for, skip it
            if not group and not line.startswith(self.supported_rules):
                continue
            # If we have something in the group or a new valid rule, process it
            # Strip end-of-line comments
            if "#" in line:
                line = line.split("#")[0].strip()
            # Append the current line to the group
            group.append(line)
            # If we have not found the end of the rule yet, read next line
            if not line.endswith(';'):
                continue
            # We have found the end of the rule, process it
            # Join lines and normalise spaces
            # TODO: evaluate whether to use string concatenation
            # or list append + join/split
            original_rule = " ".join(" ".join(group).split())
            # Expand the rule
            try:
                rules = self.expand_rule(original_rule)
            except ValueError as e:
                self.log.warning(e)
                self.log.warning("Could not expand rule \"%s\" at %s:%s",
                                 original_rule, current_file, current_line)
            else:
                for rule in rules:
                    # Record the file/line mapping for each rule
                    tmp = FileLine(current_file, current_line, original_rule)
                    mpr = MappedRule(rules[rule], rule, tmp)
                    if rule not in mapping:
                        mapping[rule] = [mpr]
                    # TODO: verify that rules are unique and this check is
                    # useless?
                    # elif mpr not in mapping[rule]:
                    else:
                        mapping[rule].append(mpr)
            # Empty the group
            del group[:]
        return mapping

    def expand_rule(self, rule):
        """Expand the given rule by interpreting attributes, sets, complement
        sets and complement types.

        Return a dictionary of rules (base, full) where "base" is the rule as
        "ruletype subject object:class" and full is the full rule."""
        blocks = self.get_rule_blocks(rule)
        # The first block contains the rule type, e.g. "allow"
        if blocks[0] in self.AVRULES:
            rules = self.__expand_avrule(blocks)
        elif blocks[0] in self.TERULES:
            rules = self.__expand_terule(blocks)
        else:
            raise ValueError("Unsupported rule")
        return rules

    def __expand_avrule(self, blocks):
        """Expand an AV rule given as a list of blocks.

        Return a dictionary of rules (base, full) where "base" is the rule as
        "ruletype subject object:class" and full is the full rule."""
        if len(blocks) != 5:
            raise ValueError("Invalid rule")
        # The rule type is block 0 and is static across expansions
        rtype = blocks[0]
        # Get the options for the subject (block 1)
        subjects = self.__expand_block(blocks[1], "type")
        # Get the options for the object (block 2)
        objects = self.__expand_block(blocks[2], "type")
        # Get the options for the class (block 3)
        classes = self.__expand_block(blocks[3], "class")
        # Multiplex the rule up to the class and append the permission set.
        # The permission set is dynamically generated for each class: thus
        # multiplex the class first to generate the permission set
        # the minimum number of times.
        # If the object is "self", we need to substitute it with the subject:
        # in order to do this efficiently split the loop in two, to check the
        # "if" condition only once and not n_cls*n_sub times.
        rules = {}
        if "self" in objects:
            # If subject is "self", substitute the object with the subject
            for cls in classes:
                perms = self.__expand_block(blocks[4], "perms", for_class=cls)
                if len(perms) > 1:
                    permstr = "{ " + " ".join(perms) + " };"
                else:
                    permstr = perms[0] + ";"
                for sub in subjects:
                    base = rtype + " " + sub + " " + sub + ":" + cls
                    full = base + " " + permstr
                    rules[base] = full
        else:
            # Expand the rule normally
            for cls in classes:
                perms = self.__expand_block(blocks[4], "perms", for_class=cls)
                if len(perms) > 1:
                    permstr = "{ " + " ".join(perms) + " };"
                else:
                    permstr = perms[0] + ";"
                for sub in subjects:
                    for obj in objects:
                        base = rtype + " " + sub + " " + obj + ":" + cls
                        full = base + " " + permstr
                        rules[base] = full
        return rules

    def __expand_terule(self, blocks):
        """Expand a TE rule given as a list of blocks.

        Return a dictionary of rules (base, full) where "base" is the rule as
        "ruletype source target:class" and full is the full rule."""
        if len(blocks) == 6:
            # It's a name transition: add default type and object name
            add = blocks[4] + blocks[5] + ";"
        elif len(blocks) == 5:
            # It's a simple type transition: add only the default type
            add = blocks[4] + ";"
        else:
            # Invalid number of blocks
            raise ValueError("Invalid rule")
        # The rule type is block 0 and is static across expansions
        rtype = blocks[0]
        # Get the options for the subject (block 1)
        subjects = self.__expand_block(blocks[1], "type")
        # Get the options for the object (block 2)
        objects = self.__expand_block(blocks[2], "type")
        # Get the options for the class (block 3)
        classes = self.__expand_block(blocks[3], "class")
        # Multiplex the rule up to the class and append the additional data
        rules = {}
        for sub in subjects:
            for obj in objects:
                for cls in classes:
                    base = rtype + " " + sub + " " + obj + ":" + cls
                    full = base + " " + add
                    rules[base] = full
        return rules

    def __expand_block(self, block, role, for_class=None):
        """Expand a rule block given its semantic role.

        Expands attributes, sets ({...}), type/attribute subtraction (-)
        inside sets, type/attribute complement (~), complementary sets
        (~{...}) and wildcard (*).

        Valid roles are "type", "class", "perms"."""
        if role not in ("type", "class", "perms"):
            raise ValueError("Bad block role \"{}\"".format(role))
        # The list of alternatives for the block
        options = None
        # Identify and parse the block
        if block.startswith("{"):
            ############## Complex block ################
            # e.g. "{ attr1 type3 -type1 -attr2 -type2 }"
            add = set()
            remove = set()
            words = block.strip("{}").split()
            # Iterate over all words in the block
            for word in words:
                if word.startswith("-"):
                    # Handle subtraction of attributes
                    if role == "type" and word.lstrip("-") in self.attributes:
                        remove.update(self.attributes[word.lstrip("-")])
                    # Handle every role (including attributes)
                    remove.add(word.lstrip("-"))
                else:
                    # Handle attributes
                    if role == "type" and word in self.attributes:
                        add.update(self.attributes[word])
                    # Handle every role (including attributes)
                    add.add(word)
            # Return all items minus the ones that were subtracted
            options = sorted(add.difference(remove))
            ##############################################
        elif block.startswith("~") or block == "*":
            ####### Complement or catch-all block ########
            # e.g. "~{ type1 type2 type3 }", "~type4", "*"
            # Add the whole set of possible values for the role
            if role == "type":
                add = self.types
            elif role == "class":
                add = set(self.classes.keys())
            elif role == "perms" and for_class:
                add = self.classes[for_class]
            else:
                raise ValueError("Bad class name for permissions block.")
            # Remove the complemented values
            remove = set(block.strip("~{}").split())
            # Return all values minus the ones that were complemented
            options = sorted(add.difference(remove))
            ##############################################
        else:
            ################ Simple block ################
            # e.g. "attr1", "type1"
            if role == "type" and block in self.attributes:
                # Handle attributes
                options = sorted(self.attributes[block].union([block]))
            else:
                # Return the simple block
                options = [block]
            ##############################################
        return options

    def get_rule_blocks(self, rule):
        """Split the supplied rule in the component blocks.

        Returns a list of blocks, e.g.:
        ["rule type", "subject", "object", "class", "perms"] """
        if rule.count("{") != rule.count("}"):
            raise ValueError("Mismatched separators in \"{}\"".format(rule))
        # The level of curly bracket nesting
        nest_lvl = 0
        # The current block
        block = ""
        # Split the rule in rule_type and rest of the rule
        rule_type, rule_early_split = rule.split(" ", 1)
        # Initialise the list of blocks with the rule type
        blocks = [rule_type]
        # Flag to indicate that a new block must be complemented
        # (i.e. prepended with the complement sign). It is set when the
        # current character is the complement sign ("~"), and reset after
        # parsing the following character. If the following character is
        # the start of a new block and a valid complementable character,
        # (i.e. "a-zA-Z{"), the new block is complemented.
        complement_next_block = False
        # Parse the rest of the rule character by character, ignoring the
        # final semicolon and the colon between blocks (e.g. "obj:cls")
        for char in rule_early_split.rstrip(';').replace(":", " "):
            # If the previous character was the complement character,
            # but the current one is not the start of a complementable block
            if complement_next_block and char not in self.complementable:
                raise ValueError("Bad complement sign in \"{}\"".format(rule))
            # Found a complement sign
            if char == "~":
                # If we are already inside one or more levels of curly brackets
                if nest_lvl != 0:
                    # This should not happen
                    raise ValueError(
                        "Nested complement group in \"{}\"".format(rule))
                else:
                    # Prepare to complement the next block
                    complement_next_block = True
            # Found an opening curly bracket
            elif char == "{":
                # Increase the nesting level
                nest_lvl += 1
                # If we are entering our first level of curly brackets,
                # initialize the block. If we were already inside a level of
                # curly brackets, ignore the opening bracket to simplify the
                # block to a single level of brackets.
                if nest_lvl == 1:
                    # If we have some data saved in block, it must be a
                    # non-nested block, otherwise we would have found the
                    # closing curly bracket first.
                    if block:
                        # If so, finalize the block and add it to the list
                        blocks.append(block.strip())
                    # If the previous character was the complement
                    if complement_next_block:
                        # Initialize this block as a complemented block
                        block = "~{"
                        # Reset the complement flag
                        complement_next_block = False
                    else:
                        # Initialize this block as a normal block
                        block = "{"
            # Found a closing curly bracket
            elif char == "}":
                # If we are in at least one level of curly brackets
                if nest_lvl > 0:
                    # Decrease the nesting level
                    nest_lvl -= 1
                    # If we exited the block
                    if nest_lvl == 0:
                        # Finalize the block and append it to the list
                        blocks.append(block + "}")
                        # Initialize a new empty block
                        block = ""
                else:
                    # We found an unmatched closing bracket
                    raise ValueError(
                        "Mismatched separators in \"{}\"".format(rule))
            # Found a generic character
            else:
                # If we are inside at least one level of curly brackets
                if nest_lvl > 0:
                    # Add the char to the current block, normalizing whitespace
                    if char != " " or not block.endswith(" "):
                        block += char
                # If we are outside all brackets, space is the separator: if
                # this is a space we might have just finished a block
                elif char == " ":
                    # If we have some data saved in block, it must be a
                    # non-nested block, otherwise we would have found the
                    # closing curly bracket first.
                    if block:
                        # If so, finalize the block and add it to the list
                        blocks.append(block.strip())
                        # Initialize a new empty block
                        block = ""
                else:
                    # If this is not a space, add it to the current block
                    # If the previous character was the complement sign,
                    # initialize a new complemented block
                    if complement_next_block:
                        block = "~"
                        complement_next_block = False
                    block += char
        # If the last block was a simple block without curly brackets, it is
        # saved in block and still needs to be processed
        if block:
            blocks.append(block.strip())
        return blocks
