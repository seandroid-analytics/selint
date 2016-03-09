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
"""Module that maps every rule in a SEAndroid policy to the file and line where
it was defined."""

import logging
import re

# TODO: source from config file
ONLY_MAP_RULES = ("allow", "auditallow", "dontaudit",
                  "neverallow", "type_transition")


# TODO: source from config file?
AVRULES = ("allow", "auditallow", "dontaudit", "neverallow")
TERULES = ("type_transition", "type_change",
           "type_member", "typebounds")


class Mapping(object):
    """Contains dictionaries that map rules to their fileline origin and
    filelines to their original line as written in the source file."""

    @staticmethod
    def split_fileline(fileline):
        """Split a fileline represented as a string into a (file, line) list.

        e.g. "/some:path/file:42" -> ["/some:path/file", "42"]
        """
        return fileline.rsplit(":", 1)

    @staticmethod
    def get_fileline_file(fileline):
        return fileline.rsplit(":", 1)[0]

    @staticmethod
    def get_fileline_line(fileline):
        return int(fileline.rsplit(":", 1)[1])

    def __init__(self, rules, lines):
        self.rules = rules
        self.lines = lines


class FileLine(object):
    """Represent a line in a file."""

    def __init__(self, f, l, text):
        # Represent the FileLine as a single string:
        # "file.te:12: allow sometype someothertype:someclass someperms;"
        index = 0
        self._f = (index, index + len(f))
        index += len(f) + 1
        self._l = (index, index + len(str(l)))
        index += len(str(l)) + 2
        self._t = (index, index + len(text))
        self._full = f + ":" + str(l) + ": " + text

    @property
    def f(self):
        return self.full[self._f[0]:self._f[1]]

    @property
    def l(self):
        return int(self.full[self._l[0]:self._l[1]])

    @property
    def t(self):
        return self.full[self._t[0]:self._t[1]]

    @property
    def full(self):
        return self._full

    def __repr__(self):
        return self.full[:self._l[1]]

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

    def __init__(self, rule, fileline):
        """Initialize a MappedRule.

        rule     - the rule as a string
        fileline - the origin file/line of the rule represented as a string
        e.g. "/the/path/to/the/file.te:42"
        """
        self.rule = rule
        self.fileline = fileline

    def __hash__(self):
        return hash(str(self))

    def __repr__(self):
        return str(self.fileline) + ": " + str(self.rule)


class TERule(object):
    """A TE rule.

    Currently only supports type transitions and name transitions."""

    def __init__(self, blocks):
        """Initialise the rule from a list of blocks."""
        # Type transitions have 5 blocks, name transitions have 6
        if len(blocks) not in (5, 6):
            # Invalid number of blocks
            raise ValueError(
                "Invalid number of blocks ({})".format(len(blocks)))
        if not all(blocks):
            # If any of the blocks is empty or none
            raise ValueError("Invalid block(s)")
        # "rtype source target:tclass deftype"
        self._str = blocks[0] + " " + blocks[1] + " " + blocks[2] + ":" +\
            blocks[3] + " " + blocks[4]
        # Save the start:end indexes for slicing. end is NOT INCLUSIVE
        index = 0
        # Block 0 is the rule type
        self._rtype = (index, index + len(blocks[0]))
        index += len(blocks[0]) + 1
        # Block 1 is the rule source
        self._source = (index, index + len(blocks[1]))
        index += len(blocks[1]) + 1
        # Block 2 is the rule target
        self._target = (index, index + len(blocks[2]))
        index += len(blocks[2]) + 1
        # Block 3 is the rule class
        self._tclass = (index, index + len(blocks[3]))
        index += len(blocks[3]) + 1
        # Block 4 is the rule default type
        self._deftype = (index, index + len(blocks[4]))
        index += len(blocks[4]) + 1
        # Block 5 is the rule object name (only name transitions)
        if len(blocks) == 6:
            objname = blocks[5].strip("\"\'")
            self._str += " \"" + objname + "\";"
            self._objname = (index + 2, index + 2 + len(objname))
        else:
            self._str += ";"
            self._objname = None

    @property
    def rtype(self):
        """Get the rule type.

        Currently only type_transition (type transitions and name transitions)
        is supported."""
        return self._str[self._rtype[0]:self._rtype[1]]

    @property
    def source(self):
        """Get the rule source."""
        return self._str[self._source[0]:self._source[1]]

    @property
    def target(self):
        """Get the rule target."""
        return self._str[self._target[0]:self._target[1]]

    @property
    def tclass(self):
        """Get the rule class."""
        return self._str[self._tclass[0]:self._tclass[1]]

    @property
    def deftype(self):
        """Get the rule default type."""
        return self._str[self._deftype[0]:self._deftype[1]]

    @property
    def is_name_trans(self):
        """Returns True if the rule is a name transition."""
        return self._objname is not None

    @property
    def objname(self):
        """If the rule is a name transition, returns the object name."""
        if self._objname:
            return self._str[self._objname[0]:self._objname[1]]
        else:
            return None

    @property
    def up_to_class(self):
        """Print a representation of the rule up to the class.
        e.g.:
        "allow adbd powerctl_prop:property_service"
        """
        return self._str[self._rtype[0]:self._tclass[1]]

    def __repr__(self):
        return self._str

    def __eq__(self, other):
        return str(self) == str(other)

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(str(self))


class AVRule(object):
    """An AV rule."""

    def __init__(self, blocks):
        """Initialise the rule from a list of blocks.

        If the last block (the permission block) contains multiple entries,
        it must be represented as a string containing a space-separated
        list of permissions, enclosed in curly brackets.

        e.g.: blocks =
        ["allow", "initrc_t", "exec_t", "file", "{ getattr read execute }"]
        ["allow", "initrc_t", "exec_t", "file", "append"]
        """
        if len(blocks) != 5:
            # Invalid number of blocks
            raise ValueError(
                "Invalid number of blocks ({})".format(len(blocks)))
        if not all(blocks):
            # If any of the blocks is empty or none
            raise ValueError("Invalid block(s)")
        # Block 0 is the rule type
        self._rtype = blocks[0]
        # Block 1 is the rule source
        self._source = blocks[1]
        # Block 2 is the rule target
        self._target = blocks[2]
        # Block 3 is the rule class
        self._tclass = blocks[3]
        # Block 4 is the set of permissions
        self._perms = blocks[4]
        self._permset = frozenset(blocks[4].strip("{}").split())

    @property
    def rtype(self):
        """Get the rule type.

        Currently only type_transition (type transitions and name transitions)
        is supported."""
        return self._rtype

    @property
    def source(self):
        """Get the rule source."""
        return self._source

    @property
    def target(self):
        """Get the rule target."""
        return self._target

    @property
    def tclass(self):
        """Get the rule class."""
        return self._tclass

    @property
    def perms(self):
        """Get the rule permission string."""
        return self._perms

    @property
    def permset(self):
        """Get the rule permissions as a set."""
        return self._permset

    @property
    def up_to_class(self):
        """Print a representation of the rule up to the class.
        e.g.:
        "allow adbd powerctl_prop:property_service"
        """
        if not hasattr(self, "_up_to_class"):
            s = "{0.rtype} {0.source} {0.target}:{0.tclass}"
            self._up_to_class = s.format(self)
        return self._up_to_class

    def __repr__(self):
        if not hasattr(self, "_str"):
            self._str = "{0.rtype} {0.source} {0.target}:{0.tclass} ".format(
                self)
            if len(self.permset) > 1:
                self._str += "{ " + " ".join(sorted(self.permset)) + " };"
            else:
                self._str += " ".join(self.permset) + ";"
        return self._str

    def __eq__(self, other):
        return self.rtype == other.rtype and self.source == other.source and\
            self.target == other.target and self.tclass == other.tclass and\
            self.permset == other.permset

    def __ne__(self, other):
        return not self == other

    def __hash__(self, other):
        return hash(str(self))


class Mapper(object):
    """Class implementing the element to origin file/line mapper."""
    supported_rules = ONLY_MAP_RULES
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
        mapping_rules = {}
        mapping_lines = {}
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
                # tmp = FileLine(current_file, current_line, original_rule)
                tmp = current_file + ":" + str(current_line)
                # Save the original rule found at file:line
                mapping_lines[tmp] = original_rule
                for rule in rules:
                    # Record the file/line mapping for each rule
                    mpr = MappedRule(rules[rule], tmp)
                    # TODO: decide whether to do tuples or classes
                    # mpr = (rules[rule], tmp)
                    if rule not in mapping_rules:
                        mapping_rules[rule] = [mpr]
                    # TODO: verify that rules are unique and this check is
                    # useless?
                    # elif mpr not in mapping[rule]:
                    else:
                        mapping_rules[rule].append(mpr)
            # Empty the group
            del group[:]
        # Generate the Mapping object
        return Mapping(mapping_rules, mapping_lines)

    def rule_factory(self, string):
        """Parse the string representation of a rule.
        Return the given rule as an object (AVRule, TERule, ...).

        Raises ValueError if the rule is invalid or unsupported."""
        if string.startswith(self.supported_rules):
            blocks = self.get_rule_blocks(string)
            # The first block contains the rule type, e.g. "allow"
            if blocks[0] in AVRULES:
                rule = AVRule(blocks)
            elif blocks[0] in TERULES:
                rule = TERule(blocks)
            else:
                raise ValueError("Unsupported rule")
        else:
            raise ValueError("Unsupported rule")
        return rule

    def rule_parser(self, string):
        """Parse the string representation of a rule.
        Return the given rule as a tuple of blocks.

        Raises ValueError if the rule is invalid or unsupported."""
        if string.startswith(self.supported_rules):
            return self.get_rule_blocks(string)
        else:
            raise ValueError("Unsupported rule")

    def expand_rule(self, rule):
        """Expand the given rule by interpreting attributes, sets, complement
        sets and complement types.

        Return a dictionary of rules {base: full} where "base" is the rule as
        "ruletype subject object:class" and "full" is the full string
        representation."""
        # TODO: update docstring (no AVRule/TERule, strings instead)
        if rule.startswith(self.supported_rules):
            blocks = self.get_rule_blocks(rule)
            # The first block contains the rule type, e.g. "allow"
            if blocks[0] in AVRULES:
                rules = self.__expand_avrule(blocks)
            elif blocks[0] in TERULES:
                rules = self.__expand_terule(blocks)
            else:
                raise ValueError("Unsupported rule")
        else:
            raise ValueError("Unsupported rule")
        return rules

    def __expand_avrule(self, blocks):
        """Expand an AV rule given as a list of blocks.

        Return a dictionary of rules {base: full} where "base" is the rule
        as "ruletype subject object:class" and "full" is the full string
        representation."""
        # TODO: update docstring (no AVRule, string instead)
        if len(blocks) != 5:
            raise ValueError("Invalid rule")
        # The rule type is block 0 and is static across expansions
        rtype = blocks[0]
        # Get the options for the subject (block 1)
        subjects = self.expand_block(blocks[1], "type")
        # Get the options for the object (block 2)
        objects = self.expand_block(blocks[2], "type")
        # Get the options for the class (block 3)
        classes = self.expand_block(blocks[3], "class")
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
                perms = self.expand_block(blocks[4], "perms", for_class=cls)
                if len(perms) > 1:
                    permstr = "{ " + " ".join(perms) + " }"
                else:
                    permstr = perms[0]
                for sub in subjects:
                    base = rtype + " " + sub + " " + sub + ":" + cls
                    # rules[base] = AVRule([rtype, sub, sub, cls, permstr])
                    rules[base] = base + " " + permstr + ";"
        else:
            # Expand the rule normally
            for cls in classes:
                perms = self.expand_block(blocks[4], "perms", for_class=cls)
                if len(perms) > 1:
                    permstr = "{ " + " ".join(perms) + " }"
                else:
                    permstr = perms[0]
                for sub in subjects:
                    for obj in objects:
                        base = rtype + " " + sub + " " + obj + ":" + cls
                        # rules[base] = AVRule([rtype, sub, obj, cls, permstr])
                        rules[base] = base + " " + permstr + ";"
        return rules

    def __expand_terule(self, blocks):
        """Expand a TE rule given as a list of blocks.

        Currently only type_transition (type transition and name transition)
        rules are supported.

        Return a dictionary of rules {base: full} where "base" is the rule
        as "ruletype source target:class" and "full" is the full string
        representation."""
        # TODO: remove commented lines
        if len(blocks) == 6:
            # It's a name transition
            is_name_trans = True
            # deftype = blocks[4]
            # objname = blocks[5]
            add = blocks[4] + " " + blocks[5] + ";"
        elif len(blocks) == 5:
            # It's a simple type transition
            is_name_trans = False
            # deftype = blocks[4]
            add = blocks[4] + ";"
        else:
            # Invalid number of blocks
            raise ValueError("Invalid rule")
        # The rule type is block 0 and is static across expansions
        rtype = blocks[0]
        # Get the options for the subject (block 1)
        subjects = self.expand_block(blocks[1], "type")
        # Get the options for the object (block 2)
        objects = self.expand_block(blocks[2], "type")
        # Get the options for the class (block 3)
        classes = self.expand_block(blocks[3], "class")
        # Multiplex the rule up to the class and append the additional data
        rules = {}
        # TODO: remove commented lines, simplify loop
        # This is a name transition: supply the object name as well
        if is_name_trans:
            for sub in subjects:
                for obj in objects:
                    for cls in classes:
                        base = rtype + " " + sub + " " + obj + ":" + cls
                        # rules[base] = TERule(
                        #    [rtype, sub, obj, cls, deftype, objname])
                        rules[base] = base + " " + add
        # This is a regular type transition
        else:
            for sub in subjects:
                for obj in objects:
                    for cls in classes:
                        base = rtype + " " + sub + " " + obj + ":" + cls
                        # rules[base] = TERule([rtype, sub, obj, cls, deftype])
                        rules[base] = base + " " + add
        return rules

    def expand_block(self, block, role, for_class=None):
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

    @staticmethod
    def get_rule_blocks(rule):
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
            if complement_next_block and char not in Mapper.complementable:
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
