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
"""Class providing an abstraction for a source SEAndroid policy"""

from tempfile import mkdtemp
import subprocess
import os.path
import re
import logging
import setools
import setools.policyrep
from policysource.macro import MacroInPolicy, M4MacroError
import policysource.mapping
import policysource.macro_plugins


class SourcePolicy(object):
    """Class representing a source SELinux policy."""
    # pylint: disable=too-many-instance-attributes
    regex_macrodef = re.compile(r'^define\(\`([^\']+)\',')
    regex_usageargstring = r'(\(.*\));?'

    def __init__(self, policyfiles, extra_defs):
        """Construct a SourcePolicy object by parsing the supplied files.

        Keyword arguments:
        policyfiles --  The policy files as a list of absolute paths."""
        # Setup logging
        self.log = logging.getLogger(self.__class__.__name__)
        # Setup useful infrastructure
        self._policyconf = None
        # Set up a general-purpose macro expander for internal use
        self._expander = None
        # Set the extra M4 defs ("-D target_build_variant=user", ...)
        self.extra_defs = extra_defs
        # Create a temporary work directory
        self._tmpdir = mkdtemp()
        self.log.debug("Created temporary directory \"%s\".", self._tmpdir)

        # Get a list of policy files with full paths
        self._policy_files = policyfiles
        if not self._policy_files:
            raise RuntimeError(
                "Could not find any policy files to parse, aborting...")
        # Parse the macros and macro usages in the policy
        self._macro_defs = self.__find_macro_defs__(self._policy_files)
        if self._macro_defs is None:
            raise RuntimeError("Error parsing macro definitions, aborting...")
        self._macro_usages = self.__find_macro_usages__(self._policy_files,
                                                        self._macro_defs)
        if self._macro_usages is None:
            raise RuntimeError("Error parsing macro usages, aborting...")
        # Create the policyconf
        self._policyconf = self.__create_policyconf__(self._policy_files)
        if not self._policyconf:
            raise RuntimeError(
                "Could not create the policy.conf file, aborting...")
        # Create the actual policy instance
        self._policy = setools.policyrep.SELinuxPolicy(self.policyconf)
        # Initialise some useful variables
        self._attributes = self.__compute_attributes()
        self._types = self.__compute_types()
        self._classes = self.__compute_classes()
        # Build the origin file/line mapping
        mapper = policysource.mapping.Mapper(self.policyconf, self.attributes,
                                             self.types, self.classes)
        self._mapping = mapper.get_mapping()
        if not self._mapping:
            raise RuntimeError(
                "Error creating the file/line mapping, aborting...")

    def __del__(self):
        # Remove the macro usages and definitions to remove the associated
        # temporary files
        del self._macro_usages
        del self._macro_defs
        # Delete the policy.conf file
        if self.policyconf:
            try:
                os.remove(self.policyconf)
            except OSError:
                self.log.warning("Trying to remove policy.conf file \"%s\"... "
                                 "failed!", self.policyconf)
            else:
                self.log.debug("Trying to remove policy.conf file \"%s\"... "
                               "done!", self.policyconf)
        # Try to remove the temporary directory
        if self._tmpdir:
            try:
                os.rmdir(self._tmpdir)
            except OSError:
                self.log.warning("Trying to remove the temporary directory "
                                 "\"%s\"... failed!", self._tmpdir)
            else:
                self.log.debug("Trying to remove the temporary directory "
                               "\"%s\"... done!", self._tmpdir)

    def __create_policyconf__(self, policy_files):
        """Process the separate policy files with m4 and return a single
        policy.conf file"""
        # Prepare the output file
        policyconf = os.path.join(self._tmpdir, "policy.conf")
        # Prepare the m4 command line
        command = ['m4']
        for definition in self.extra_defs:
            command.extend(["-D", definition])
        command.extend(['-s'])
        command.extend(policy_files)
        # Try to run m4
        try:
            with open(policyconf, "w") as pcf:
                subprocess.check_call(command, stdout=pcf)
        except subprocess.CalledProcessError as e:
            self.log.error(e.message)
            self.log.error(
                "Could not create the policy.conf \"%s\" file", policyconf)
            policyconf = None
        return policyconf

    def __find_macro_files__(self, policy_files):
        """Find files that contain m4 macro definitions."""
        # Regex to match the macro definition string
        macro_files = []
        for single_file in policy_files:
            with open(single_file, 'r') as macro_file:
                for line in macro_file:
                    # If this file contains at least one macro definition,
                    # append it to the list of macro files and skip to
                    # the next policy file
                    if self.regex_macrodef.search(line):
                        macro_files.append(single_file)
                        break
        return macro_files

    def __find_macro_defs__(self, policy_files):
        """Get a dictionary containing all the m4 macros defined in the files.

        The dictionary maps the macro name to a M4Macro object."""
        macro_files = self.__find_macro_files__(policy_files)
        parser = policysource.macro_plugins.M4MacroParser(
            tmpdir=None, extra_defs=self.extra_defs)
        macros = parser.parse(macro_files)
        self._expander = parser.macro_expander
        return macros

    @staticmethod
    def __split_macro_usage_args__(argstring):
        """Return a list of macro usage arguments, respecting grouping by
        curly brackets and m4-style quotes.

        e.g. The following argstring
        "({ appdomain, -isolated_app }, something, `third argument')"
        would be split in 3 arguments as such
        ["{ appdomain, -isolated_app }", "something", "`third argument'"]
        """
        group = ""
        args = []
        nested_curly = 0
        nested_quotes = 0
        nested_parentheses = 0
        for c in argstring:
            # Found opening parenthesis
            if c == "(":
                # If this is the outermost parenthesis, drop it
                # Otherwise keep it
                if nested_quotes or nested_curly or nested_parentheses:
                    group += c
                # If we are outside nested quotes or brackets, this is a
                # special character
                if not nested_quotes and not nested_curly:
                    nested_parentheses += 1
            # Found opening curly bracket
            elif c == "{":
                # If we are outside nested quotes, this is a special character
                if not nested_quotes:
                    # Increase nest level
                    nested_curly += 1
                group += c
            # Found opening quote
            elif c == "`":
                # If we are outside nested curly brackets, this is a special
                # character
                if not nested_curly:
                    # Increase nested level
                    nested_quotes += 1
                group += c
            # Found closing curly bracket
            elif c == "}":
                # If we are outside nested quotes, this is a special character
                if not nested_quotes:
                    # Decrease nested level
                    nested_curly -= 1
                    if nested_curly < 0:
                        # Mismatched brackets
                        return None
                group += c
            # Found closing quote
            elif c == "'":
                # If we are outside nested curly brackets, this is a special
                # character
                if not nested_curly:
                    # Decrease nested level
                    nested_quotes -= 1
                    if nested_quotes < 0:
                        # Mismatched quotes
                        return None
                group += c
            # Found closing parenthesis
            elif c == ")":
                # If we are outside nested quotes or brackets, this is a
                # special character
                if not nested_quotes and not nested_curly:
                    nested_parentheses -= 1
                # If this is the outermost parenthesis, drop it
                # Otherwise keep it
                if nested_quotes or nested_curly or nested_parentheses > 0:
                    group += c
                elif nested_parentheses == 0:
                    # Found outermost closing parenthesis, end of arguments
                    break
                elif nested_parentheses < 0:
                    # Mismatched parentheses
                    return None
            # Found comma
            elif c == ",":
                # If we are outside nested curly brackets and quotes, this is
                # the separator character
                if not nested_curly and not nested_quotes:
                    # Append the group as a new argument
                    args.append(group)
                    # Initialize a new empty group
                    group = ""
                else:
                    # Append to the group as a regular character
                    group += c
            # Found space
            elif c == " ":
                # If we are outside nested curly brackets and quotes, discard
                # spaces
                if nested_curly or nested_quotes:
                    group += c
            # Found generic character
            else:
                group += c
        # Save the last block
        args.append(group)
        return args

    def __get_macro_usage_args__(self, macro, line):
        """Get the current macro arguments"""
        # The macro is supposed to have nargs arguments
        if macro.nargs > 0:
            # Check if it is actually used with all its arguments
            # Get the usage argstring (whatever is between the parentheses)
            usage_r = macro.name + self.regex_usageargstring
            tmp = re.match(usage_r, line)
            if tmp:
                # Get the arguments
                args = self.__split_macro_usage_args__(tmp.group(1))
                # Bad usage
                if len(args) != macro.nargs:
                    args = None
            else:
                # Special case: multiline macros (e.g. "eng(` \n ... \n')")
                if "{}(`".format(macro.name) in line:
                    args = []
                    for i in xrange(macro.nargs):
                        args.append("multiline")
                else:
                    args = None
        else:
            # Macro without arguments
            args = []
        return args

    def __find_macro_usages__(self, policy_files, macros):
        """Get a list of all the m4 macros used in the supplied files.

        The list contains MacroInPolicy objects."""
        macro_usages = []
        for current_file in (x for x in policy_files if x.endswith(".te")):
            # For each .te file
            with open(current_file) as current_file_content:
                for lineno, line in enumerate(current_file_content, 1):
                    # Remove extra whitespace
                    line = line.strip()
                    if line.startswith("#"):
                        # Ignore comments
                        continue
                    # Strip end-of-line comments
                    if "#" in line:
                        line = line.split("#")[0].strip()
                    # Search for macros
                    stripped_line = str(line)
                    for word in re.split(r'\W+', line):
                        # Handle usage of the same macro multiple times on the
                        # same line: only parse the first occurrence, and
                        # remove each occurrence from the string after parsing
                        # Find the index of the word in the string
                        word_index = stripped_line.index(word)
                        # Discard everything before that
                        stripped_line = stripped_line[word_index:]
                        if word in macros:
                            # We have found a macro
                            # Get the arguments
                            args = self.__get_macro_usage_args__(
                                macros[word], stripped_line)
                            if args is None:
                                # The macro usage is not valid
                                self.log.warning("\"%s\" is a macro name but "
                                                 "it is used wrong at:", word)
                                self.log.warning("%s:%s: %s", current_file,
                                                 lineno, line.rstrip())
                                continue
                            # Construct the new macro object
                            try:
                                n_m = MacroInPolicy(macros, current_file,
                                                    lineno, word, args)
                            except M4MacroError as e:
                                # Bad macro, skip
                                self.log.warning("%s", e.message)
                            else:
                                # Add the new macro to the list
                                macro_usages.append(n_m)
        return macro_usages

    def __compute_attributes(self):
        """Get the SELinuxPolicy attributes as a dictionary of sets.

        Return a dictionary (attribute, set(types))."""
        attributes = {}
        for attr in self.policy.typeattributes():
            attributes[str(attr)] = set(str(x) for x in attr.expand())
        return attributes

    def __compute_types(self):
        """Get the set of SELinuxPolicy types as a set of strings."""
        types = set()
        for tpe in self.policy.types():
            types.add(str(tpe))
        return types

    def __compute_classes(self):
        """Get the SELinuxPolicy classes as a dictionary of sets.

        Return a dictionary (class, set(perms)).
        Each set contains all the permissions for the associated class,
        both inherited from commons and directly assigned."""
        classes = {}
        for cls in self.policy.classes():
            try:
                cmn = cls.common
            except setools.policyrep.exception.NoCommon:
                cmnset = cls.perms
            else:
                cmnset = cls.perms.union(self.policy.lookup_common(cmn).perms)
            classes[str(cls)] = cmnset
        return classes

    @property
    def macro_defs(self):
        """Get the macros defined in the policy source."""
        return self._macro_defs

    @property
    def macro_usages(self):
        """Get the macros used in the policy source."""
        return self._macro_usages

    @property
    def policy(self):
        """Get the SELinuxPolicy policy."""
        return self._policy

    @property
    def policyconf(self):
        """Get the path to the policy.conf file."""
        return self._policyconf

    @property
    def attributes(self):
        """Get the SELinuxPolicy attributes.

        Returns a a dictionary (attr, set(types))."""
        return self._attributes

    @property
    def types(self):
        """Get the SELinuxPolicy types.

        Returns a set of types."""
        return self._types

    @property
    def classes(self):
        """Get the SELinuxPolicy security classes.

        Returns a dictionary (class, set(permissions))"""
        return self._classes

    @property
    def mapping(self):
        """Get the mapping between policy rules and origin file/line.

        Return a Mapping object."""
        return self._mapping
