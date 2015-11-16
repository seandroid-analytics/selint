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
"""Class providing an abstraction for a source SEAndroid policy"""

import setools
import setools.policyrep
from tempfile import mkdtemp
import subprocess
import os.path
import re
from .macro import MacroInPolicy, M4MacroError
from . import macro_plugins
import logging

BASE_DIR_GLOBAL = "~/workspace"
POLICYFILES_GLOBAL = [
    "external/sepolicy/security_classes",
    "external/sepolicy/initial_sids",
    "external/sepolicy/access_vectors",
    "external/sepolicy/global_macros",
    "external/sepolicy/neverallow_macros",
    "external/sepolicy/mls_macros",
    "external/sepolicy/mls",
    "external/sepolicy/policy_capabilities",
    "external/sepolicy/te_macros",
    "external/sepolicy/attributes",
    "external/sepolicy/ioctl_macros",
    "external/sepolicy/adbd.te",
    "external/sepolicy/app.te",
    "external/sepolicy/atrace.te",
    "external/sepolicy/binderservicedomain.te",
    "external/sepolicy/blkid.te",
    "external/sepolicy/blkid_untrusted.te",
    "external/sepolicy/bluetooth.te",
    "external/sepolicy/bootanim.te",
    "external/sepolicy/clatd.te",
    "external/sepolicy/debuggerd.te",
    "external/sepolicy/device.te",
    "external/sepolicy/dex2oat.te",
    "external/sepolicy/dhcp.te",
    "external/sepolicy/dnsmasq.te",
    "external/sepolicy/domain.te",
    "external/sepolicy/domain_deprecated.te",
    "external/sepolicy/drmserver.te",
    "external/sepolicy/dumpstate.te",
    "external/sepolicy/file.te",
    "external/sepolicy/fingerprintd.te",
    "external/sepolicy/fsck.te",
    "external/sepolicy/fsck_untrusted.te",
    "external/sepolicy/gatekeeperd.te",
    "external/sepolicy/gpsd.te",
    "external/sepolicy/hci_attach.te",
    "external/sepolicy/healthd.te",
    "external/sepolicy/hostapd.te",
    "external/sepolicy/idmap.te",
    "external/sepolicy/init.te",
    "external/sepolicy/inputflinger.te",
    "external/sepolicy/install_recovery.te",
    "external/sepolicy/installd.te",
    "external/sepolicy/isolated_app.te",
    "external/sepolicy/kernel.te",
    "external/sepolicy/keystore.te",
    "external/sepolicy/lmkd.te",
    "external/sepolicy/logd.te",
    "external/sepolicy/mdnsd.te",
    "external/sepolicy/mediaserver.te",
    "external/sepolicy/mtp.te",
    "external/sepolicy/net.te",
    "external/sepolicy/netd.te",
    "external/sepolicy/nfc.te",
    "external/sepolicy/perfprofd.te",
    "external/sepolicy/platform_app.te",
    "external/sepolicy/ppp.te",
    "external/sepolicy/priv_app.te",
    "external/sepolicy/property.te",
    "external/sepolicy/racoon.te",
    "external/sepolicy/radio.te",
    "external/sepolicy/recovery.te",
    "external/sepolicy/rild.te",
    "external/sepolicy/runas.te",
    "external/sepolicy/sdcardd.te",
    "external/sepolicy/service.te",
    "external/sepolicy/servicemanager.te",
    "external/sepolicy/sgdisk.te",
    "external/sepolicy/shared_relro.te",
    "external/sepolicy/shell.te",
    "external/sepolicy/slideshow.te",
    "external/sepolicy/su.te",
    "external/sepolicy/surfaceflinger.te",
    "external/sepolicy/system_app.te",
    "external/sepolicy/system_server.te",
    "external/sepolicy/tee.te",
    "external/sepolicy/toolbox.te",
    "external/sepolicy/tzdatacheck.te",
    "external/sepolicy/ueventd.te",
    "external/sepolicy/uncrypt.te",
    "external/sepolicy/untrusted_app.te",
    "external/sepolicy/update_engine.te",
    "external/sepolicy/vdc.te",
    "external/sepolicy/vold.te",
    "external/sepolicy/watchdogd.te",
    "external/sepolicy/wpa.te",
    "external/sepolicy/zygote.te",
    "build/target/board/generic/sepolicy/bootanim.te",
    "build/target/board/generic/sepolicy/device.te",
    "build/target/board/generic/sepolicy/domain.te",
    "build/target/board/generic/sepolicy/file.te",
    "build/target/board/generic/sepolicy/goldfish_setup.te",
    "build/target/board/generic/sepolicy/init.te",
    "build/target/board/generic/sepolicy/logd.te",
    "build/target/board/generic/sepolicy/property.te",
    "build/target/board/generic/sepolicy/qemu_props.te",
    "build/target/board/generic/sepolicy/qemud.te",
    "build/target/board/generic/sepolicy/rild.te",
    "build/target/board/generic/sepolicy/shell.te",
    "build/target/board/generic/sepolicy/surfaceflinger.te",
    "build/target/board/generic/sepolicy/system_server.te",
    "external/sepolicy/roles",
    "external/sepolicy/users",
    "external/sepolicy/initial_sid_contexts",
    "external/sepolicy/fs_use",
    "external/sepolicy/genfs_contexts",
    "external/sepolicy/port_contexts"]


class SourcePolicy(object):
    """Class representing a source SELinux policy."""
    regex_macrodef = r'^define\(\`([^\']+)\','

    def __init__(self, base_dir, policyfiles):
        """Construct a SourcePolicy object by parsing the supplied files.

        Keyword arguments:
        base_dir    --  A common path for the policy files
        policyfiles --  A list of file paths, relative to the base dir"""
        # Setup logging
        self.log = logging.getLogger(self.__class__.__name__)
        # Setup useful infrastructure
        self._tmpdir = mkdtemp()
        self._policyconf = None
        # Create a temporary work directory
        self.log.debug("Created temporary directory \"%s\".", self._tmpdir)
        # Get a list of policy files with full paths
        self._policy_files = self.__join_policy_files__(base_dir, policyfiles)
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
        # These will go in some conf file or cli option
        extra_defs = ['mls_num_sens=1', 'mls_num_cats=1024',
                      'target_build_variant=eng']
        # Create the policyconf
        self._policyconf = self.__create_policyconf__(self._policy_files,
                                                      extra_defs)
        if not self._policyconf:
            raise RuntimeError(
                "Could not create the policy.conf file, aborting...")
        # Create the actual policy instance
        self._policy = setools.policyrep.SELinuxPolicy(self._policyconf)

    def __del__(self):
        if self._policyconf:
            try:
                os.remove(self._policyconf)
            except OSError:
                self.log.debug("Trying to remove policy.conf file \"%s\"... "
                               "failed!", self._policyconf)
            else:
                self.log.debug("Trying to remove policy.conf file \"%s\"... "
                               "done!", self._policyconf)
        if self._tmpdir:
            try:
                os.rmdir(self._tmpdir)
            except OSError:
                self.log.warning("Trying to remove the temporary directory "
                                 "\"%s\"... failed!", self._tmpdir)
            else:
                self.log.debug("Trying to remove the temporary directory "
                               "\"%s\"... done!", self._tmpdir)

    def __create_policyconf__(self, policy_files, extra_defs):
        """Process the separate policy files with m4 and return a single
        policy.conf file"""
        # Prepare the output file
        policyconf = os.path.join(self._tmpdir, "policy.conf")
        # Prepare the m4 command line
        command = ['m4']
        for definition in extra_defs:
            command.extend(["-D", definition])
        command.extend(['-s'])
        command.extend(policy_files)
        # Try to run m4
        try:
            with open(policyconf, "w") as pcf:
                subprocess.check_call(command, stdout=pcf)
        except subprocess.CalledProcessError as e:
            self.log.error(e.msg)
            self.log.error(
                "Could not create the policy.conf \"%s\" file", policyconf)
            policyconf = None
        return policyconf

    def __join_policy_files__(self, base_dir, policyfiles):
        """Get the absolute path of the policy files, removing empty values"""
        sanitized_files = []
        if not base_dir:
            # If the directory is None or the name is empty
            self.log.error("Bad policy base directory.")
            return None
        # Expand and sanitize the directory name
        full_dir = os.path.abspath(os.path.expanduser(base_dir))
        # If the directory does not exist or is not traversable/readable
        if (not os.access(full_dir, os.F_OK)
                or not os.access(full_dir, os.X_OK | os.R_OK)):
            self.log.error("Bad policy base directory \"%s\"", full_dir)
            return None
        if not policyfiles:
            # If policyfiles is None or the list is empty
            return None
        # For each non-empty value in the list
        for each_file in (x for x in policyfiles if x):
            # Expand and sanitize the file name
            full_path = os.path.abspath(os.path.join(full_dir, each_file))
            # If the file exists and is readable, add it to the list
            if os.access(full_path, os.F_OK) and os.access(full_path, os.R_OK):
                self.log.debug("Found policy file \"%s\"", full_path)
                sanitized_files.append(full_path)
            else:
                self.log.warning("Bad policy file \"%s\"", full_path)
        return sanitized_files

    def __find_macro_files__(self, policy_files):
        """Find files that contain m4 macro definitions."""
        # Regex to match the macro definition string
        macrodef_r = re.compile(self.regex_macrodef)
        macro_files = []
        for single_file in policy_files:
            with open(single_file, 'r') as macro_file:
                for line in macro_file:
                    # If this file contains at least one macro definition,
                    # append it to the list of macro files and skip to
                    # the next policy file
                    if macrodef_r.search(line):
                        macro_files.append(single_file)
                        break
        return macro_files

    def __find_macro_defs__(self, policy_files):
        """Get a dictionary containing all the m4 macros defined in the files.

        The dictionary maps the macro name to a M4Macro object."""
        macro_files = self.__find_macro_files__(policy_files)
        parser = macro_plugins.M4MacroParser(self._tmpdir)
        macros = parser.parse(macro_files)
        return macros

    @staticmethod
    def __build_regex_nargs__(name, nargs):
        """Build a regex to match a macro usage, given the name and number of
        arguments."""
        # Match spaces, followed by the name, an opening parenthesis, $nargs
        # comma-separed strings/curly bracket blocks, a closing parenthesis
        # and spaces. E.g.: name = foo, nargs = 3
        # reg = r'\s*foo\(((?:(?:\w+|\{[^,]+\}),\s?){3}(?:\w+|\{[^,]+\}))\)\s*'
        # will match foo(arg0, {argument 1}, arg2)
        if nargs < 1:
            return None
        reg = r'\s*{}\(('.format(name)
        if nargs > 1:
            reg += r'(?:(?:\w+|\{[^,]+\}),\s?){' + str(nargs - 1) + '}'
        reg += r'(?:\w+|\{[^,]+\}))\)\s*'
        return reg

    def __get_macro_usage_args__(self, macro, line):
        """Get the current macro arguments"""
        # macroargs = r'\(((?:(?:\w+|\{[^,]+\}),\s?)*(?:\w+|\{[^,]+\}))\)\s*'
        # The macro is supposed to have nargs arguments
        if macro.nargs > 0:
            # Check if it is actually used with all its arguments
            usage_r = self.__build_regex_nargs__(macro.name, macro.nargs)
            tmp = re.match(usage_r, line)
            if tmp:
                # Save the arguments
                args = re.split(r',\s*', tmp.group(1))
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
                    if line.startswith("#"):
                        # Ignore comments
                        continue
                    for word in re.split(r'\W+', line):
                        if word in macros:
                            # We have found a macro
                            # Get the arguments
                            args = self.__get_macro_usage_args__(
                                macros[word], line)
                            if args is None:
                                # The macro usage is not valid
                                self.log.warning("\"%s\" is a macro name but "
                                                 "it is used wrong at %s:%s:",
                                                 word, current_file, lineno)
                                self.log.warning("\"%s\"", line.rstrip())
                                continue
                            # Construct the new macro object
                            try:
                                n_m = MacroInPolicy(macros, current_file,
                                                    lineno, word, args)
                            except M4MacroError as e:
                                # Bad macro, skip
                                self.log.warning("%s", e.msg)
                            else:
                                # Add the new macro to the list
                                macro_usages.append(n_m)
        return macro_usages

    @property
    def macro_defs(self):
        return self._macro_defs

    @property
    def macro_usages(self):
        return self._macro_usages
