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
MACRODEF = r'^define\(\`([^\']+)\','
LOG = logging.getLogger(__name__)


def find_macro_files(base_dir, policyfiles):
    """Find files that contain m4 macro definitions."""
    # Regex to match the macro definition string
    macrodef = re.compile(MACRODEF)
    macro_files = []
    # Get the absolute path of the supplied policy files, remove empty values
    pf = join_policy_files(base_dir, policyfiles)
    for f in pf:
        with open(f, 'r') as mf:
            for line in mf:
                # If this file contains at least one macro definition, append
                # it to the list of macro files and skip to the next policy
                # file
                if macrodef.search(line):
                    macro_files.append(f)
                    break
    return macro_files


def expand_macros(base_dir, policyfiles):
    """Get a dictionary containing all the m4 macros defined in the files.

    The dictionary maps the macro name to a M4Macro object."""
    macro_files = find_macro_files(base_dir, policyfiles)
    parser = macro_plugins.M4MacroParser()
    macros = parser.parse(macro_files)
    return macros


def join_policy_files(base_dir, policyfiles):
    """Get the absolute path of the policy files, removing empty values"""
    return [os.path.join(os.path.expanduser(os.path.abspath(base_dir)), x)
            for x in policyfiles if x]


def __get_macro_args__(macro, word, line, f):
    """Get the current macro arguments"""
    # The macro is supposed to have nargs arguments
    if macro.nargs > 0:
        # Check if it is actually used with all its arguments
        usage_r = r'\s*' + word + \
            r'\(((?:(?:\w+|\{[^,]+\}),\s?)*(?:\w+|\{[^,]+\}))\)\s*'
        tmp = re.match(usage_r, line)
        if tmp:
            # Save the arguments
            args = re.split(r',\s*', tmp.group(1))
        else:
            # The macro usage is not valid
            LOG.warning("\"%s\" is a macro name "
                        "but it is used wrong at "
                        "%s:%s:", word, f, lineno)
            LOG.warning("\"%s\"", line.rstrip())
            args = None
    else:
        # Macro without arguments
        args = []
    return args


def find_macros(base_dir, policyfiles):
    """Get a list of all the m4 macros used in the supplied files.

    The list contains MacroInPolicy objects."""
    # TODO: refactor this function
    macros = expand_macros(base_dir, policyfiles)
    macros_in_policy = []
    # Get the absolute path of the supplied policy files, remove empty values
    pf = join_policy_files(base_dir, policyfiles)
    for f in pf:
        # For each file
        if f.endswith(".te"):
            # If it's a .te file
            with open(f) as cf:
                for lineno, line in enumerate(cf, 1):
                    if not line.startswith("#"):
                        # Ignore comments
                        # TODO: if line.startswith("neverallow") record it
                        for word in re.split(r'\W+', line):
                            if word in macros:
                                # We have found a macro
                                # Check if it has arguments
                                args == __get_macro_args__(macros[word],
                                                           word, line, f)
                                if args is None:
                                    continue
                                # Construct the new macro object
                                try:
                                    newmacro = MacroInPolicy(
                                        macros, f, lineno, word, args)
                                except M4MacroError as e:
                                    # Bad macro, skip
                                    LOG.warning("%s", e.msg)
                                else:
                                    # Add the new macro to the list
                                    macros_in_policy.append(newmacro)
    return macros_in_policy
