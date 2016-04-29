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
"""SELint configuration parameters"""

# Location of the Android tree
# All paths expressed in other variables will be relative to this
BASE_DIR_GLOBAL = "~/workspace"

# Policy source file directories
# This list contains directories to be searched for policy files specified in
# POLICY_FILES below. This is the rough equivalent of the BOARD_SEPOLICY_DIRS
# variable in the BoardConfig.mk makefile, except it also specifies the AOSP
# sepolicy directory.
# This list can contain both strings and tuples (string, bool), where a bool
# value of True means that the directory must be searched recursively. E.g.:
# POLICY_DIRS = ["external/sepolicy",
#                ("device/intel/sepolicy", True)]
# Directories will be processed in the order in which they are specified.
POLICY_DIRS = ["system/sepolicy",
               "build/target/board/generic/sepolicy"]

# Policy source files
# This list contains file names to be searched in the POLICY_DIRS specified
# above. This is the rough equivalent of the sepolicy_build_files variable in
# the sepolicy Android.mk makefile.
# This list contains strings. It supports UNIX shell-style patterns ("*", ...)
# Files will be processed in the order in which they are specified.
POLICY_FILES = ["security_classes",
                "initial_sids",
                "access_vectors",
                "global_macros",
                "neverallow_macros",
                "mls_macros",
                "mls",
                "policy_capabilities",
                "te_macros",
                "attributes",
                "ioctl_macros",
                "*.te",
                "roles",
                "users",
                "initial_sid_contexts",
                "fs_use",
                "genfs_contexts",
                "port_contexts"]

# Extra definitions for M4 macro expansion
# These will be passed to M4 with the "-D" option
# Additional definitions can also be specified on the command line: they will
# be combined with these
# e.g.
# EXTRA_DEFS = ['mls_num_sens=1', 'mls_num_cats=1024',
#               'target_build_variant=user']
EXTRA_DEFS = ['mls_num_sens=1', 'mls_num_cats=1024',
              'target_build_variant=user']

# Verbosity level
# 0: critical [default]
# 1: error
# 2: warning
# 3: info
# 4: debug
# Can be overridden on the command line
# VERBOSITY = 4
