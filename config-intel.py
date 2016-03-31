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
"""SELint configuration parameters for the Intel tree"""

# Location of the Android tree
# All paths expressed in other variables will be relative to this
BASE_DIR_GLOBAL = "~/extra/android-ia"

# Statically specified policy files
# Some files must go before all .te files
POLICYFILES_STATIC_PRE = [
    "external/sepolicy/security_classes",
    "external/sepolicy/initial_sids",
    "external/sepolicy/access_vectors",
    "external/sepolicy/global_macros",
    "external/sepolicy/mls_macros",
    "external/sepolicy/mls",
    "external/sepolicy/policy_capabilities",
    "external/sepolicy/te_macros",
    "device/intel/common/sepolicy/te_macros",
    "external/sepolicy/attributes"]
# All .te files found in these directories will automatically be picked up
TEFILES_DIRS = [
    "external/sepolicy/",
    "build/target/board/generic/sepolicy/",
    "device/intel/common/sepolicy"]
# Statically specified .te files
# This should not be necessary, use the TEFILES_DIRS variable
POLICYFILES_STATIC_TE = []
# Some policy files must go after all .te files
# Otherwise setools will crash, I believe due to wrong file terminators
POLICYFILES_STATIC_POST = [
    "external/sepolicy/roles",
    "external/sepolicy/users",
    "external/sepolicy/initial_sid_contexts",
    "external/sepolicy/fs_use",
    "external/sepolicy/genfs_contexts",
    "device/intel/common/sepolicy/genfs_contexts",
    "external/sepolicy/port_contexts"]

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
