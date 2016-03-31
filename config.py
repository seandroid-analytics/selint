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

# Statically specified policy files
# Some files must go before all .te files
POLICYFILES_STATIC_PRE = [
    "system/sepolicy/security_classes",
    "system/sepolicy/initial_sids",
    "system/sepolicy/access_vectors",
    "system/sepolicy/global_macros",
    "system/sepolicy/neverallow_macros",
    "system/sepolicy/mls_macros",
    "system/sepolicy/mls",
    "system/sepolicy/policy_capabilities",
    "system/sepolicy/te_macros",
    "system/sepolicy/attributes",
    "system/sepolicy/ioctl_macros"]
# All .te files found in these directories will automatically be picked up
TEFILES_DIRS = [
    "system/sepolicy/",
    "build/target/board/generic/sepolicy/"]
# Statically specified .te files
# This should not be necessary, use the TEFILES_DIRS variable
POLICYFILES_STATIC_TE = []
# Some policy files must go after all .te files
# Otherwise setools will crash, I believe due to wrong file terminators
POLICYFILES_STATIC_POST = [
    "system/sepolicy/roles",
    "system/sepolicy/users",
    "system/sepolicy/initial_sid_contexts",
    "system/sepolicy/fs_use",
    "system/sepolicy/genfs_contexts",
    "system/sepolicy/port_contexts"]
