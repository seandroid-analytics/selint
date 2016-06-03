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
"""Configuration file for the te_macros plugin."""

# Do not make suggestions on rules coming from files in these paths
#
# e.g. to ignore AOSP:
# RULE_IGNORE_PATHS = ["external/sepolicy"]
RULE_IGNORE_PATHS = ["external/sepolicy",
                     "build/target/board/generic/sepolicy"]

# Only make suggestions for the following rule types
# SUPPORTED_RULE_TYPES = ("allow", "type_transition", "neverallow")
# This must be a tuple: if there is only one element, insert a trailing comma
SUPPORTED_RULE_TYPES = ("allow", "type_transition")

# Do not try to reconstruct these macros
MACRO_IGNORE = ["recovery_only", "non_system_app_set", "userdebug_or_eng",
                "print", "permissive_or_unconfined", "userfastboot_only",
                "notuserfastboot", "eng", "binder_service", "net_domain",
                "unconfined_domain", "bluetooth_domain"]

# Only suggest macros that match above this threshold [0-1]
SUGGESTION_THRESHOLD = 0.8

# Do not suggest these usages
# WARNING: Be careful what you put in here.
USAGES_IGNORE = []
