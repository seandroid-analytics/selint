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
"""Configuration file for the global_macros plugin."""

# Do not make suggestions on rules coming from files in these paths
#
# e.g. to ignore AOSP:
# RULE_IGNORE_PATHS = ["external/sepolicy"]
RULE_IGNORE_PATHS = ["external/sepolicy",
                     "build/target/board/generic/sepolicy"]

# Only make suggestions for the following rule types
# SUPPORTED_RULE_TYPES = ("allow", "auditallow", "dontaudit", "neverallow")
# This must be a tuple: if there is only one element, insert a trailing comma
SUPPORTED_RULE_TYPES = ("allow",)

# Parameters for partial match macro suggestions
# Only suggest macros that match above this threshold [0-1]
SUGGESTION_THRESHOLD = 0.8
# Make up to this number of suggestions
SUGGESTION_MAX_NO = 3

# Do not suggest global macros in these rules.
# Specify rule masks up to the class, e.g.:
# IGNORED_RULES = ["allow a b:c", "allow somedomain sometype:someclass"]
# Matching rules will be ignored.
# WARNING: Be careful what you put in here.
IGNORED_RULES = []
