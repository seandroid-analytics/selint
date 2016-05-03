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
"""Configuration file for the unnecessary_rules plugin."""

# Do not make suggestions on rules coming from files in these paths
#
# e.g. to ignore AOSP:
# RULE_IGNORE_PATHS = ["external/sepolicy"]
RULE_IGNORE_PATHS = ["external/sepolicy",
                     "build/target/board/generic/sepolicy"]

# Functionality 1
# Tuples of rules that must always be found together. If the first rule in the
# tuple is found in the policy, report any other rule in the tuple which is
# not in the policy.
#
# The plugin supports searching with placeholder arguments, e.g. you can
# specify such a tuple:
# ("type_transition @@ARG0@@ @@ARG1@@:process @@ARG2@@;",
#  "allow @@ARG0@@ @@ARG1@@:file execute;",
#  "allow @@ARG2@@ @@ARG1@@:file entrypoint;",
#  "allow @@ARG0@@ @@ARG2@@:process transition;")
# which will match the following set of rules:
#
#   type_transition initrc_t acct_exec_t:process acct_t;
#   allow initrc_t acct_exec_t:file execute;
#   allow acct_t acct_exec_t:file entrypoint;
#   allow initrc_t acct_t:process transition;
#
# N.B. the first rule in the tuple MUST contain all the placeholder arguments
#      used in later rules.
RULES_TUPLES = [("type_transition @@ARG0@@ @@ARG1@@:process @@ARG2@@;",
                 "allow @@ARG0@@ @@ARG1@@:file execute;",
                 "allow @@ARG2@@ @@ARG1@@:file entrypoint;",
                 "allow @@ARG0@@ @@ARG2@@:process transition;"),
                ("type_transition @@ARG0@@ @@ARG1@@:file @@ARG2@@;",
                 "allow @@ARG0@@ @@ARG1@@:dir { search add_name write };",
                 "allow @@ARG0@@ @@ARG2@@:file { create write };")]

# Functionality 2
# List of debug types, which must not be in the user policy
# The plugin will report any rule which contains any of these types.
DEBUG_TYPES = [""]

# Functionality 3
# Dictionary of class-specific permissions required for a rule to make sense
# The plugin will report any rule which grants any permission from the first
# set without granting at least the required perms in the second set, or an
# additional set of permissions on another class.
# The dictionary key is the name of the class as a string; the dictionary value
# is a tuple of two sets of strings and a dictionary containing a set.
# E.g.:
# REQUIRED_PERMS = {"file": (set(["write", " read", "append", "ioctl"]), # SET1
#                            set(["open"]),                              # SET2
#                            {"fd": set(["use"])})                       # ADD
#                   }
# means: for class "file"
# IF any permission from SET1 is granted AND NOT (
#   (all the permissions in SET2 are granted)
#   OR
#   (for each class in the ADD dictionary, all permissions in the relative
#       set are granted)
#   ):
#     REPORT RULE
REQUIRED_PERMS = {"file": (set(["write", "read", "append", "ioctl"]),
                           set(["open"]),
                           {"fd": set(["use"])})
                  }

# Do not report these rules
# Rules in this configuration parameter will be ignored when looking for the
# first rule in a tuple (functionality 1), when looking for rules containing
# debug types (functionality 2) and when looking for rules not granting desired
# permissions (functionality 3).
# They WILL be detected, if applicable, when looking for matching additional
# rules in tuples (functionality 1).
# The rules must match exactly as strings
# e.g.
# IGNORED_RULES = ["allow domain type:class permission;"]
IGNORED_RULES = []
