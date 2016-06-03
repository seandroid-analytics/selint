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
"""Configuration file for the user_neverallow plugin."""

# Only analyse rules of these types
# This must be a tuple: if there is only one element, insert a trailing comma
SUPPORTED_RULE_TYPES = ("allow",)

# Report rules that do not obey these neverallow rules
# The neverallow rules can contain global_macros
# e.g.
# NEVERALLOWS = ["neverallow domain type:class permission;"]
NEVERALLOWS = ["neverallow adbd shell:process noatsecure;"]
