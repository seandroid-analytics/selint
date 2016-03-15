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
"""Configuration file for the dangerous_rules plugin."""

# Dictionary containing the classification of types
TYPES = {}
# Dictionary containing the classification of permissions
PERMS = {}
# Dictionary containing the score for each entry in types/permissions
SCORE = {}
# Maximum score a rule can obtain (2x highest scoring type)
MAXIMUM_SCORE = 60

# Security sensitive types
# These are the types that directly impact system security, and as such must be
# closely guarded.
SCORE["security_sensitive"] = 30
TYPES["security_sensitive"] = ["proc_security", "security_file",
                               "security_prop", "securityfile_service",
                               "securitymanager_service", "tee",
                               "tee_data_file", "tee_device", "tee_exec",
                               "tee_tmpfs", "keystore", "keystore_data_file",
                               "keystore_exec", "keystore_service",
                               "kmem_device", "keystore_tmpfs",
                               "keychain_data_file", "vpn_data_file"]
# Types assigned to user-installed apps
# These types must not be granted eccessive permissions.
# On most devices, there is only one of these types, "untrusted_app".
SCORE["user_app"] = 10
TYPES["user_app"] = ["untrusted_app"]
# Core system domains
# These types cover core system services launched by the init system.
# While not directly involved with security, these services are very important.
SCORE["core_domains"] = 15
TYPES["core_domains"] = ["adbd", "adbd_socket", "init", "init_shell",
                         "init_tmpfs", "installd", "installd_exec",
                         "installd_socket", "installd_tmpfs", "radio",
                         "radio_data_file", "radio_device", "radio_prop",
                         "radio_service", "radio_tmpfs", "vold", "vold_exec",
                         "vold_prop", "vold_socket", "vold_tmpfs", "drmserver",
                         "drmserver_exec", "drmserver_service",
                         "drmserver_socket", "drmserver_tmpfs",
                         "drm_data_file", "logd", "logd_debug", "logd_exec",
                         "logd_prop", "logd_socket", "logd_tmpfs", "netd",
                         "netd_exec", "netd_socket", "netd_tmpfs", "rild",
                         "rild_debug_socket", "rild_exec", "rild_socket",
                         "rild_tmpfs", "system_server",
                         "system_server_service", "system_server_tmpfs",
                         "ueventd", "ueventd_tmpfs", "zygote", "zygote_exec",
                         "zygote_socket", "zygote_tmpfs"]
# Default types
# These types are used to label objects in absence of any specific label
# applied to them in the policy.
# These should not be used most of the time.
SCORE["default_types"] = 10
TYPES["default_types"] = ["device", "unlabeled", "default_android_service",
                          "socket_device", "default_property", "system_file",
                          "system_data_file", "default_prop"]
# Sensitive types
# These types are non directly security-related, but protect key parts of the
# system such as the graphics device memory.
SCORE["sensitive"] = 20
TYPES["sensitive"] = ["graphics_device", "ram_device"]

# TODO: add socket permissions, other permissions from access_vectors
# High-risk permissions
SCORE["perms_high"] = 1
PERMS["perms_high"] = set(["ioctl", "write", "setattr", "lock", "relabelfrom",
                           "relabelto", "append", "unlink", "link", "rename",
                           "execute"])
# Medium-risk permissions
SCORE["perms_med"] = 0.66
PERMS["perms_med"] = set(["swapon", "quotaon", "mounton"])
# Low-risk permissions
SCORE["perms_low"] = 0.33
PERMS["perms_low"] = set(["read", "create", "getattr"])

# Ignore rules coming from files in these paths
# e.g. to ignore AOSP:
# RULE_IGNORE_PATHS = ["external/sepolicy"]
RULE_IGNORE_PATHS = ["external/sepolicy"]

# Don't report rules that score below this threshold
SCORE_THRESHOLD = 0.6
