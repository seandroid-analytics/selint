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
"""Global test parameters and functions."""
import os.path

BASE_DIR = "test/test_policy_files"
MACROFILES = [
    "global_macros",
    "te_macros",
    "ioctl_macros"]
POLICYFILES = [
    "rules.te"]
SUPPORTED_MACRO_FILES = [
    "global_macros",
    "te_macros"]
EXISTING_PLUGINS = [
    "global_macros",
    "te_macros"]
VALID_PLUGINS = [
    "global_macros",
    "te_macros"]


def join_files(basedir, files):
    return [os.path.join(os.path.abspath(os.path.expanduser(basedir)), x) for x in files if x]
