#!/usr/bin/python2
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
"""Test various functions for correctness"""

import setools
import setools.policyrep
import os.path
import policysource.policy as p
import policysource.macro as m
import logging
import sys
import copy
import subprocess
from tempfile import mkdtemp


def test_source_policy():
    pol = p.SourcePolicy(p.BASE_DIR_GLOBAL, p.POLICYFILES_GLOBAL)


def main():
    logging.basicConfig(level=logging.DEBUG)  # , format='%(message)s')
    test_source_policy()


if __name__ == "__main__":
    main()
