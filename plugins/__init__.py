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
"""TODO: file docstring"""

# Necessary for Python 2/3 compatibility
from __future__ import absolute_import

import os
import os.path
import sys
import keyword
import inspect
import logging

# Setup logging
LOG = logging.getLogger(__name__)

# Recognize plugins
available_plugins = []
__plugins = {}
for plugin_file in os.listdir(os.path.dirname(__file__)):
    if plugin_file.endswith(u".py"):
        plugin = os.path.splitext(plugin_file)[0]
        if not plugin.startswith(u"_") and not keyword.iskeyword(plugin):
            try:
                __import__(__name__ + u"." + plugin)
            except:
                e = sys.exc_info()
                print(e)
                LOG.debug(u"Found invalid plugin \"%s\"", plugin)
            else:
                if inspect.isfunction(locals()[plugin].main) and\
                        hasattr(locals()[plugin], "REQUIRED_RULES") and\
                        isinstance(locals()[plugin].REQUIRED_RULES, tuple):
                    available_plugins.append(plugin)
                    __plugins[plugin] = locals()[plugin]
                    LOG.debug(u"Found valid plugin \"%s\"", plugin)
                else:
                    LOG.debug(u"Found invalid plugin \"%s\"", plugin)
available_plugins.sort()


def get_plugin(name):
    """Get a plugin by name."""
    if name in __plugins:
        return __plugins[name]
    else:
        return None
