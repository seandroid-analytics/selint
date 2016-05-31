#Configure SELint
You need to configure SELint to use your Android tree.
Two sample configuration files are shipped with SELint, `config.py` and `config-intel.py`: you can modify them directly or use them as reference.
The available configuration parameters are also described below.

**BASE_DIR_GLOBAL**:
The location of the Android tree. All other paths expressed in other variables below are relative to this.
This variable is a string; it is a UNIX path, e.g. it can contain `~` and `..`.

**POLICY_DIRS**: The directories containing policy source files.
This is roughly the equivalent of the `BOARD_SEPOLICY_DIRS` variable in the BoardConfig.mk makefile, except it also specifies the AOSP sepolicy directory.
The paths are relative to `BASE_DIR_GLOBAL`.
This variable is a list; it can contain both strings and tuples `(string, bool)`, where a bool value of `True` means that the directory must be searched recursively.
If the element is a simple string, an implicit value of `False` is assumed, and the directory is not searched recursively.
E.g.:
```
POLICY_DIRS = ["external/sepolicy", ("device/intel/sepolicy", True)]
```
Directories will be processed in the order in which they are specified.

**POLICY_FILES**: The names of the policy source files.
This is roughly the equivalent of the `sepolicy_build_files` variable in the `sepolicy` Android.mk makefile.
This variable is a list of strings; it supports UNIX shell-style patterns ("*", ...).
E.g.:
```
POLICY_FILES =["attributes", "*.te"]
```
Files will be processed in the order in which they are specified.

**EXTRA_DEFS**: The extra definitions for M4 macro expansion.
These correspond to the options which are found in the M4 invocation in the `sepolicy` Android.mk makefile.
This variable is a list of strings.
E.g.:
```
EXTRA_DEFS = ["mls_num_sens=1", "mls_num_cats=1024", "target_build_variant=user"]
```
Additional definitions can also be specified on the command line: they will be combined with the options specified here.

**VERBOSITY**: The verbosity level. This variable is an integer; available values are:
```
0: critical [default]
1: error
2: warning
3: info
4: debug
```
E.g.:
```
VERBOSITY = 4
```
This value can be overridden on the command line.

# Configure SELint plugins
SELint plugins must be configured to adapt to your SEAndroid policy.
Plugins are found in the `plugins` directory, and their configuration files in `plugins/config`.
You can modify the existing configuration files to adapt them to your needs.
The available configuration options for each plugin are presented in the sections below.

Currently, plugins automatically load the configuration file with the same name as the plugin.
We are planning to allow different plugin configuration files to be individually specified for each plugin in the future.

# Existing plugins
The following sections describe the existing plugins, how to configure them and how to interpret their output.
## Global_macros
The `global_macros` plugin suggests new usages of global macros.
Using M4 macros where applicable produces a more compact and readable policy.
#### Configuration
The plugin configuration file can contain the following variables.

**RULE_IGNORE_PATHS**: Do not suggest M4 macros in rules coming from these paths.
This variable is a list: it contains paths relative to `BASE_DIR_GLOBAL` defined in the global SELint configuration file.

**SUPPORTED_RULE_TYPES**: Only suggest M4 macros in rules of these types.
This variable is a tuple: it contains rule types as strings. E.g.:
```
SUPPORTED_RULE_TYPES = ("allow",)
```
If there is only one element in the tuple, insert a trailing comma as in the example to indicate the variable is in fact a tuple.

**SUGGESTION_THRESHOLD**: Only suggest macros that match above this threshold.
This variable is a number between 0 and 1. E.g.:
```
SUGGESTION_THRESHOLD = 0.8
```

**SUGGESTION_MAX_NO**: Suggest at most N partial macro matches.
This variable is an integer. E.g.:
```
SUGGESTION_MAX_NO = 3
```

**IGNORED_RULES**: Do not suggest global macros in these rules.
This variable is a list; it contains rule masks up to the class. Matching rules will be ignored. E.g.:
```
IGNORED_RULES = ["allow somedomain sometype:someclass"]
```

#### Output
The plugin produces this output:
```
The following macros match a rule on these lines:
.../file.te:29
.../file.te:102
Full match:
ra_file_perms
Suggested usage:
allow somedomain sometype:file ra_file_perms;
```
This means that the rules found at lines 29 and 102 in `file.te` can be expressed more compactly by using the `ra_file_perms` macro.
If you agree with the suggestion, you can insert the suggested usage in the policy.

## Te_macros
The `te_macros` plugin suggests new usages of TE macros.
Using M4 macros where applicable produces a more compact and readable policy.
#### Configuration
The plugin configuration file can contain the following variables.

**RULE_IGNORE_PATHS**: Do not suggest M4 macros in rules coming from these paths.
This variable is a list: it contains paths relative to `BASE_DIR_GLOBAL` defined in the global SELint configuration file.

**SUPPORTED_RULE_TYPES**: Only suggest M4 macros in rules of these types.
This variable is a tuple: it contains rule types as strings. E.g.:
```
SUPPORTED_RULE_TYPES = ("allow", "type_transition")
```
If there is only one element in the tuple, insert a trailing comma to indicate the variable is in fact a tuple.

**MACRO_IGNORE**: Never suggest these M4 macros with any arguments.
This variable is a list of strings.
This variable should contain all TE macros which do not expand into regular `allow` and `type_transition` rules.
For example, conditional macros and macros which only define types/domains should be ignored.
E.g.:
```
MACRO_IGNORE = ["recovery_only", "userdebug_or_eng", "print", "eng", "net_domain"]
```

**SUGGESTION_THRESHOLD**: Only suggest macros that match above this threshold.
This variable is a number between 0 and 1. E.g.:
```
SUGGESTION_THRESHOLD = 0.8
```

**USAGES_IGNORE**: Do not suggest these specific macro usages with these specific arguments.
This variable is a list of strings.
You can use this variable to blacklist specific macro usages which you do not want SELint to suggest.
E.g.:
```
USAGES_IGNORE = ["some_macro(arg1, arg2)"]
```

#### Output
The plugin produces this output:
```
These lines could be substituted by macro unix_socket_send(system_server, thermal, init) (100.0%):
.../system_server.te:9: allow system_server thermal_socket:sock_file write;
.../system_server.te:5: allow system_server init:unix_dgram_socket sendto;
Corresponding rules in the macro expansion:
allow system_server thermal_socket:sock_file write;
allow system_server init:unix_dgram_socket sendto;
```
This means that the rules found at lines 5 and 9 of the `system_server.te` file could be expressed by using the `unix_socket_send(system_server, thermal, init)` macro.
If you agree with the suggestion, you can insert the macro usage in the policy.

## risky_rules

## unnecessary_rules

## user_neverallows

# Develop new SELint plugins
You can develop new plugins to implement additional analysis functionality.
SELint plugins are regular Python files. They must declare a `main(policy, config)` function and a `REQUIRED_RULES` tuple.

The `main(policy, config)` function is passed the loaded policy as a `SourcePolicy` object and the selected configuration file as the `config` module.

The `REQUIRED_RULES` tuple must contain the rule types that the plugin intends to work on.

You can put a configuration file for your plugin in the `plugins/config` directory: it must have the same name as the plugin.
You can then import the configuration file as a module in your plugin:
```
import plugins.config.<NAME> as plugin_conf
```

The plugin configuration file will be available as the plugin_conf module.
