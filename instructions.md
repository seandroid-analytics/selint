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

## Risky_rules
The `risky_rules` plugin assigns a score to every rule by combining the partial scores of its elements.
The partial scores must be defined for each policy in the plugin configuration file.

#### Configuration
The plugin configuration file can contain the following variables.

**SCORING_SYSTEM**: The scoring system. This can be one of `risk`, `trust_lh`, `trust_hl`, `trust_hh`, `trust_ll`.
Rule elements are assigned a `risk` score, which denotes their level of risk, and a `trust` score, which denotes their level of trust.

Depending on the selected scoring system, rules will be assigned different scores.

The `risk` scoring system will assign a higher score to rules whose elements have higher combined `risk` scores.
This scoring system takes into account the domain, type, permission and capabilities of an `allow` rule, and the domain and default type of a `type_transition` rule.

The `trust_lh` scoring system will assign a higher score to rules whose domain has a low `trust` score and whose type has a high `trust` score.
Conversely, the `trust_hl` scoring system will assign a higher score to rules whose domain has a high `trust` score and whose type has a low `trust` score.
The `trust_hh` scoring system will assign a higher score to rules whose domain and type both have a high `trust` score.
The `trust_ll` scoring system will assign a higher score to rules whose domain and type both have a low `trust` score; this is perhaps the least useful of the scoring systems.

**SUPPORTED_RULE_TYPES**: Only assign a score to rules of these types.
This variable is a tuple: it contains rule types as strings. E.g.:
```
SUPPORTED_RULE_TYPES = ("allow", "type_transition")
```
If there is only one element in the tuple, insert a trailing comma to indicate the variable is in fact a tuple.

**RULE_IGNORE_PATHS**: Ignore rules coming from these paths.
This variable is a list: it contains paths relative to `BASE_DIR_GLOBAL` defined in the global SELint configuration file.

**MAXIMUM_SCORE**: The maximum score a rule can have. This value is used to normalize scores between 0 and 1.
Following from the formula for computing the score in both the `risk` and `trust` scoring systems, this value must be double the highest partial score assigned to a domain/type. The default configuration uses a `MAXIMUM_SCORE` value of 60, and a highest partial score of 30; these values can be changed if necessary.

**TYPES**: The classification of types. This variable is a dictionary {string: list}: it classifies types into "*bins*" identified by a semantic label. Bins group types with similar roles in the policy, to simplify the scoring.  Bins are assigned both a `risk` and a `trust` score: these are filed in the `SCORE_RISK` and `SCORE_TRUST` dictionaries under the bin's label.

The default configuration defines 5 bins for classifying types. You may add extra ones to suit your needs: simply add an entry to the `TYPES`, `SCORE_RISK` and `SCORE_TRUST` dictionaries.  E.g.:
```
# User-defined bin 1
SCORE_TRUST["user_bin_1"] = 10
SCORE_RISK["user_bin_1"] = 30
TYPES["user_bin_1"] = ["user_type_1", "user_type_2", "user_type_3"]
```

**SCORE_TRUST**: The `trust` scores. This variable is a dictionary {string: integer}, where the string is the label of a `TYPES` bin and the integer is the associated `trust` score for that bin.

**SCORE_RISK**: The `risk` scores. This variable is a dictionary {string: integer}, where the string is the label of a `TYPES` bin and the integer is the associated `risk` score for that bin.

**PERMS**: The classification of permissions. This variable is a dictionary {string: set}: it classifies permissions into sets identified by a semantic label. These sets group permissions with similar levels of risk, to simplify the scoring. These sets are assigned a `risk` coefficient, filed in the `SCORE` dictionary under the set's label. Permissions are not assigned a `trust` score, as that scoring system only deals with types.

The default configuration defines 3 sets for classifying permissions. You may add extra ones to suit your needs: simply add an entry to the `PERMS` and `SCORE` dictionaries. E.g.:
```
# User-defined set 1
SCORE["perms_user_1"] = 0.8
PERMS["perms_user_1"] = set(["perm1", "perm2"])
```
A permission must be present in only one set.

**SCORE**: The `risk` scores of non-type rule elements (permissions, capabilities). This variable is a dictionary {string: float}, where the string is the label of a `PERMS` or `CAPABILITIES` set, and the number is the associated `risk` coefficient or score for that set.

Permissions are assigned a `risk` coefficient, which is multiplied by the sum of the domain and type `risk` scores to compute the overall rule score.

Capabilities are assigned a `risk` score of their own, and they are treated as types when found in a rule: their score is added to the domain score to compute the overall rule score.
Currently we are targeting capabilities in an aggregate way (we assign a higher score to rules which grant any capabilities): in the future we may target capabilities individually, by dividing them into sets according to their level of risk.

**CAPABILITIES**: The classes associated with capabilities. This variable should be changed only if further classes were to be associated with capabilities in the future (e.g. a `capability3` class). In the future we may change how we handle capabilities.

**SCORE_THRESHOLD**: Don't report rules which score below this threshold.
This variable is a number between 0 and 1. E.g.:
```
SCORE_THRESHOLD = 0.8
```

**REVERSE_SORT**: Print the results in reverse order. This variable is a Boolean value.

**IGNORED_RULES**: Never report these rules. This variable is a list of strings. The rules must match exactly as strings.

#### Output
The plugin produces this output:
```
1.00: .../file.te:28: allow some_domain some_type:some_class { perm1 perm2 perm3 };
```
This means that, by combining the partial scores of its elements according to the selected scoring system, the rule has been assigned score 1 (maximum).

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
