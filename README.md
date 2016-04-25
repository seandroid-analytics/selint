# SELint
SELint is an SEAndroid policy analysis tool. It performs a series of checks on a source policy, suggesting improvements to the policy developer.

## Obtaining SELint
SELing may be obtained by cloning this repository. From the command line, do:

```
$ git clone git@github.com:seandroid-analytics/selint.git
```

SELint requires the `setools` library from [SEToolsv4](https://github.com/TresysTechnology/setools).

### Using `setools4` from the AOSP tree (recommended)
The `setools` library is distributed as part of the [AOSP tree](https://source.android.com/source/index.html), where it is bundled as a prebuilt. After [downloading the AOSP tree](https://source.android.com/source/downloading.html) in `<WORKING_DIRECTORY>`, the `setools` package will be in
```
<WORKING_DIRECTORY>/prebuilts/python/linux-x86/2.7.5/lib/python2.7/site-packages
```
To use this package, add this path to your `$PYTHONPATH`; for example, on Ubuntu 14.04 LTS add this to your `.profile`:
```
export PYTHONPATH="<WORKING_DIRECTORY>/prebuilts/python/linux-x86/2.7.5/lib/python2.7/site-packages:$PYTHONPATH"
```

### Using `setools4` from the official git repository
You may also use the latest version of the `setools` library from the [official git repo](https://github.com/TresysTechnology/setools).

After cloning the repo in `<SETOOLS4_DIRECTORY>`, you need to build SETools for local use: follow the instructions on the official SETools repo.
To use the newly built software, add the directory to your `$PYTHONPATH`; for example, on Ubuntu 14.04 LTS add this to your `.profile`:
```
export PYTHONPATH="<SETOOLS4_DIRECTORY>:$PYTHONPATH"
```

## Running SELint
Before running SELint, you need to configure it to work on the desired SEAndroid policy source files. You can specify them in a configuration file.
The configuration file is a regular Python file; the default one is `config.py` in the project directory, which you can modify directly or use as reference to see what configuration parameters are available.
You can pass SELint a different configuration file with the `-c` option.

After configuring the software, you can run it:
```
$ ./selint [OPTIONS]
```

### Usage
You may obtain the full list of command line options by running:
```
$ ./selint -h
usage: selint [-h] [-l] [-w <PLUGIN> [<PLUGIN> ...] | -b <PLUGIN>
              [<PLUGIN> ...]] [-D NAME[=VALUE] [NAME[=VALUE] ...]]
              [--dumppolicyconf <FILE>] [--listpolicyfiles] [-v <LVL>]
              [-c <FILE>]

SELinux source policy analysis tool.

optional arguments:
  -h, --help            show this help message and exit
  -l, --list            list the available plugins and exit.
  -w <PLUGIN> [<PLUGIN> ...], --whitelist <PLUGIN> [<PLUGIN> ...]
                        specify the plugins to run [Default: run all].
  -b <PLUGIN> [<PLUGIN> ...], --blacklist <PLUGIN> [<PLUGIN> ...]
                        specify the plugins not to run [Default: run all].
  -D NAME[=VALUE] [NAME[=VALUE] ...], --define NAME[=VALUE] [NAME[=VALUE] ...]
                        Pass additional definitions to M4 when expanding the
                        policy. Identical to the -D option in m4.
  --dumppolicyconf <FILE>
                        write the policy.conf to a user-specified file. If the
                        file already exists, IT WILL BE OVERWRITTEN.
  --listpolicyfiles     List all the recognized policy files and exit.
  -v <LVL>, --verbosity <LVL>
                        Be verbose. Supported levels are 0-4, with 0 being the
                        default.
  -c <FILE>, --config <FILE>
                        Source the specified config file [Default: config.py].

If not differently specified, all available plugins will be run.
```

### Example usages
Here are some example usages of SELint which you may find useful.

See all available plugins:
```
$ ./selint -l
```

Run `global_macros` and `te_macros` plugins, using a user-provided configuration file:
```
$ ./selint -c user-config.py -w global_macros te_macros
```

Run all plugins except `global_macros` and `te_macros`, using a user-provided configuration file:
```
$ ./selint -c user-config.py -b global_macros te_macros
```

List all the recognized policy files from a user-provided configuration file and exit:
```
$ ./selint -c user-config.py --listpolicyfiles
```


## Reporting bugs
You can report bugs in the project [issue tracker](https://github.com/seandroid-analytics/selint/issues).

## License
Copyright 2015 Aalto University

The SELint program and its plugins are licensed under the Apache License 2.0 (see [LICENSE.APACHE](LICENSE.APACHE)). The `policysource` library is licensed under the GNU Lesser General Public License (see [LICENSE.LGPL](LICENSE.LGPL)). All files distributed with this package indicate the appropriate license to use.

SELint is an open source project being developed by Filippo Bonazzi and Elena Reshetova from the [Secure Systems research group (SSG)](http://cse.aalto.fi/en/research/secure-systems/) at Aalto University. The project is part of the [Intel Collaborative Research Institute for Secure Computing (ICRI-SC)](http://www.icri-sc.org).
