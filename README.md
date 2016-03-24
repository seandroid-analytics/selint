# SELint
SELint is an SEAndroid policy analysis tool. It performs a series of checks on a source policy, suggesting improvements to the policy developer.

## Obtaining SELint
SELing may be obtained by cloning this repository. From the command line, do:

```
$ git clone git@github.com:seandroid-analytics/selint.git
```

SELint requires the `setools` library from [SEToolsv4](https://github.com/TresysTechnology/setools).
The `setools` library is also distributed as part of the [AOSP tree](https://source.android.com/source/index.html), where it is distributed as a prebuilt. After [downloading the AOSP tree](https://source.android.com/source/downloading.html) in `$WORKING_DIRECTORY`, the `setools` package will be in
```
$WORKING_DIRECTORY/prebuilts/python/linux-x86/2.7.5/lib/python2.7/site-packages
```
To use this package, add this path to your `$PYTHONPATH`; for example, on Ubuntu 14.04 LTS add this to your `.profile`:
```
export PYTHONPATH="$WORKING_DIRECTORY/prebuilts/python/linux-x86/2.7.5/lib/python2.7/site-packages:$PYTHONPATH"
```

## Running SELint
From the resulting directory, run:
```
$ python selint [OPTIONS]
```

## Reporting bugs
You can report bugs in the project [issue tracker](https://github.com/seandroid-analytics/selint/issues).

## License
Copyright 2015 Aalto University

The SELint program and its plugins are licensed under the Apache License 2.0 (see [LICENSE.APACHE](LICENSE.APACHE)). The `policysource` library is licensed under the GNU Lesser General Public License (see [LICENSE.LGPL](LICENSE.LGPL)). All files distributed with this package indicate the appropriate license to use.

SELint is an open source project being developed by Filippo Bonazzi and Elena Reshetova from the [Secure Systems research group (SSG)](http://cse.aalto.fi/en/research/secure-systems/) at Aalto University. The project is part of the [Intel Collaborative Research Institute for Secure Computing (ICRI-SC)](http://www.icri-sc.org).
