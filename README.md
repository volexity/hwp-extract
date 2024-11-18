# HWP Extract

This is a Python utility for extracting objects and metadata from `.hwp` files. This script supports extraction of objects from password
protected HWP files (assuming a password is provided).

## Installation

To install HWP Extract, you can use something like this:

`python -m pip install hwp-extract`

## Usage as a library

For examples of how to use HWP Extract as a library, review the code in `src/hwpextract/cli.py`

## CLI usage

Following successful installation of HWP Extract a new CLI utility will be available, for usage see:

`hwp-extract --help`

### Extract embedded files

`hwp-extract /path/to/file.hwp --extract-files`

### Display metadata

`hwp-extract /path/to/file.hwp --extract-meta`

### Extract embedded files from a password protected HWP file with password 1234

`hwp-extract /path/to/file.hwp --extract-files --password 1234`

## Disclaimer

There's another great library for working with .hwp files which is published [here](https://github.com/mete0r/pyhwp). The primary reasons to use this library over pyhwp are:

* Simpler CLI interaction
* Support for password protected HWP files.

If you're looking for a function in this library that doesn't exist, it may well exist in PyHwp.
