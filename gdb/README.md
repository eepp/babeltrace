# Babeltrace GDB helpers

This directory contains helpers for debugging Babeltrace with
[GDB](https://sourceware.org/gdb/).


## Common requirements

  * GDB 7.0+ (7.10+ is preferred) with Python support
    (find `--with-python` in the output of `gdb --configuration`)
  * Python 3


## Quick start

From your favorite shell, source `gdb/activate.sh` from the root of
Babeltrace's tree:

    source gdb/activate.sh

This will create an alias `gdb` which loads the Babeltrace GDB
helper commands and scripts.

Execute `gdb` as usual.


## Commands

The GDB helpers add the following GDB commands.


### `bt-inspect` (alias: `bti`)

Launches `bt-inspect` on the given Babeltrace object.

`bt-inspect` is a GUI program which allows the user to inspect a
Babeltrace object recursively, find objects, and perform various
analyses on the object and its children.

**Requirements**:

  * Qt 5
  * [PyQt5](https://riverbankcomputing.com/software/pyqt/download5)
    Python 3 package (available in most distributions)
  * [bt-inspect](https://pypi.python.org/pypi/bt-inspect) Python 3 package

**Syntax**:

    bt-inspect <CTF IR object>

**Examples**:

    bt-inspect event->event_class
    bt-inspect my_type


### `bt-resolve-show-type-stack`

Shows the current elements of the given resolving type stack.

**Syntax**:

    bt-resolve-show-type-stack <resolving type stack>

**Example**:

    bt-resolve-show-type-stack ctx.type_stack
