# SPDX-FileCopyrightText: 2025 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: MIT

# pyright: strict

import enum
import pathlib
import platform


class OsType(enum.Enum):
    # MinGW (Windows)
    MINGW = "mingw"

    # macOS
    DARWIN = "darwin"

    # Linux
    LINUX = "linux"

    # Cygwin (Windows)
    CYGWIN = "cygwin"

    # Anything else
    UNSUPPORTED = "unsupported"


# Returns the normalized OS type.
def os_type() -> OsType:
    system = platform.system().lower()

    if system.startswith("mingw") or "windows" in system:
        return OsType.MINGW
    elif system.startswith("cygwin"):
        return OsType.CYGWIN
    elif "darwin" in system:
        return OsType.DARWIN
    elif "linux" in system:
        return OsType.LINUX
    else:
        return OsType.UNSUPPORTED


# Directory containing the `bt2` Python package considering the root
# build directory `build_root_dir` (the build directory containing the
# `tests` directory).
def bt2_package_dir(build_root_dir: pathlib.Path) -> pathlib.Path:
    return build_root_dir / "src/bindings/python/bt2/build/build_lib"
