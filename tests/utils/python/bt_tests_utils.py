# SPDX-FileCopyrightText: 2025 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: MIT

# pyright: strict

import enum
import types
import logging
import pathlib
import platform
from typing import Any, Callable, Optional

import pytest

_logger = logging.getLogger(__name__)


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


# A `pytest.Item` which offers the pytest 7+ API even when working
# with pytest 6:
#
# • path() is always available (returns `pathlib.Path`).
class PytestItem(pytest.Item):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)  # pyright: ignore[reportUnknownMemberType]
        assert "parent" in kwargs

        if hasattr(kwargs["parent"], "fspath"):
            # pytest 6
            self._path = pathlib.Path(str(self.fspath))
        else:
            # pytest 7+
            self._path = self.path

    @property
    def path(  # pyright: ignore[reportIncompatibleVariableOverride]
        self,
    ) -> pathlib.Path:
        return self._path

    @path.setter
    def path(  # pyright: ignore[reportIncompatibleVariableOverride]
        self, path: pathlib.Path
    ) -> None:
        self._path = path


# A `pytest.File` which offers the pytest 7+ API even when working
# with pytest 6:
#
# • from_parent() accepts `path` (`pathlib.Path` type).
# • path() is always available (returns `pathlib.Path`).
#
# Within your own collect(), create items of which the class
# inherits `PytestItem`.
class PytestFile(pytest.File):
    @classmethod
    def from_parent(  # pyright: ignore[reportIncompatibleMethodOverride]
        cls, parent: "pytest.Collector", *, path: pathlib.Path, **kwargs: Any
    ) -> "PytestFile":
        # Try pytest 7+ API first
        try:
            return super().from_parent(parent=parent, path=path, **kwargs)  # type: ignore[return-value]
        except TypeError:
            # Fall back to pytest 6 API
            import py.path  # pyright: ignore[reportMissingModuleSource]

            return super().from_parent(  # type: ignore[return-value]
                parent=parent, fspath=py.path.local(str(path)), **kwargs
            )

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        assert "path" in kwargs or "fspath" in kwargs

        # Normalize the path
        if "path" in kwargs:
            # pytest 7+
            self._path = self.path
        elif "fspath" in kwargs:
            # pytest 6
            self._path = pathlib.Path(str(self.fspath))

    @property
    def path(
        self,
    ) -> pathlib.Path:  # pyright: ignore[reportIncompatibleVariableOverride]
        return self._path

    @path.setter
    def path(
        self, path: pathlib.Path
    ) -> None:  # pyright: ignore[reportIncompatibleVariableOverride]
        self._path = path


# Installs a pytest_collect_file() hook within the module `module` which
# calls `func` which expects the pytest_collect_file() API of pytest 7+.
#
# This is needed because pytest checks the parameter names of hooks, and
# the `path` parameter (old `py.path.local` type) is deprecated in
# pytest 7+ in favor of `file_path` (`pathlib.Path` type).
#
# Use like this:
#
#     def _my_pytest_collect_file(file_path: pathlib.Path, parent):
#         # ...
#
#     btu.install_pytest_collect_file(sys.modules[__name__],
#                                     _my_pytest_collect_file)
#
# Within `func`, create a file object which inherits `PytestFile`.
def install_pytest_collect_file(
    module: types.ModuleType,
    func: Callable[..., Optional[PytestFile]],
) -> None:
    if hasattr(pytest, "version_tuple"):
        # pytest 7+: expect a `pathlib.Path` path
        def pytest_7_hook(
            file_path: pathlib.Path, parent: "pytest.Collector"
        ) -> Optional[PytestFile]:
            return func(file_path=file_path, parent=parent)

        setattr(module, "pytest_collect_file", pytest_7_hook)
        _logger.info(
            "Installed pytest 7+ pytest_collect_file() hook into module `{}`".format(
                module.__name__
            )
        )
    else:
        # pytest 6: expect a `py.path.local` path
        def pytest_6_hook(
            path: Any, parent: "pytest.Collector"
        ) -> Optional[PytestFile]:
            # Convert to `pathlib.Path`
            return func(file_path=pathlib.Path(str(path)), parent=parent)

        setattr(module, "pytest_collect_file", pytest_6_hook)
        _logger.info(
            "Installed pytest 6 pytest_collect_file() hook into module `{}`".format(
                module.__name__
            )
        )


# Returns the executable file path from `path`, appending `.exe`
# on MinGW if not already present.
def exe_path(path: pathlib.Path) -> pathlib.Path:
    if os_type() == OsType.MINGW and not path.name.endswith(".exe"):
        return path.with_suffix(path.suffix + ".exe")

    return path
