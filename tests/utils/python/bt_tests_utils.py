# SPDX-FileCopyrightText: 2025 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: MIT

# pyright: strict, reportTypeCommentUsage=false

import os
import enum
import shlex
import types
import logging
import pathlib
import platform
import subprocess
from typing import Any, Dict, List, Callable, Optional

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


# Logs a command to be run.
def _log_run_cmd(
    env: Dict[str, str],
    exec_path: pathlib.Path,
    args: List[str],
    extra_env: Optional[Dict[str, str]],
) -> None:
    env_vars_to_log = {
        "ASAN_OPTIONS",
        "BABELTRACE_PLUGIN_PATH",
        "BT_TESTS_BUILDDIR",
        "BT_TESTS_CC_BIN",
        "BT_TESTS_PYTHON_BIN",
        "BT_TESTS_PYTHON_CONFIG_BIN",
        "BT_TESTS_SRCDIR",
        "DYLD_LIBRARY_PATH",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "LIBBABELTRACE2_PLUGIN_PROVIDER_DIR",
        "PYTHONPATH",
    }

    # Collect all environment variables to log
    env_to_log = {}  # type: Dict[str, str]

    for var_name in env_vars_to_log:
        if var_name in env:
            env_to_log[var_name] = env[var_name]

    if extra_env is not None:
        for var_name, var_val in extra_env.items():
            if var_name not in env_vars_to_log:
                env_to_log[var_name] = var_val

    # Build command parts, sorting environment variables by name
    cmd_parts = []  # type: List[str]

    for var_name in sorted(env_to_log.keys()):
        cmd_parts.append("{}={}".format(var_name, shlex.quote(env_to_log[var_name])))

    cmd_parts.append(shlex.quote(str(exec_path)))
    cmd_parts.extend(shlex.quote(arg) for arg in args)

    # Log
    _logger.info("Running: {}".format(" ".join(cmd_parts)))


# Like subprocess.run(), but always captures the standard streams and
# sets the `PYTHONPATH` environment variable to the directory containing
# the built `bt2` package.
#
# `exec_path` is the path to the executable to use: don't include it in
# `args`. This function automatically adds the `.exe` suffix on Windows
# if `windows_safe` is `True`.
#
# `build_root_dir` is the build directory containing the
# `tests` directory
#
# This function adds the `extra_env` environment dictionary to the
# current environment before running the subprocess.
#
# `check`, `text`, and `timeout` are subprocess.run() parameters.
def run(
    build_root_dir: pathlib.Path,
    exec_path: pathlib.Path,
    args: List[str],
    check: bool = False,
    text: bool = True,
    timeout: Optional[float] = None,
    windows_safe: bool = True,
    extra_env: Optional[Dict[str, str]] = None,
) -> "subprocess.CompletedProcess[str]":
    # Add `.exe` suffix on Windows (MinGW)
    if windows_safe:
        exec_path = exe_path(exec_path)

    env = os.environ.copy()

    # The `PYTHONPATH` environment variable must include:
    #
    # • The directory containing the built `bt2` package.
    #
    # • This directory (`tests/utils/python`) so that Babeltrace2
    #   Python _plugins_ may import testing Python modules
    #   (for example, `cli_params_to_string`).
    env["PYTHONPATH"] = os.pathsep.join(
        [
            str(bt2_package_dir(build_root_dir)),
            str(pathlib.Path(__file__).resolve().parent),
        ]
    )

    if extra_env is not None:
        env.update(extra_env)

    _log_run_cmd(env, exec_path, args, extra_env)

    res = subprocess.run(  # type: subprocess.CompletedProcess[str]
        [str(exec_path)] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
        env=env,
        timeout=timeout,
        universal_newlines=text,
    )

    _logger.info("  Exit status: {}".format(res.returncode))
    return res
