# SPDX-FileCopyrightText: 2025 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: MIT

# pyright: strict, reportMissingTypeStubs=false, reportTypeCommentUsage=false, reportPrivateUsage=false

import os
import re
import sys
import typing
import logging
import pathlib
import subprocess
from typing import Any, List, Optional

import pytest

if typing.TYPE_CHECKING:
    import bt2
    import bt_tests_utils as btu

_logger = logging.getLogger(__name__)


# Helper functions to access/set dynamic config attributes (satisfies type checker)
def _config_build_root_dir(config: "pytest.Config") -> pathlib.Path:
    return getattr(config, "build_root_dir")


def _set_config_build_root_dir(config: "pytest.Config", path: pathlib.Path) -> None:
    setattr(config, "build_root_dir", path)


def _config_build_tests_dir(config: "pytest.Config") -> pathlib.Path:
    return getattr(config, "build_tests_dir")


def _src_root_dir() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent.parent


def _src_tests_dir() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent


def _add_to_sys_path(path: pathlib.Path) -> None:
    assert path.exists()
    sys.path.insert(0, str(path))


# Adds paths to `sys.path` so that testing utilities are available.
def _setup_init_python_path() -> None:
    # Add `utils/python` and `utils/python/vendor` to the module
    # search path (contains utilities).
    src_utils_python_path = _src_tests_dir() / "utils/python"
    _add_to_sys_path(src_utils_python_path)
    src_utils_python_vendor_path = src_utils_python_path / "vendor"
    _add_to_sys_path(src_utils_python_vendor_path)

    # Add a local directory containing a `typing.py` to the module search
    # path for Python 3.5 which only offers a partial `typing` module.
    if sys.version_info[:2] == (3, 5):
        _add_to_sys_path(src_utils_python_path / "typing")


# This needs to happen now because we need `bt_tests_utils` within
# this module.
_setup_init_python_path()


# Safe to import now.
import bt_tests_utils as btu  # noqa: E402


# Adds the `bt2` package path to `sys.path`.
def _setup_bt2_python_path(config: "pytest.Config") -> None:
    _add_to_sys_path(btu.bt2_package_dir(_config_build_root_dir(config)))


# Sets plugin-related environment variables so that common utility
# plugins as well as compiled plugins are available to libbabeltrace2.
def _setup_babeltrace_plugins_env_vars(config: "pytest.Config") -> None:
    import bt_tests_utils as btu

    # Set `BABELTRACE_PLUGIN_PATH`
    plugins_path = _config_build_root_dir(config) / "src/plugins"
    plugin_path_parts = [
        _src_tests_dir() / "utils/python",
        plugins_path / "ctf",
        plugins_path / "utils",
        plugins_path / "text",
        plugins_path / "lttng-utils",
    ]
    os.environ["BABELTRACE_PLUGIN_PATH"] = (
        ";" if btu.os_type() == btu.OsType.MINGW else ":"
    ).join(map(str, plugin_path_parts))

    # Set `LIBBABELTRACE2_PLUGIN_PROVIDER_DIR`
    os.environ["LIBBABELTRACE2_PLUGIN_PROVIDER_DIR"] = str(
        _config_build_root_dir(config) / "src/python-plugin-provider/.libs"
    )


def _set_config_build_root_tests_dirs(config: "pytest.Config") -> None:
    bt_tests_builddir = os.environ.get("BT_TESTS_BUILDDIR")
    build_dir_arg = config.getoption("--build-dir")

    if bt_tests_builddir:
        # `BT_TESTS_BUILDDIR` specifies the `tests` build directory
        _set_config_build_root_dir(
            config, pathlib.Path(bt_tests_builddir).resolve().parent
        )
    elif build_dir_arg:
        # `--build-dir` specifies the root build directory
        _set_config_build_root_dir(config, pathlib.Path(build_dir_arg).resolve())
    else:
        # Default to the root source directory (in-tree build)
        _set_config_build_root_dir(config, _src_root_dir())

    setattr(config, "build_tests_dir", _config_build_root_dir(config) / "tests")


def _log_env_var(name: str) -> None:
    _logger.info(
        "  `{}` environment variable: `{}`".format(name, os.environ.get(name, ""))
    )


# pytest hook.
def pytest_sessionstart(session: "pytest.Session") -> None:
    _logger.info("pytest_sessionstart():")
    _logger.info("  Root source directory: `{}`".format(_src_root_dir()))
    _logger.info(
        "  Root build directory: `{}`".format(_config_build_root_dir(session.config))
    )
    _logger.info(
        "  `tests` build directory: `{}`".format(
            _config_build_tests_dir(session.config)
        )
    )
    _log_env_var("ASAN_OPTIONS")
    _log_env_var("BABELTRACE_PLUGIN_PATH")
    _log_env_var("BT_TESTS_BUILDDIR")
    _log_env_var("BT_TESTS_CC_BIN")
    _log_env_var("BT_TESTS_PYTHON_BIN")
    _log_env_var("BT_TESTS_PYTHON_CONFIG_BIN")
    _log_env_var("BT_TESTS_SRCDIR")
    _log_env_var("DYLD_LIBRARY_PATH")
    _log_env_var("LD_LIBRARY_PATH")
    _log_env_var("LD_PRELOAD")
    _log_env_var("LIBBABELTRACE2_PLUGIN_PROVIDER_DIR")
    _log_env_var("PATH")
    _logger.info("  `sys.path` value: {}".format(sys.path))

    import bt2  # noqa: F401

    _logger.info("  `bt2` package version: {}".format(bt2.__version__))


# pytest hook.
def pytest_configure(config: "pytest.Config") -> None:
    _set_config_build_root_tests_dirs(config)
    _setup_bt2_python_path(config)
    setattr(config, "src_tests_dir", _src_tests_dir())
    setattr(config, "ctf_traces_dir", _src_tests_dir() / "data/ctf-traces")
    _setup_babeltrace_plugins_env_vars(config)

    # Sanity check
    try:
        import bt2  # noqa: F401  # pyright: ignore[reportUnusedImport]
    except ImportError as exc:
        raise RuntimeError(
            "Failed to import the `bt2` package: make sure to source `tests/utils/pytest-env.sh` before you run pytest."
        ) from exc


# pytest hook.
def pytest_addoption(parser: "pytest.Parser") -> None:
    parser.addoption(
        "--build-dir",
        action="store",
        default=None,
        help="Root build directory (defaults to root of source directory)",
    )


@pytest.fixture(scope="session")
def src_root_dir() -> pathlib.Path:
    return _src_root_dir()


@pytest.fixture(scope="session")
def src_tests_dir() -> pathlib.Path:
    return _src_tests_dir()


@pytest.fixture(scope="session")
def build_root_dir(request: "pytest.FixtureRequest") -> pathlib.Path:
    return _config_build_root_dir(request.config)


@pytest.fixture(scope="session")
def build_tests_dir(request: "pytest.FixtureRequest") -> pathlib.Path:
    return _config_build_tests_dir(request.config)


@pytest.fixture(scope="session")
def data_dir() -> pathlib.Path:
    return _src_tests_dir() / "data"


@pytest.fixture(scope="session")
def ctf_traces_dir(data_dir: pathlib.Path) -> pathlib.Path:
    return data_dir / "ctf-traces"


@pytest.fixture(scope="session")
def muxer_comp_cls() -> "bt2._FilterComponentClassConst":
    import bt2

    return bt2.find_plugin(
        "utils"
    ).filter_component_classes[  # pyright: ignore[reportOptionalMemberAccess]
        "muxer"
    ]


@pytest.fixture(scope="session")
def sink_ctf_comp_cls() -> "bt2._SinkComponentClassConst":
    import bt2

    return bt2.find_plugin(
        "ctf"
    ).sink_component_classes[  # pyright: ignore[reportOptionalMemberAccess]
        "fs"
    ]


@pytest.fixture(scope="session")
def src_ctf_comp_cls() -> "bt2._SourceComponentClassConst":
    import bt2

    return bt2.find_plugin(
        "ctf"
    ).source_component_classes[  # pyright: ignore[reportOptionalMemberAccess]
        "fs"
    ]


@pytest.fixture(scope="session")
def trimmer_comp_cls() -> "bt2._FilterComponentClassConst":
    import bt2

    return bt2.find_plugin(
        "utils"
    ).filter_component_classes[  # pyright: ignore[reportOptionalMemberAccess]
        "trimmer"
    ]


@pytest.fixture(scope="session")
def details_comp_cls() -> "bt2._SinkComponentClassConst":
    import bt2

    return bt2.find_plugin(
        "text"
    ).sink_component_classes[  # pyright: ignore[reportOptionalMemberAccess]
        "details"
    ]


@pytest.fixture(scope="session")
def pretty_comp_cls() -> "bt2._SinkComponentClassConst":
    import bt2

    return bt2.find_plugin(
        "text"
    ).sink_component_classes[  # pyright: ignore[reportOptionalMemberAccess]
        "pretty"
    ]


@pytest.fixture(scope="session")
def dmesg_comp_cls() -> "bt2._SourceComponentClassConst":
    import bt2

    return bt2.find_plugin(
        "text"
    ).source_component_classes[  # pyright: ignore[reportOptionalMemberAccess]
        "dmesg"
    ]


@pytest.fixture(scope="session")
def dummy_comp_cls() -> "bt2._SinkComponentClassConst":
    import bt2

    return bt2.find_plugin(
        "utils"
    ).sink_component_classes[  # pyright: ignore[reportOptionalMemberAccess]
        "dummy"
    ]


@pytest.fixture(scope="session")
def os_type() -> "btu.OsType":
    import bt_tests_utils as btu

    return btu.os_type()


class _Catch2TestItem(btu.PytestItem):
    def __init__(
        self,
        *,
        test_binary: pathlib.Path,
        catch2_test_name: str,
        build_root_dir: pathlib.Path,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self._test_binary = test_binary
        self._catch2_test_name = catch2_test_name
        self._build_root_dir = build_root_dir

    def runtest(self) -> None:
        _logger.info(
            "Running Catch2 test case `{}` in `{}`".format(
                self._catch2_test_name, self._test_binary
            )
        )
        result = btu.run(
            self._build_root_dir,
            self._test_binary,
            [self._catch2_test_name],
        )

        if result.returncode != 0:
            raise _Catch2TestException(self._catch2_test_name, result)

    def reportinfo(self):
        return self.path, None, self.name

    def repr_failure(
        self,
        excinfo: "pytest.ExceptionInfo[BaseException]",
        style: Any = None,
    ):
        if isinstance(excinfo.value, _Catch2TestException):
            return excinfo.value.format_output()

        return super().repr_failure(excinfo, style)


class _Catch2TestException(Exception):
    def __init__(
        self, catch2_test_name: str, result: "subprocess.CompletedProcess[str]"
    ):
        super().__init__("Catch2 test failed: `{}`".format(catch2_test_name))
        self._result = result

    def format_output(self) -> str:
        output = []  # type: List[str]

        if self._result.stdout:
            output.append("⚠️ Standard output:")
            output.append(self._result.stdout)

        if self._result.stderr:
            output.append("\n⚠️ Standard error:")
            output.append(self._result.stderr)

        return "\n".join(output).strip()


class _Catch2TestFile(btu.PytestFile):
    @staticmethod
    def _normalize_catch2_test_name(test_name: str) -> str:
        test_name = test_name.lower()
        test_name = re.sub(r"[ :-]", "_", test_name)
        test_name = re.sub(r"_{2,}", "_", test_name)
        test_name = re.sub(r"\W", "", test_name)
        return "test_" + test_name

    def collect(self) -> List[_Catch2TestItem]:
        # Build the test binary path (remove `.cpp` extension)
        test_binary = btu.exe_path(
            _config_build_tests_dir(self.config)
            / self.path.relative_to(_src_tests_dir()).with_suffix("")
        )

        # Skip if the binary doesn't exist
        if not test_binary.exists():
            pytest.skip("`{}` Catch2 binary doesn't exist".format(test_binary))
        else:
            assert os.access(test_binary, os.X_OK)

        # List test names from Catch2.
        #
        # With the `--list-test-names-only` option, Catch2 uses the
        # number of test cases as its exit status. Therefore ignore the
        # exit status here.
        _logger.info("Listing Catch2 test case names from `{}`".format(test_binary))
        build_root_dir = _config_build_root_dir(self.config)
        result = btu.run(
            build_root_dir,
            test_binary,
            ["--list-test-names-only"],
        )
        _logger.debug(result.stdout)

        # Parse test names and create corresponding test items
        items = []  # type: List[_Catch2TestItem]

        for line in result.stdout.strip().split("\n"):
            test_name = line.strip()

            if test_name:
                # Normalize the test name for the pytest node ID
                _logger.info(
                    "Adding Catch2 test case `{}` from `{}`".format(
                        test_name, test_binary
                    )
                )
                items.append(
                    _Catch2TestItem.from_parent(  # pyright: ignore[reportUnknownMemberType]
                        name=self._normalize_catch2_test_name(test_name),
                        parent=self,
                        test_binary=test_binary,
                        catch2_test_name=test_name,
                        build_root_dir=build_root_dir,
                    )
                )

        # Return test items
        return items


# pytest hook.
def _pytest_collect_file(
    file_path: pathlib.Path, parent: "pytest.Collector"
) -> Optional[_Catch2TestFile]:
    if file_path.suffix == ".cpp" and file_path.name.startswith("test-"):
        return typing.cast(
            _Catch2TestFile, _Catch2TestFile.from_parent(parent=parent, path=file_path)
        )

    return


btu.install_pytest_collect_file(sys.modules[__name__], _pytest_collect_file)
