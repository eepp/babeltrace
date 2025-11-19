# SPDX-FileCopyrightText: 2025 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: MIT

# pyright: strict, reportMissingTypeStubs=false, reportPrivateUsage=false

import os
import sys
import typing
import logging
import pathlib

import pytest

if typing.TYPE_CHECKING:
    import bt2

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


# Adds paths to `sys.path` so that testing utilities and the `bt2`
# package are available.
def _setup_python_path(config: "pytest.Config") -> None:
    def add_to_sys_path(path: pathlib.Path) -> None:
        assert path.exists()
        sys.path.insert(0, str(path))

    # Add `utils/python` and `utils/python/vendor` to the module
    # search path (contains utilities).
    src_utils_python_path = _src_tests_dir() / "utils/python"
    add_to_sys_path(src_utils_python_path)
    src_utils_python_vendor_path = src_utils_python_path / "vendor"
    add_to_sys_path(src_utils_python_vendor_path)

    # Add a local directory containing a `typing.py` to the module
    # search path for Python 3.5 which only offers a partial
    # `typing` module.
    if sys.version_info[:2] == (3, 5):
        add_to_sys_path(src_utils_python_vendor_path / "typing")

    # Add the built `bt2` Python package to the module search path
    import bt_tests_utils as btu

    add_to_sys_path(btu.bt2_package_dir(_config_build_root_dir(config)))


# Sets plugin-related environment variables so that common utility
# plugins as well as compiled plugins are available to libbabeltrace2.
def _setup_babeltrace_plugins_env_vars(config: "pytest.Config") -> None:
    # Set `BABELTRACE_PLUGIN_PATH`
    plugins_path = _config_build_root_dir(config) / "src/plugins"
    plugin_path_parts = [
        _src_tests_dir() / "utils/python",
        plugins_path / "ctf",
        plugins_path / "utils",
        plugins_path / "text",
        plugins_path / "lttng-utils",
    ]
    os.environ["BABELTRACE_PLUGIN_PATH"] = ":".join(map(str, plugin_path_parts))

    # Set `LIBBABELTRACE2_PLUGIN_PROVIDER_DIR`
    os.environ["LIBBABELTRACE2_PLUGIN_PROVIDER_DIR"] = str(
        _config_build_root_dir(config) / "src" / "python-plugin-provider" / ".libs"
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


def pytest_configure(config: "pytest.Config") -> None:
    _set_config_build_root_tests_dirs(config)
    _setup_python_path(config)
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
def dummy_comp_cls() -> "bt2._SinkComponentClassConst":
    import bt2

    return bt2.find_plugin(
        "utils"
    ).sink_component_classes[  # pyright: ignore[reportOptionalMemberAccess]
        "dummy"
    ]
