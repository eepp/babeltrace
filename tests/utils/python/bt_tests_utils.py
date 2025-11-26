# SPDX-FileCopyrightText: 2025 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: MIT

# pyright: strict, reportTypeCommentUsage=false, reportMissingTypeStubs=false, reportPrivateUsage=false

import os
import enum
import time
import shlex
import types
import typing
import logging
import pathlib
import platform
import tempfile
import textwrap
import itertools
import subprocess
from typing import Any, Dict, List, Type, Tuple, Union, Callable, Iterable, Optional

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


# Formats `obj` as a `babeltrace2` CLI `--params` value string.
#
# `obj` may be `None`, a boolean, a number, a string, a list, or
# a dictionary.
#
# This function doesn't escape special characters in strings.
def cli_params_from_obj(obj: Any, is_root: bool = True) -> str:
    if obj is None:
        return "null"
    elif isinstance(obj, bool):
        return "yes" if obj else "no"
    elif isinstance(obj, int):
        return str(obj)
    elif isinstance(obj, float):
        return str(obj)
    elif isinstance(obj, str):
        return '"{}"'.format(obj)
    elif isinstance(obj, list):
        return "[{}]".format(
            ", ".join(
                cli_params_from_obj(item, False) for item in typing.cast(List[Any], obj)
            )
        )
    elif isinstance(obj, dict):
        items = ", ".join(
            "{}={}".format(k, cli_params_from_obj(v, False))
            for k, v in typing.cast(Dict[str, Any], obj).items()
        )

        return items if is_root else "{{{}}}".format(items)
    else:
        assert False


if typing.TYPE_CHECKING:
    import bt2

    # Any component type
    _AnyCompT = Union[
        bt2._GenericSourceComponentConst,
        bt2._GenericFilterComponentConst,
        bt2._GenericSinkComponentConst,
    ]

    # Any component class type (user class or wrapper)
    _AnyCompClsT = Union[
        bt2._SourceComponentClassConst,
        bt2._FilterComponentClassConst,
        bt2._SinkComponentClassConst,
        Type[bt2._UserSourceComponent],
        Type[bt2._UserFilterComponent],
        Type[bt2._UserSinkComponent],
    ]


# Sink component specification to be used with convert().
#
# Similar to `bt2.ComponentSpec` but for sink component classes.
class SinkComponentSpec:
    def __init__(
        self,
        component_class: Union[
            "bt2._SinkComponentClassConst",
            Type["bt2._UserSinkComponent"],
        ],
        params: "bt2._ComponentParams" = None,
        obj: object = None,
        logging_level: Optional["bt2.LoggingLevel"] = None,
    ):
        import bt2

        self._component_class = component_class
        self._params = bt2.create_value(params)
        self._obj = obj
        self._logging_level = (
            logging_level if logging_level is not None else bt2.LoggingLevel.NONE
        )

    @property
    def component_class(
        self,
    ) -> Union[
        "bt2._SinkComponentClassConst",
        Type["bt2._UserSinkComponent"],
    ]:
        return self._component_class

    @property
    def params(self) -> Optional["bt2._Value"]:
        return self._params

    @property
    def obj(self) -> object:
        return self._obj

    @property
    def logging_level(self) -> "bt2.LoggingLevel":
        return self._logging_level


# Returns a string representation of a component class spec for logging.
def _fmt_comp_cls_spec(comp_cls: "_AnyCompClsT") -> str:
    import bt2

    # Determine the component type prefix
    if isinstance(comp_cls, bt2._SourceComponentClassConst) or (
        isinstance(comp_cls, type) and issubclass(comp_cls, bt2._UserSourceComponent)
    ):
        type_prefix = "src"
    elif isinstance(comp_cls, bt2._FilterComponentClassConst) or (
        isinstance(comp_cls, type) and issubclass(comp_cls, bt2._UserFilterComponent)
    ):
        type_prefix = "flt"
    else:
        assert isinstance(comp_cls, bt2._SinkComponentClassConst) or (
            isinstance(comp_cls, type) and issubclass(comp_cls, bt2._UserSinkComponent)
        )
        type_prefix = "sink"

    # Get the plugin name if available
    plugin_name = getattr(comp_cls, "plugin_name", None) or "<none>"

    # Create string
    return "{}.{}.{}".format(type_prefix, plugin_name, comp_cls.name)


# Returns a string representation of a component spec for logging.
def _fmt_comp_spec(
    comp_spec: Union["bt2.ComponentSpec", SinkComponentSpec], indent: int
) -> str:
    return "{ind}`{cc_spec}`:\n{ind}  Params: {params}".format(
        ind=" " * indent,
        cc_spec=_fmt_comp_cls_spec(comp_spec.component_class),
        params=repr(comp_spec.params),
    )


# Returns a unique component name for a component class and the updated
# next suffix.
#
# `all_comps` is a list of all components created so far.
#
# `next_suffix` is the next suffix to use if a name collision occurs.
def _get_unique_comp_name(
    comp_cls: "_AnyCompClsT",
    all_comps: List["_AnyCompT"],
    next_suffix: int,
) -> Tuple[str, int]:
    name = comp_cls.name

    if name in [comp.name for comp in all_comps]:
        name += "-{}".format(next_suffix)
        next_suffix += 1

    return name, next_suffix


# Creates a component from a component spec.
#
# `all_comps` is a list of all components created so far.
#
# `next_suffix` is the next suffix to use if a name collision occurs.
#
# Returns the created component and the updated next suffix.
def _create_comp(
    graph: "bt2.Graph",
    comp_spec: Union["bt2.ComponentSpec", SinkComponentSpec],
    all_comps: List["_AnyCompT"],
    next_suffix: int,
) -> Tuple["_AnyCompT", int]:
    import bt2

    comp_cls = comp_spec.component_class
    comp_name, next_suffix = _get_unique_comp_name(comp_cls, all_comps, next_suffix)
    _logger.info(
        "  Instantiating `{}` as component `{}`".format(
            _fmt_comp_cls_spec(comp_cls), comp_name
        )
    )
    comp = graph.add_component(
        comp_cls,
        comp_name,
        typing.cast(bt2._ComponentParams, comp_spec.params),
        comp_spec.obj,
        (
            bt2.LoggingLevel.NONE
            if comp_spec.logging_level is None
            else comp_spec.logging_level
        ),
    )
    all_comps.append(comp)
    return comp, next_suffix


# Returns the next free input port of an `flt.utils.muxer` component.
def _get_free_muxer_input_port(
    muxer_comp: "bt2._GenericFilterComponentConst",
) -> Optional["bt2._InputPortConst"]:
    for port in muxer_comp.input_ports.values():
        if not port.is_connected:
            return port

    return


# Logs and connects ports.
def _connect_ports(
    graph: "bt2.Graph",
    out_port: "bt2._OutputPortConst",
    out_comp: "_AnyCompT",
    in_port: "bt2._InputPortConst",
    in_comp: "_AnyCompT",
) -> None:
    _logger.info(
        "  Connecting ports: `{}` of `{}` → `{}` of `{}`".format(
            out_port.name, out_comp.name, in_port.name, in_comp.name
        )
    )
    graph.connect_ports(out_port, in_port)


# Runs a graph to completion with the given component specifications.
#
# Similar to `bt2.TraceCollectionMessageIterator`, but:
#
# • Not an iterator (runs to completion).
# • Accepts a single sink component spec.
# • No stream intersection feature.
# • No `flt.utils.trimmer` feature.
# • No custom plugin set.
#
# `src_component_specs` and `flt_component_specs` are like
# their bt2.TraceCollectionMessageIterator.__init__() equivalent.
def convert(
    src_component_specs: Union[
        str,
        pathlib.Path,
        "bt2.AutoSourceComponentSpec",
        "bt2.ComponentSpec",
        Iterable[
            Union[str, pathlib.Path, "bt2.AutoSourceComponentSpec", "bt2.ComponentSpec"]
        ],
    ],
    sink_component_spec: SinkComponentSpec,
    flt_component_specs: Optional[
        Union["bt2.ComponentSpec", Iterable["bt2.ComponentSpec"]]
    ] = None,
    mip_version: Optional[int] = None,
) -> None:
    import bt2

    _logger.info("btu.convert():")

    # Normalize `src_component_specs` to a list
    if isinstance(
        src_component_specs,
        (str, pathlib.Path, bt2.AutoSourceComponentSpec, bt2.ComponentSpec),
    ):
        src_component_specs = [src_component_specs]

    # Convert strings to `AutoSourceComponentSpec`
    src_component_specs = [
        (
            bt2.AutoSourceComponentSpec(str(spec))
            if isinstance(spec, (str, pathlib.Path))
            else spec
        )
        for spec in src_component_specs
    ]

    # Normalize `flt_component_specs` to a list
    if isinstance(flt_component_specs, bt2.ComponentSpec):
        flt_component_specs = [flt_component_specs]

    if flt_component_specs is None:
        flt_component_specs = []

    # Combine all source component specs
    all_src_component_specs = [
        spec for spec in src_component_specs if type(spec) is bt2.ComponentSpec
    ] + bt2.source_component_specs_from_auto_source_component_specs(
        [
            spec
            for spec in src_component_specs
            if type(spec) is bt2.AutoSourceComponentSpec
        ]
    )

    # Validate filter component specs and convert to list
    flt_component_specs = list(flt_component_specs)

    for comp_spec in flt_component_specs:
        assert isinstance(comp_spec, bt2.ComponentSpec)

    # Log source component specs
    _logger.info("  Source component specs ({})".format(len(all_src_component_specs)))

    for comp_spec in all_src_component_specs:
        _logger.info(_fmt_comp_spec(comp_spec, 4))

    # Log filter component specs
    _logger.info("  Filter component specs ({})".format(len(flt_component_specs)))

    for comp_spec in flt_component_specs:
        _logger.info(_fmt_comp_spec(comp_spec, 4))

    # Log sink component spec
    _logger.info("  Sink component spec:")
    _logger.info(_fmt_comp_spec(sink_component_spec, 4))

    # State for unique component naming
    next_suffix = 1
    all_comps = []  # type: List[_AnyCompT]

    # Compute greatest operative MIP version if not provided
    if mip_version is None:
        _logger.info("  Computing greatest operative MIP version")
        descriptors = []  # type: List[bt2.ComponentDescriptor]

        for comp_spec in itertools.chain(
            all_src_component_specs, flt_component_specs, [sink_component_spec]
        ):
            descriptors.append(
                bt2.ComponentDescriptor(
                    comp_spec.component_class,
                    typing.cast(bt2._ComponentParams, comp_spec.params),
                )
            )

        mip_version = bt2.get_greatest_operative_mip_version(descriptors)

        if mip_version is None:
            raise RuntimeError("failed to find an operative MIP version")

    # Build graph
    _logger.info("  Creating graph with MIP {}".format(mip_version))
    graph = bt2.Graph(mip_version)

    # Create muxer
    plugin = bt2.find_plugin("utils")

    if plugin is None:
        raise RuntimeError(
            "cannot find `utils` plugin (needed for the `flt.utils.muxer`)"
        )

    if "muxer" not in plugin.filter_component_classes:
        raise RuntimeError("cannot find `flt.utils.muxer` within the `utils` plugin")

    _logger.info("  Creating component `muxer` (utils.muxer)")
    muxer_comp = graph.add_component(plugin.filter_component_classes["muxer"], "muxer")
    all_comps.append(muxer_comp)

    # Track the last output port and its component in the chain
    last_out_port = muxer_comp.output_ports["out"]
    last_out_comp = muxer_comp

    # Create filter components (chained)
    for comp_spec in flt_component_specs:
        flt_comp, next_suffix = _create_comp(graph, comp_spec, all_comps, next_suffix)
        flt_comp = typing.cast(bt2._GenericFilterComponentConst, flt_comp)
        out_port = list(flt_comp.output_ports.values())[0]
        in_port = list(flt_comp.input_ports.values())[0]
        _connect_ports(graph, last_out_port, last_out_comp, in_port, flt_comp)
        last_out_port = out_port
        last_out_comp = flt_comp

    # Create source components
    src_comps = []  # type: List[_AnyCompT]

    for comp_spec in all_src_component_specs:
        src_comp, next_suffix = _create_comp(graph, comp_spec, all_comps, next_suffix)
        src_comps.append(src_comp)

    # Connect source output ports to muxer input ports
    for src_comp in src_comps:
        src_comp = typing.cast(bt2._GenericSourceComponentConst, src_comp)

        for out_port in src_comp.output_ports.values():
            muxer_in_port = _get_free_muxer_input_port(muxer_comp)
            assert muxer_in_port is not None
            _connect_ports(graph, out_port, src_comp, muxer_in_port, muxer_comp)

    # Create sink component and connect it
    sink_comp, next_suffix = _create_comp(
        graph, sink_component_spec, all_comps, next_suffix
    )
    sink_comp = typing.cast(bt2._GenericSinkComponentConst, sink_comp)
    sink_in_port = list(sink_comp.input_ports.values())[0]
    _connect_ports(graph, last_out_port, last_out_comp, sink_in_port, sink_comp)

    # Run graph to completion, retrying on `bt2.TryAgain` (like the
    # CLI does).
    _logger.info("  Running graph")

    while True:
        try:
            graph.run()
            break
        except bt2.TryAgain:
            _logger.debug("  Got `bt2.TryAgain`: sleeping 0.1 s")
            time.sleep(0.1)

    _logger.info("  Graph completed")


# Runs a graph with `sink.text.details` using convert() and compares
# the output to the expectation `expect` (a string or the path of an
# expectation file to open).
#
# `src_component_specs` and `flt_component_specs` are like
# their convert() equivalent.
#
# `expect` is the expected output, either:
#
# • A `pathlib.Path` object (expectation file path).
# • A string (dedented before comparison).
#
# `details_params` is an optional dictionary of initialization
# parameters to pass to the `sink.text.details` component.
#
# `mip_version` is like its convert() equivalent.
#
# This function asserts that the output matches the expectation
# (both stripped of leading/trailing whitespace).
def convert_sink_text_details_test(
    src_component_specs: Union[
        str,
        pathlib.Path,
        "bt2.AutoSourceComponentSpec",
        "bt2.ComponentSpec",
        Iterable[
            Union[str, pathlib.Path, "bt2.AutoSourceComponentSpec", "bt2.ComponentSpec"]
        ],
    ],
    expect: Union[pathlib.Path, str],
    flt_component_specs: Optional[
        Union["bt2.ComponentSpec", Iterable["bt2.ComponentSpec"]]
    ] = None,
    details_params: Optional[Dict[str, Any]] = None,
    mip_version: Optional[int] = None,
) -> None:
    import bt2

    if details_params is None:
        details_params = {}

    # Find the `text` plugin and get `details` sink component class
    plugin = bt2.find_plugin("text")

    if plugin is None:
        raise RuntimeError("cannot find `text` plugin")

    if "details" not in plugin.sink_component_classes:
        raise RuntimeError("cannot find `sink.text.details` within the `text` plugin")

    with tempfile.TemporaryDirectory(prefix="bt-test-sink.text.details-") as temp_dir:
        # Output file path
        temp_path = pathlib.Path(temp_dir) / "output.txt"

        # Add the path to the details params
        full_params = dict(details_params)
        full_params["path"] = str(temp_path)

        # Create sink component spec
        sink_spec = SinkComponentSpec(
            plugin.sink_component_classes["details"], full_params
        )

        # Run the conversion
        convert(
            src_component_specs,
            sink_spec,
            flt_component_specs,
            mip_version=mip_version,
        )

        # Read the output
        output = temp_path.read_text().strip()

        # Get expected output
        if isinstance(expect, pathlib.Path):
            expected = expect.read_text().strip()
        else:
            expected = textwrap.dedent(expect).strip()

        # Compare
        assert output == expected


# Returns the build directory equivalent to the source directory
# containing `source_file`.
#
# `build_root_dir` is the root build directory (the build directory
# containing the `tests` directory).
#
# Typical usage examples:
#
#     build_dir_of_source_file(config.build_root_dir, __file__)
#
# For example, if `source_file` is
# `/path/to/babeltrace/tests/meow/mix/test_lel.py`, then this function
# returns `/path/to/build/tests/meow/mix`.
def build_dir_of_source_file(
    build_root_dir: pathlib.Path, source_file: Union[pathlib.Path, str]
) -> pathlib.Path:
    source_file = pathlib.Path(source_file).resolve()

    # Find root source dir. by walking up until we find `pyproject.toml`
    src_root_dir = source_file.parent

    while not (src_root_dir / "pyproject.toml").exists():
        assert src_root_dir.parent != src_root_dir
        src_root_dir = src_root_dir.parent

    # Equivalent path in the build directory
    return build_root_dir / source_file.parent.relative_to(src_root_dir)


# Builds a `bt2.TraceCollectionMessageIterator` with `args` and
# `kwargs`, collects all the event messages until the end, and returns
# the list.
def tcmi_events(*args: Any, **kwargs: Any) -> List[Any]:
    import bt2

    msgs = typing.cast(
        Iterable[bt2._MessageConst],
        bt2.TraceCollectionMessageIterator(*args, **kwargs),
    )

    return [m.event for m in msgs if isinstance(m, bt2._EventMessageConst)]
