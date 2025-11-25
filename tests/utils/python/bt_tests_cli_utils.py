# SPDX-FileCopyrightText: 2025 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: MIT

# pyright: strict, reportTypeCommentUsage=false, reportMissingTypeStubs=false

import typing
import logging
import pathlib
import subprocess
from typing import Any, Dict, List, Union, Optional

import bt_tests_utils as btu

_logger = logging.getLogger(__name__)


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


# `babeltrace2-for-tests` CLI parameters to be passed to `run_cli()`.
class CliParams:
    def __init__(self, params: Dict[str, Any]):
        assert len(params) > 0
        self._params = params

    @property
    def params(self):
        return self._params


# Runs the `babeltrace2-for-tests` CLI compiled within `build_root_dir`
# (the build directory containing the `tests` directory) with the
# arguments `args` considering the plugin paths `plugin_paths`.
#
# Each item of `args` may be a string or a `CliParams` instance. A
# `CliParams` instance is converted to `--params` followed by the
# equivalent parameters value string.
#
# `check`, `text`, `timeout`, and `extra_env` are passed to btu.run().
def run_cli(
    build_root_dir: pathlib.Path,
    args: List[Union[str, CliParams]],
    plugin_paths: Optional[List[Any]] = None,
    check: bool = False,
    text: bool = True,
    timeout: Optional[float] = None,
    extra_env: Optional[Dict[str, str]] = None,
) -> "subprocess.CompletedProcess[str]":
    cli_args = []  # type: List[str]

    if plugin_paths is not None:
        cli_args += [
            "--plugin-path",
            (";" if btu.os_type() == btu.OsType.MINGW else ":").join(
                str(p) for p in plugin_paths
            ),
        ]

    for arg in args:
        if isinstance(arg, CliParams):
            cli_args += ["-p", cli_params_from_obj(arg.params)]
        else:
            cli_args.append(arg)

    return btu.run(
        build_root_dir,
        build_root_dir / "src/cli/babeltrace2-for-tests",
        cli_args,
        check=check,
        text=text,
        timeout=timeout,
        extra_env=extra_env,
    )
