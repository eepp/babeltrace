# SPDX-FileCopyrightText: 2019 Simon Marchi <simon.marchi@efficios.com>
# SPDX-FileCopyrightText: 2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import pytest
import bt_tests_cli_utils as btu_cli


@pytest.fixture
def plugin_dir(data_dir):
    return data_dir / "auto-source-discovery" / "params-log-level"


def _run_log_level_test(build_root_dir, plugin_dir, cli_args, expected):
    btu_cli.run_cli_sink_text_details_test(
        build_root_dir,
        ["convert"] + cli_args,
        {"with-metadata": False},
        expected,
        plugin_paths=[plugin_dir],
    )


# Apply log level to two components from one non-option argument.
def test_apply_log_level_to_two_components_from_one_non_option_argument(
    plugin_dir, build_root_dir
):
    _run_log_level_test(
        build_root_dir,
        plugin_dir,
        [
            str(plugin_dir / "dir-ab"),
            "--log-level=DEBUG",
            btu_cli.CliParams({"what": "log-level"}),
        ],
        """
        {Trace 0, Stream class ID 0, Stream ID 0}
        Stream beginning:
          Name: TestSourceA: LoggingLevel.DEBUG
          Trace:
            Stream (ID 0, Class ID 0)

        {Trace 1, Stream class ID 0, Stream ID 0}
        Stream beginning:
          Name: TestSourceB: LoggingLevel.DEBUG
          Trace:
            Stream (ID 0, Class ID 0)

        {Trace 0, Stream class ID 0, Stream ID 0}
        Stream end

        {Trace 1, Stream class ID 0, Stream ID 0}
        Stream end
        """,
    )


# Apply log level to two components from two distinct non-option arguments.
def test_apply_log_level_to_two_non_option_arguments(plugin_dir, build_root_dir):
    _run_log_level_test(
        build_root_dir,
        plugin_dir,
        [
            str(plugin_dir / "dir-a"),
            "--log-level=DEBUG",
            btu_cli.CliParams({"what": "log-level"}),
            str(plugin_dir / "dir-b"),
            "--log-level=TRACE",
            btu_cli.CliParams({"what": "log-level"}),
        ],
        """
        {Trace 0, Stream class ID 0, Stream ID 0}
        Stream beginning:
          Name: TestSourceA: LoggingLevel.DEBUG
          Trace:
            Stream (ID 0, Class ID 0)

        {Trace 1, Stream class ID 0, Stream ID 0}
        Stream beginning:
          Name: TestSourceB: LoggingLevel.TRACE
          Trace:
            Stream (ID 0, Class ID 0)

        {Trace 0, Stream class ID 0, Stream ID 0}
        Stream end

        {Trace 1, Stream class ID 0, Stream ID 0}
        Stream end
        """,
    )


# Apply log level to one component coming from one non-option argument and one
# component coming from two non-option arguments (1).
def test_apply_log_level_to_one_component_from_one_and_two_non_option_arguments_1(
    plugin_dir, build_root_dir
):
    _run_log_level_test(
        build_root_dir,
        plugin_dir,
        [
            str(plugin_dir / "dir-a"),
            "--log-level=DEBUG",
            btu_cli.CliParams({"what": "log-level"}),
            str(plugin_dir / "dir-ab"),
            "--log-level=TRACE",
            btu_cli.CliParams({"what": "log-level"}),
        ],
        """
        {Trace 0, Stream class ID 0, Stream ID 0}
        Stream beginning:
          Name: TestSourceA: LoggingLevel.TRACE
          Trace:
            Stream (ID 0, Class ID 0)

        {Trace 1, Stream class ID 0, Stream ID 0}
        Stream beginning:
          Name: TestSourceB: LoggingLevel.TRACE
          Trace:
            Stream (ID 0, Class ID 0)

        {Trace 0, Stream class ID 0, Stream ID 0}
        Stream end

        {Trace 1, Stream class ID 0, Stream ID 0}
        Stream end
        """,
    )


# Apply log level to one component coming from one non-option argument and one
# component coming from two non-option arguments (2).
def test_apply_log_level_to_one_component_from_one_and_two_non_option_arguments_2(
    plugin_dir, build_root_dir
):
    _run_log_level_test(
        build_root_dir,
        plugin_dir,
        [
            str(plugin_dir / "dir-ab"),
            "--log-level=DEBUG",
            btu_cli.CliParams({"what": "log-level"}),
            str(plugin_dir / "dir-a"),
            "--log-level=TRACE",
            btu_cli.CliParams({"what": "log-level"}),
        ],
        """
        {Trace 0, Stream class ID 0, Stream ID 0}
        Stream beginning:
          Name: TestSourceA: LoggingLevel.TRACE
          Trace:
            Stream (ID 0, Class ID 0)

        {Trace 1, Stream class ID 0, Stream ID 0}
        Stream beginning:
          Name: TestSourceB: LoggingLevel.DEBUG
          Trace:
            Stream (ID 0, Class ID 0)

        {Trace 0, Stream class ID 0, Stream ID 0}
        Stream end

        {Trace 1, Stream class ID 0, Stream ID 0}
        Stream end
        """,
    )
