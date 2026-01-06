# SPDX-FileCopyrightText: 2019 Simon Marchi <simon.marchi@efficios.com>
# SPDX-FileCopyrightText: 2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import pytest
import bt_tests_cli_utils as btu_cli


@pytest.fixture
def plugin_dir(data_dir):
    return data_dir / "auto-source-discovery" / "params-log-level"


def _run_params_test(build_root_dir, plugin_dir, cli_args, expected):
    btu_cli.run_cli_sink_text_details_test(
        build_root_dir,
        ["convert"] + cli_args,
        {"with-metadata": False},
        expected,
        plugin_paths=[plugin_dir],
    )


# Apply parameters to two components from one non-option argument.
def test_apply_params_to_two_components_from_one_non_option_argument(
    plugin_dir, build_root_dir
):
    _run_params_test(
        build_root_dir,
        plugin_dir,
        [
            str(plugin_dir / "dir-ab"),
            btu_cli.CliParams({"what": "test-params", "test-allo": "madame"}),
        ],
        """
        {Trace 0, Stream class ID 0, Stream ID 0}
        Stream beginning:
          Name: TestSourceA: ('test-allo', 'madame')
          Trace:
            Stream (ID 0, Class ID 0)

        {Trace 1, Stream class ID 0, Stream ID 0}
        Stream beginning:
          Name: TestSourceB: ('test-allo', 'madame')
          Trace:
            Stream (ID 0, Class ID 0)

        {Trace 0, Stream class ID 0, Stream ID 0}
        Stream end

        {Trace 1, Stream class ID 0, Stream ID 0}
        Stream end
        """,
    )


# Apply parameters to two components from two distinct
# non-option arguments.
def test_apply_params_to_two_non_option_arguments(plugin_dir, build_root_dir):
    _run_params_test(
        build_root_dir,
        plugin_dir,
        [
            str(plugin_dir / "dir-a"),
            btu_cli.CliParams({"test-allo": "madame"}),
            btu_cli.CliParams({"what": "test-params"}),
            str(plugin_dir / "dir-b"),
            btu_cli.CliParams({"test-bonjour": "monsieur"}),
            btu_cli.CliParams({"what": "test-params"}),
        ],
        """
        {Trace 0, Stream class ID 0, Stream ID 0}
        Stream beginning:
          Name: TestSourceA: ('test-allo', 'madame')
          Trace:
            Stream (ID 0, Class ID 0)

        {Trace 1, Stream class ID 0, Stream ID 0}
        Stream beginning:
          Name: TestSourceB: ('test-bonjour', 'monsieur')
          Trace:
            Stream (ID 0, Class ID 0)

        {Trace 0, Stream class ID 0, Stream ID 0}
        Stream end

        {Trace 1, Stream class ID 0, Stream ID 0}
        Stream end
        """,
    )


# Apply parameters to one component coming from one non-option argument
# and one component coming from two non-option arguments (1).
def test_apply_params_to_one_component_from_one_and_two_non_option_arguments_1(
    plugin_dir, build_root_dir
):
    _run_params_test(
        build_root_dir,
        plugin_dir,
        [
            str(plugin_dir / "dir-a"),
            btu_cli.CliParams({"what": "test-params", "test-allo": "madame"}),
            str(plugin_dir / "dir-ab"),
            btu_cli.CliParams({"what": "test-params", "test-bonjour": "monsieur"}),
        ],
        """
        {Trace 0, Stream class ID 0, Stream ID 0}
        Stream beginning:
          Name: TestSourceA: ('test-allo', 'madame'), ('test-bonjour', 'monsieur')
          Trace:
            Stream (ID 0, Class ID 0)

        {Trace 1, Stream class ID 0, Stream ID 0}
        Stream beginning:
          Name: TestSourceB: ('test-bonjour', 'monsieur')
          Trace:
            Stream (ID 0, Class ID 0)

        {Trace 0, Stream class ID 0, Stream ID 0}
        Stream end

        {Trace 1, Stream class ID 0, Stream ID 0}
        Stream end
        """,
    )


# Apply parameters to one component coming from one non-option argument
# and one component coming from two non-option arguments (2).
def test_apply_params_to_one_component_from_one_and_two_non_option_arguments_2(
    plugin_dir, build_root_dir
):
    _run_params_test(
        build_root_dir,
        plugin_dir,
        [
            str(plugin_dir / "dir-ab"),
            btu_cli.CliParams(
                {
                    "what": "test-params",
                    "test-bonjour": "madame",
                    "test-salut": "les amis",
                }
            ),
            str(plugin_dir / "dir-a"),
            btu_cli.CliParams({"what": "test-params", "test-bonjour": "monsieur"}),
        ],
        """
        {Trace 0, Stream class ID 0, Stream ID 0}
        Stream beginning:
          Name: TestSourceA: ('test-bonjour', 'monsieur'), ('test-salut', 'les amis')
          Trace:
            Stream (ID 0, Class ID 0)

        {Trace 1, Stream class ID 0, Stream ID 0}
        Stream beginning:
          Name: TestSourceB: ('test-bonjour', 'madame'), ('test-salut', 'les amis')
          Trace:
            Stream (ID 0, Class ID 0)

        {Trace 0, Stream class ID 0, Stream ID 0}
        Stream end

        {Trace 1, Stream class ID 0, Stream ID 0}
        Stream end
        """,
    )
