# SPDX-FileCopyrightText: 2019-2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import re
import textwrap

import pytest
import bt_tests_cli_utils as btu_cli


@pytest.fixture(scope="module")
def plugin_dir(data_dir):
    return data_dir / "cli/list-plugins"


@pytest.fixture(scope="module")
def cli_run(build_root_dir, plugin_dir):
    result = btu_cli.run_cli(
        build_root_dir,
        ["list-plugins"],
        plugin_paths=[plugin_dir],
        check=True,
    )
    return result


# Extract the section for a specific plugin from the `list-plugins`
# command output.
#
# Returns the plugin header line plus `num_lines_after` lines.
def _extract_plugin_section(stdout, plugin_name, num_lines_after=11):
    lines = stdout.split("\n")

    for i, line in enumerate(lines):
        if re.match(r"^{}:$".format(re.escape(plugin_name)), line):
            # Return the plugin header line plus the following lines
            end_idx = min(i + num_lines_after + 1, len(lines))
            return "\n".join(lines[i:end_idx])


def test_plugin_entry_present(cli_run):
    assert (
        _extract_plugin_section(cli_run.stdout, "this-is-a-plugin") is not None
    ), "Entry for `this-is-a-plugin` not found in output"


def test_plugin_entry_content(cli_run, plugin_dir):
    section = _extract_plugin_section(cli_run.stdout, "this-is-a-plugin")
    assert section is not None, "Entry for `this-is-a-plugin` not found in output"

    expected = textwrap.dedent(
        """
        this-is-a-plugin:
          Path: {plugin_dir}/bt_plugin_list_plugins.py
          Version: 1.2.3bob
          Description: A plugin
          Author: Jorge Mario Bergoglio
          License: The license
          Source component classes:
            'source.this-is-a-plugin.ThisIsASource'
          Filter component classes:
            'filter.this-is-a-plugin.ThisIsAFilter'
          Sink component classes:
            'sink.this-is-a-plugin.ThisIsASink'
        """.format(
            plugin_dir=plugin_dir
        )
    ).strip()

    assert section == expected
