# SPDX-FileCopyrightText: 2019 Simon Marchi <simon.marchi@efficios.com>
# SPDX-FileCopyrightText: 2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import bt_tests_cli_utils as btu_cli


# Tests the automatic source component discovery mechanism of the CLI.
def test_grouping(data_dir, build_root_dir):
    plugin_data_dir = data_dir / "auto-source-discovery" / "grouping"

    result = btu_cli.run_cli_sink_text_details_test(
        build_root_dir,
        [
            "convert",
            "ABCDE",
            str(plugin_data_dir / "traces"),
            "some_other_non_opt",
        ],
        {"with-metadata": False},
        data_dir / "cli" / "convert" / "auto-source-discovery-grouping.expect",
        plugin_paths=[plugin_data_dir],
    )

    # Check that the expected warning is printed
    assert "No trace was found based on input `some_other_non_opt`" in result.stderr
