# SPDX-FileCopyrightText: 2019 Simon Marchi <simon.marchi@efficios.com>
# SPDX-FileCopyrightText: 2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import bt_tests_utils as btu
import bt_tests_cli_utils as btu_cli


# Tests the automatic source component discovery mechanism of the CLI.
def test_grouping(build_root_dir, common_data_dir):
    plugin_dir = common_data_dir / "auto-src-comp-discovery/grouping"

    result = btu_cli.run_cli_sink_text_details_test(
        build_root_dir,
        [
            "convert",
            "ABCDE",
            str(plugin_dir / "traces"),
            "some_other_non_opt",
        ],
        {"with-metadata": False},
        btu.this_src_dir(__file__) / "convert-auto-src-comp-discovery-grouping.expect",
        plugin_paths=[plugin_dir],
    )

    # Check that the expected warning is printed
    assert "No trace was found based on input `some_other_non_opt`" in result.stderr
