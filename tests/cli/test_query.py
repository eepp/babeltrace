# SPDX-FileCopyrightText: 2019 Simon Marchi <simon.marchi@efficios.com>
# SPDX-FileCopyrightText: 2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import pytest
import bt_tests_cli_utils as btu_cli


@pytest.fixture
def plugin_dir(data_dir):
    return data_dir / "cli" / "query"


@pytest.mark.parametrize(
    ["object_name", "params", "expected_output"],
    [
        pytest.param("the-object", [], "the-object:{}", id="no-params"),
        pytest.param(
            "the-object",
            [btu_cli.CliParams({"a": 2})],
            "the-object:{a=2}",
            id="single-param",
        ),
        # Check that `-p` parameters are processed in order
        pytest.param(
            "the-object",
            [
                btu_cli.CliParams({"a": 2, "ben": "kin"}),
                btu_cli.CliParams({"voyons": "donc", "a": 3}),
            ],
            "the-object:{a=3, ben=kin, voyons=donc}",
            id="multiple-params-processed-in-order",
        ),
    ],
)
def test_query_success(
    plugin_dir, build_root_dir, object_name, params, expected_output
):
    result = btu_cli.run_cli(
        build_root_dir,
        ["query", "src.query.SourceWithQueryThatPrintsParams", object_name] + params,
        plugin_paths=[plugin_dir],
        check=True,
    )

    assert result.stdout.strip() == expected_output


@pytest.mark.parametrize(
    ["component_class", "object_name", "params", "expected_stderr"],
    [
        # Failure inside the query method
        pytest.param(
            "src.query.SourceWithQueryThatPrintsParams",
            "please-fail",
            [btu_cli.CliParams({"a": 2})],
            "ValueError: catastrophic failure",
            id="query-method-failure",
        ),
        # Nonexistent component class
        pytest.param(
            "src.query.NonExistentSource",
            "the-object",
            [btu_cli.CliParams({"a": 2})],
            'Cannot find component class: plugin-name="query", comp-cls-name="NonExistentSource", comp-cls-type=SOURCE',
            id="non-existent-component-class",
        ),
        # Wrong parameter syntax
        pytest.param(
            "src.query.SourceWithQueryThatPrintsParams",
            "please-fail",
            ["-p", "a=3,"],
            "Invalid format for --params option's argument:",
            id="wrong-parameter-syntax",
        ),
    ],
)
def test_query_failure(
    plugin_dir, build_root_dir, component_class, object_name, params, expected_stderr
):
    result = btu_cli.run_cli(
        build_root_dir,
        ["query", component_class, object_name] + params,
        plugin_paths=[plugin_dir],
    )

    # Expect non-zero exit code
    assert result.returncode != 0

    # Expect nothing on stdout
    assert result.stdout == ""

    # Expect CLI error stack on standard error
    assert "ERROR: " in result.stderr

    # Expect specific error message on standard error
    assert expected_stderr in result.stderr
