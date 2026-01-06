# SPDX-FileCopyrightText: 2017 Philippe Proulx <pproulx@efficios.com>
# SPDX-FileCopyrightText: 2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import shlex

import pytest
import bt_tests_cli_utils as btu_cli


@pytest.fixture
def path_to_trace(ctf_traces_dir):
    return str(ctf_traces_dir / "1/succeed/succeed1")


@pytest.fixture
def path_to_trace_2(ctf_traces_dir):
    return str(ctf_traces_dir / "1/succeed/succeed2")


@pytest.mark.parametrize(
    ["convert_args_templ", "expected_run_args_templ"],
    [
        pytest.param(
            "{path_to_trace}",
            "--component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --component muxer:filter.utils.muxer --connect auto-disc-source-ctf-fs:muxer --connect muxer:pretty",
            id="path-non-option-arg",
        ),
        pytest.param(
            "{path_to_trace} {path_to_trace_2}",
            '--component auto-disc-source-ctf-fs:source.ctf.fs --params \'inputs=["{path_to_trace}", "{path_to_trace_2}"]\' --component pretty:sink.text.pretty --component muxer:filter.utils.muxer --connect auto-disc-source-ctf-fs:muxer --connect muxer:pretty',
            id="path-non-option-args",
        ),
        pytest.param(
            "{path_to_trace} --component ZZ:source.another.source --params salut=yes",
            "--component ZZ:source.another.source --params salut=yes --component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --component muxer:filter.utils.muxer --connect ZZ:muxer --connect auto-disc-source-ctf-fs:muxer --connect muxer:pretty",
            id="path-non-option-arg-and-named-user-source-with-params",
        ),
        pytest.param(
            "--component source.salut.com",
            "--component source.salut.com:source.salut.com --component pretty:sink.text.pretty --component muxer:filter.utils.muxer --connect 'source\\.salut\\.com:muxer' --connect muxer:pretty",
            id="unnamed-user-source",
        ),
        pytest.param(
            "--component auto-disc-source-ctf-fs:source.salut.com {path_to_trace}",
            "--component auto-disc-source-ctf-fs:source.salut.com --component auto-disc-source-ctf-fs-0:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --component muxer:filter.utils.muxer --connect auto-disc-source-ctf-fs:muxer --connect auto-disc-source-ctf-fs-0:muxer --connect muxer:pretty",
            id="path-non-option-arg-and-user-source-named-auto-disc-source-ctf-fs",
        ),
        pytest.param(
            "--component pretty:sink.my.sink {path_to_trace}",
            "--component pretty:sink.my.sink --component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component muxer:filter.utils.muxer --connect auto-disc-source-ctf-fs:muxer --connect muxer:pretty",
            id="path-non-option-arg-and-user-sink-named-pretty",
        ),
        pytest.param(
            "--component muxer:filter.salut.com {path_to_trace}",
            "--component muxer:filter.salut.com --component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --component muxer-0:filter.utils.muxer --connect auto-disc-source-ctf-fs:muxer-0 --connect muxer-0:muxer --connect muxer:pretty",
            id="path-non-option-arg-and-user-filter-named-muxer",
        ),
        pytest.param(
            "{path_to_trace} --component trimmer:filter.salut.com --begin=abc",
            "--component trimmer:filter.salut.com --component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --component muxer:filter.utils.muxer --component trimmer-0:filter.utils.trimmer --params 'begin=\"abc\"' --connect auto-disc-source-ctf-fs:muxer --connect muxer:trimmer-0 --connect trimmer-0:trimmer --connect trimmer:pretty",
            id="path-non-option-arg-and-begin-and-user-filter-named-trimmer",
        ),
        pytest.param(
            "{path_to_trace} --begin=123",
            "--component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --component muxer:filter.utils.muxer --component trimmer:filter.utils.trimmer --params 'begin=\"123\"' --connect auto-disc-source-ctf-fs:muxer --connect muxer:trimmer --connect trimmer:pretty",
            id="path-non-option-arg-and-begin",
        ),
        pytest.param(
            "{path_to_trace} --end=456 --begin 123",
            "--component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --component muxer:filter.utils.muxer --component trimmer:filter.utils.trimmer --params 'end=\"456\"' --params 'begin=\"123\"' --connect auto-disc-source-ctf-fs:muxer --connect muxer:trimmer --connect trimmer:pretty",
            id="path-non-option-arg-and-begin-end",
        ),
        pytest.param(
            "{path_to_trace} --timerange=[abc,xyz]",
            "--component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --component muxer:filter.utils.muxer --component trimmer:filter.utils.trimmer --params 'begin=\"abc\"' --params 'end=\"xyz\"' --connect auto-disc-source-ctf-fs:muxer --connect muxer:trimmer --connect trimmer:pretty",
            id="path-non-option-arg-and-timerange",
        ),
        pytest.param(
            "{path_to_trace} --clock-cycles",
            "--component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --params clock-cycles=yes --component muxer:filter.utils.muxer --connect auto-disc-source-ctf-fs:muxer --connect muxer:pretty",
            id="path-non-option-arg-and-clock-cycles",
        ),
        pytest.param(
            "{path_to_trace} --clock-date",
            "--component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --params clock-date=yes --component muxer:filter.utils.muxer --connect auto-disc-source-ctf-fs:muxer --connect muxer:pretty",
            id="path-non-option-arg-and-clock-date",
        ),
        pytest.param(
            "{path_to_trace} --clock-force-correlate",
            "--component auto-disc-source-ctf-fs:source.ctf.fs --params force-clock-class-origin-unix-epoch=yes --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --component muxer:filter.utils.muxer --connect auto-disc-source-ctf-fs:muxer --connect muxer:pretty",
            id="path-non-option-arg-and-clock-force-correlate",
        ),
        pytest.param(
            "{path_to_trace} --clock-gmt",
            "--component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --params clock-gmt=yes --component muxer:filter.utils.muxer --connect auto-disc-source-ctf-fs:muxer --connect muxer:pretty",
            id="path-non-option-arg-and-clock-gmt",
        ),
        pytest.param(
            "{path_to_trace} --clock-offset=15487",
            "--component auto-disc-source-ctf-fs:source.ctf.fs --params clock-class-offset-s=15487 --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --component muxer:filter.utils.muxer --connect auto-disc-source-ctf-fs:muxer --connect muxer:pretty",
            id="path-non-option-arg-and-clock-offset",
        ),
        pytest.param(
            "{path_to_trace} --clock-offset-ns=326159487",
            "--component auto-disc-source-ctf-fs:source.ctf.fs --params clock-class-offset-ns=326159487 --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --component muxer:filter.utils.muxer --connect auto-disc-source-ctf-fs:muxer --connect muxer:pretty",
            id="path-non-option-arg-and-clock-offset-ns",
        ),
        pytest.param(
            "{path_to_trace} --clock-seconds",
            "--component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --params clock-seconds=yes --component muxer:filter.utils.muxer --connect auto-disc-source-ctf-fs:muxer --connect muxer:pretty",
            id="path-non-option-arg-and-clock-seconds",
        ),
        pytest.param(
            "{path_to_trace} --color=never",
            "--component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --params 'color=\"never\"' --component muxer:filter.utils.muxer --connect auto-disc-source-ctf-fs:muxer --connect muxer:pretty",
            id="path-non-option-arg-and-color",
        ),
        pytest.param(
            "{path_to_trace} --debug-info",
            "--component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --component muxer:filter.utils.muxer --component debug-info:filter.lttng-utils.debug-info --connect auto-disc-source-ctf-fs:muxer --connect muxer:debug-info --connect debug-info:pretty",
            id="path-non-option-arg-and-debug-info",
        ),
        pytest.param(
            "{path_to_trace} --debug-info-dir=/output/path",
            "--component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --component muxer:filter.utils.muxer --component debug-info:filter.lttng-utils.debug-info --params 'debug-info-dir=\"/output/path\"' --connect auto-disc-source-ctf-fs:muxer --connect muxer:debug-info --connect debug-info:pretty",
            id="path-non-option-arg-and-debug-info-dir",
        ),
        pytest.param(
            "{path_to_trace} --debug-info-target-prefix=/output/path",
            "--component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --component muxer:filter.utils.muxer --component debug-info:filter.lttng-utils.debug-info --params 'target-prefix=\"/output/path\"' --connect auto-disc-source-ctf-fs:muxer --connect muxer:debug-info --connect debug-info:pretty",
            id="path-non-option-arg-and-debug-info-target-prefix",
        ),
        pytest.param(
            "{path_to_trace} --debug-info-full-path",
            "--component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --component muxer:filter.utils.muxer --component debug-info:filter.lttng-utils.debug-info --params full-path=yes --connect auto-disc-source-ctf-fs:muxer --connect muxer:debug-info --connect debug-info:pretty",
            id="path-non-option-arg-and-debug-info-full-path",
        ),
        pytest.param(
            "--fields=trace:domain,loglevel {path_to_trace}",
            "--component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --params field-trace:domain=yes,field-loglevel=yes,field-default=hide --component muxer:filter.utils.muxer --connect auto-disc-source-ctf-fs:muxer --connect muxer:pretty",
            id="path-non-option-arg-and-fields-trace-domain-loglevel",
        ),
        pytest.param(
            "--fields=all {path_to_trace}",
            "--component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --params field-default=show --component muxer:filter.utils.muxer --connect auto-disc-source-ctf-fs:muxer --connect muxer:pretty",
            id="path-non-option-arg-and-fields-all",
        ),
        pytest.param(
            "--names=context,header {path_to_trace}",
            "--component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --params name-context=yes,name-header=yes,name-default=hide --component muxer:filter.utils.muxer --connect auto-disc-source-ctf-fs:muxer --connect muxer:pretty",
            id="path-non-option-arg-and-names-context-header",
        ),
        pytest.param(
            "--names=all {path_to_trace}",
            "--component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --params name-default=show --component muxer:filter.utils.muxer --connect auto-disc-source-ctf-fs:muxer --connect muxer:pretty",
            id="path-non-option-arg-and-names-all",
        ),
        pytest.param(
            "{path_to_trace} --no-delta",
            "--component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --params no-delta=yes --component muxer:filter.utils.muxer --connect auto-disc-source-ctf-fs:muxer --connect muxer:pretty",
            id="path-non-option-arg-and-no-delta",
        ),
        pytest.param(
            "{path_to_trace} --output /output/path",
            "--component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --params 'path=\"/output/path\"' --component muxer:filter.utils.muxer --connect auto-disc-source-ctf-fs:muxer --connect muxer:pretty",
            id="path-non-option-arg-and-output",
        ),
        pytest.param(
            "{path_to_trace} -i ctf",
            "--component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component pretty:sink.text.pretty --component muxer:filter.utils.muxer --connect auto-disc-source-ctf-fs:muxer --connect muxer:pretty",
            id="path-non-option-arg-and-i-ctf",
        ),
        pytest.param(
            "net://some-host/host/target/session -i lttng-live",
            "--component lttng-live:source.ctf.lttng-live --params 'inputs=[\"net://some-host/host/target/session\"]' --params 'session-not-found-action=\"end\"' --component pretty:sink.text.pretty --component muxer:filter.utils.muxer --connect lttng-live:muxer --connect muxer:pretty",
            id="url-non-option-arg-and-i-lttng-live",
        ),
        pytest.param(
            "{path_to_trace} -o dummy",
            "--component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component dummy:sink.utils.dummy --component muxer:filter.utils.muxer --connect auto-disc-source-ctf-fs:muxer --connect muxer:dummy",
            id="path-non-option-arg-and-o-dummy",
        ),
        pytest.param(
            "{path_to_trace} -o ctf --output /output/path",
            "--component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component sink-ctf-fs:sink.ctf.fs --params 'path=\"/output/path\"' --component muxer:filter.utils.muxer --connect auto-disc-source-ctf-fs:muxer --connect muxer:sink-ctf-fs",
            id="path-non-option-arg-and-o-ctf-and-output",
        ),
        pytest.param(
            "{path_to_trace} -c sink.mein.sink -lW",
            "--component sink.mein.sink:sink.mein.sink --log-level W --component auto-disc-source-ctf-fs:source.ctf.fs --params 'inputs=[\"{path_to_trace}\"]' --component muxer:filter.utils.muxer --connect auto-disc-source-ctf-fs:muxer --connect 'muxer:sink\\.mein\\.sink'",
            id="path-non-option-arg-and-user-sink-with-log-level",
        ),
    ],
)
def test_convert_run_args_success(
    build_root_dir,
    path_to_trace,
    path_to_trace_2,
    convert_args_templ,
    expected_run_args_templ,
):
    # Run the CLI with `convert --run-args`
    assert btu_cli.run_cli(
        build_root_dir,
        ["convert", "--run-args"]
        + shlex.split(
            convert_args_templ.format(
                path_to_trace=path_to_trace,
                path_to_trace_2=path_to_trace_2,
            )
        ),
        check=True,
    ).stdout.strip() == expected_run_args_templ.format(
        path_to_trace=path_to_trace,
        path_to_trace_2=path_to_trace_2,
    )


@pytest.mark.parametrize(
    ["convert_args_templ", "expected_error_str"],
    [
        pytest.param(
            "--component salut",
            "Invalid format for --component option's argument:",
            id="bad-component-format-plugin-only",
        ),
        pytest.param(
            "--component name:salut",
            "Missing component class type (`source`, `filter`, or `sink`).",
            id="bad-component-format-name-and-plugin-only",
        ),
        pytest.param(
            "--component name:",
            "Missing component class type (`source`, `filter`, or `sink`).",
            id="bad-component-format-name-only",
        ),
        pytest.param(
            "--component name:source.plugin.comp.cls",
            "Invalid format for --component option's argument:",
            id="bad-component-format-extra-dot-found",
        ),
        pytest.param(
            "--component hello:sink.a.b --component hello:source.c.d",
            "Duplicate component instance name:",
            id="duplicate-component-name",
        ),
        pytest.param(
            "--component hello:sink.a.b --salut",
            "Unknown option `--salut`",
            id="unknown-option",
        ),
        pytest.param(
            "--params lol=23",
            "No current component (--component option) or non-option argument of which to",
            id="params-without-current-component",
        ),
        pytest.param(
            "--begin abc --clock-seconds --begin cde",
            "At --begin option: --begin or --timerange option already specified",
            id="duplicate-begin",
        ),
        pytest.param(
            "--begin abc --end xyz --clock-seconds --end cde",
            "At --end option: --end or --timerange option already specified",
            id="duplicate-end",
        ),
        pytest.param(
            "--begin abc --clock-seconds --timerange abc,def",
            "At --timerange option: --begin, --end, or --timerange option already specified",
            id="begin-and-timerange",
        ),
        pytest.param(
            "--end abc --clock-seconds --timerange abc,def",
            "At --timerange option: --begin, --end, or --timerange option already specified",
            id="end-and-timerange",
        ),
        pytest.param(
            "--timerange abc",
            "Invalid --timerange option's argument: expecting BEGIN,END or [BEGIN,END]:",
            id="bad-timerange-format-1",
        ),
        pytest.param(
            "--timerange abc,",
            "Invalid --timerange option's argument: expecting BEGIN,END or [BEGIN,END]:",
            id="bad-timerange-format-2",
        ),
        pytest.param(
            "--timerange ,cde",
            "Invalid --timerange option's argument: expecting BEGIN,END or [BEGIN,END]:",
            id="bad-timerange-format-3",
        ),
        pytest.param(
            "--fields salut",
            "Unknown field: `salut`.",
            id="bad-fields-format",
        ),
        pytest.param(
            "--names salut",
            "Unknown name: `salut`.",
            id="bad-names-format",
        ),
        pytest.param(
            "-i lol",
            "Unknown legacy input format:",
            id="unknown-i",
        ),
        pytest.param(
            "-i lttng-live --clock-seconds --input-format=ctf",
            "Duplicate --input-format option.",
            id="duplicate-i",
        ),
        pytest.param(
            "-o lol",
            "Unknown legacy output format:",
            id="unknown-o",
        ),
        pytest.param(
            "-o dummy --clock-seconds --output-format=text",
            "Duplicate --output-format option.",
            id="duplicate-o",
        ),
        pytest.param(
            "{path_to_trace} --run-args --run-args-0",
            "Cannot specify --run-args and --run-args-0.",
            id="run-args-and-run-args-0",
        ),
        pytest.param(
            "-o ctf-metadata",
            "--output-format=ctf-metadata specified without a path.",
            id="o-ctf-metadata-without-path",
        ),
        pytest.param(
            "-i lttng-live net://some-host/host/target/session --clock-offset=23",
            "--clock-offset specified, but no source.ctf.fs component instantiated.",
            id="i-lttng-live-and-implicit-source-ctf-fs",
        ),
        pytest.param(
            "--clock-offset=23",
            "--clock-offset specified, but no source.ctf.fs component instantiated.",
            id="implicit-source-ctf-fs-without-path",
        ),
        pytest.param(
            "-i lttng-live",
            "Missing URL for implicit `source.ctf.lttng-live` component.",
            id="implicit-source-ctf-lttng-live-without-url",
        ),
        pytest.param(
            "-o text",
            "No source component.",
            id="no-source",
        ),
        pytest.param(
            "my-trace -o ctf",
            "--output-format=ctf specified without --output (trace output path).",
            id="o-ctf-without-output",
        ),
        pytest.param(
            "my-trace -o ctf --output /output/path --no-delta",
            "Ambiguous --output option: --output-format=ctf specified but another option",
            id="o-ctf-and-output-with-implicit-sink-text-pretty",
        ),
        pytest.param(
            "{path_to_trace} --stream-intersection",
            "Cannot specify --stream-intersection with --run-args or --run-args-0.",
            id="stream-intersection",
        ),
        pytest.param(
            "{path_to_trace} -o dummy --clock-seconds",
            "More than one sink component specified.",
            id="two-sinks-with-o-dummy-and-clock-seconds",
        ),
        pytest.param(
            "{path_to_trace} --component=sink.abc.def -o text",
            "More than one sink component specified.",
            id="path-non-option-arg-and-user-sink-and-o-text",
        ),
    ],
)
def test_convert_run_args_failure(
    build_root_dir,
    path_to_trace,
    path_to_trace_2,
    convert_args_templ,
    expected_error_str,
):
    # Run the CLI with `convert --run-args`
    result = btu_cli.run_cli(
        build_root_dir,
        ["convert", "--run-args"]
        + shlex.split(
            convert_args_templ.format(
                path_to_trace=path_to_trace,
                path_to_trace_2=path_to_trace_2,
            )
        ),
    )

    # Verify failure exit status
    assert result.returncode != 0

    # Verify the CLI doesn't print to standard output
    assert result.stdout == ""

    # Verify expected error message on standard error
    assert (
        expected_error_str in result.stderr
    ), "Expected error string `{}` not found in standard error:\n{}".format(
        expected_error_str, result.stderr
    )
