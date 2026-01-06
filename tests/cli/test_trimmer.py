# SPDX-FileCopyrightText: 2017 Julien Desfossez <jdesfossez@efficios.com>
# SPDX-FileCopyrightText: 2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import pytest
import bt_tests_cli_utils as btu_cli


# Counts the number of non-empty lines in `stdout`.
def _count_output_lines(stdout):
    if not stdout.strip():
        return 0

    return len(stdout.strip().split("\n"))


@pytest.mark.parametrize(
    ["expected_event_count", "cli_args"],
    [
        pytest.param(
            18,
            ["--clock-gmt", "--begin", "17:48:17.587029529"],
            id="begin-gmt-relative",
        ),
        pytest.param(
            9,
            ["--clock-gmt", "--end", "17:48:17.588680018"],
            id="end-gmt-relative",
        ),
        pytest.param(
            7,
            [
                "--clock-gmt",
                "--begin",
                "17:48:17.587029529",
                "--end",
                "17:48:17.588680018",
            ],
            id="begin-and-end-gmt-relative",
        ),
        pytest.param(
            0,
            ["--clock-gmt", "--begin", "18:48:17.587029529"],
            id="begin-out-of-range-gmt-relative",
        ),
        pytest.param(
            0,
            ["--clock-gmt", "--end", "16:48:17.588680018"],
            id="end-out-of-range-gmt-relative",
        ),
        pytest.param(
            18,
            ["--clock-gmt", "--begin", "2012-10-29 17:48:17.587029529"],
            id="begin-gmt-absolute",
        ),
        pytest.param(
            9,
            ["--clock-gmt", "--end", "2012-10-29 17:48:17.588680018"],
            id="end-gmt-absolute",
        ),
        pytest.param(
            7,
            [
                "--clock-gmt",
                "--begin",
                "2012-10-29 17:48:17.587029529",
                "--end",
                "2012-10-29 17:48:17.588680018",
            ],
            id="begin-and-end-gmt-absolute",
        ),
        pytest.param(
            0,
            ["--clock-gmt", "--begin", "2012-10-29 18:48:17.587029529"],
            id="begin-out-of-range-gmt-absolute",
        ),
        pytest.param(
            0,
            ["--clock-gmt", "--end", "2012-10-29 16:48:17.588680018"],
            id="end-out-of-range-gmt-absolute-1",
        ),
    ],
)
def test_trimmer_success_gmt(
    ctf_traces_dir, build_root_dir, expected_event_count, cli_args
):
    result = btu_cli.run_cli(
        build_root_dir,
        [str(ctf_traces_dir / "1/succeed/wk-heartbeat-u")] + cli_args,
        check=True,
    )
    assert _count_output_lines(result.stdout) == expected_event_count


@pytest.mark.parametrize(
    ["expected_event_count", "cli_args"],
    [
        pytest.param(
            18,
            ["--begin", "12:48:17.587029529"],
            id="begin-est-relative",
        ),
        pytest.param(
            9,
            ["--end", "12:48:17.588680018"],
            id="end-est-relative",
        ),
        pytest.param(
            7,
            ["--begin", "12:48:17.587029529", "--end", "12:48:17.588680018"],
            id="begin-and-end-est-relative",
        ),
        pytest.param(
            0,
            ["--begin", "13:48:17.587029529"],
            id="begin-out-of-range-est-relative",
        ),
        pytest.param(
            0,
            ["--end", "11:48:17.588680018"],
            id="end-out-of-range-est-relative",
        ),
        pytest.param(
            18,
            ["--begin", "2012-10-29 12:48:17.587029529"],
            id="begin-est-absolute",
        ),
        pytest.param(
            9,
            ["--end", "12:48:17.588680018"],
            id="end-est-absolute",
        ),
        pytest.param(
            7,
            [
                "--begin",
                "2012-10-29 12:48:17.587029529",
                "--end",
                "2012-10-29 12:48:17.588680018",
            ],
            id="begin-and-end-est-absolute",
        ),
        pytest.param(
            0,
            ["--begin", "2012-10-29 13:48:17.587029529"],
            id="begin-out-of-range-est-absolute",
        ),
        pytest.param(
            0,
            ["--end", "2012-10-29 11:48:17.588680018"],
            id="end-out-of-range-est-absolute",
        ),
        # Various format tests (using EST timezone). We sometimes apply a
        # clock offset to make the events of the trace span two different
        # seconds or minutes.
        pytest.param(
            13,
            ["--begin=2012-10-29 12:48:17.588"],
            id="date-time-format-partial-nanosecond-precision",
        ),
        pytest.param(
            11,
            ["--clock-offset-ns=411282268", "--begin=2012-10-29 12:48:18"],
            id="date-time-format-second-precision",
        ),
        pytest.param(
            11,
            [
                "--clock-offset=42",
                "--clock-offset-ns=411282268",
                "--begin=2012-10-29 12:49",
            ],
            id="date-time-format-minute-precision",
        ),
        pytest.param(
            11,
            ["--begin=1351532897.588717732"],
            id="seconds-from-origin-format-nanosecond-precision",
        ),
        pytest.param(
            11,
            ["--begin=1351532897.58871773"],
            id="seconds-from-origin-format-partial-nanosecond-precision",
        ),
        pytest.param(
            11,
            ["--clock-offset-ns=411282268", "--begin=1351532898"],
            id="seconds-from-origin-format-second-precision",
        ),
    ],
)
def test_trimmer_success_est(
    ctf_traces_dir, build_root_dir, expected_event_count, cli_args
):
    # EST relative timestamp tests.
    #
    # NOTE: The POSIX notation is a bit weird. The libc documentation
    # sheds some light on this:
    #
    # > The offset specifies the time value you must add to the local
    # > time to get a Coordinated Universal Time value. It has syntax
    # > like `[+|-]hh[:mm[:ss]]`. This is positive if the local time
    # > zone is west of the Prime Meridian and negative if it is east.
    # > The hour must be between 0 and 24, and the minute and seconds
    # > between 0 and 59.
    #
    # This is why we use `EST5` to simulate an effective UTC-05:00 time.
    #
    # See
    # <https://www.gnu.org/software/libc/manual/html_node/TZ-Variable.html>
    # to learn more.
    result = btu_cli.run_cli(
        build_root_dir,
        [str(ctf_traces_dir / "1/succeed/wk-heartbeat-u")] + cli_args,
        check=True,
        extra_env={"TZ": "EST5"},
    )
    assert _count_output_lines(result.stdout) == expected_event_count


@pytest.mark.parametrize(
    "cli_args",
    [
        pytest.param(
            ["--begin=2012-10-29 12:48:17.1231231231"],
            id="date-time-format-too-many-nanosecond-digits",
        ),
        pytest.param(
            ["--begin=2012-10-29 12:48:17."],
            id="date-time-format-missing-nanoseconds",
        ),
        pytest.param(
            ["--begin=2012-10-29 12:48:123"],
            id="date-time-format-seconds-with-too-many-digits",
        ),
        pytest.param(
            ["--begin=2012-10-29 12:48:1"],
            id="date-time-format-seconds-with-missing-digit",
        ),
        pytest.param(
            ["--begin=2012-10-29 12:489:17"],
            id="date-time-format-minutes-with-too-many-digits",
        ),
        pytest.param(
            ["--begin=2012-10-29 12:4:17"],
            id="date-time-format-minutes-with-missing-digit",
        ),
        pytest.param(
            ["--begin=2012-10-29 123:48:17"],
            id="date-time-format-hours-with-too-many-digits",
        ),
        pytest.param(
            ["--begin=2012-10-29 2:48:17"],
            id="date-time-format-hours-with-missing-digit",
        ),
        pytest.param(
            ["--begin=2012-10-29 12:48:"],
            id="date-time-format-missing-seconds",
        ),
        pytest.param(
            ["--begin=2012-10-29 12:"],
            id="date-time-format-missing-minutes-1",
        ),
        pytest.param(
            ["--begin=2012-10-29 12"],
            id="date-time-format-missing-minutes-2",
        ),
        pytest.param(
            ["--begin=2012-10-29 "],
            id="date-time-format-missing-time",
        ),
        pytest.param(
            ["--begin=2012-10-291"],
            id="date-time-format-day-with-too-many-digits",
        ),
        pytest.param(
            ["--begin=2012-10-2"],
            id="date-time-format-day-with-missing-digit",
        ),
        pytest.param(
            ["--begin=2012-101-29"],
            id="date-time-format-month-with-too-many-digits",
        ),
        pytest.param(
            ["--begin=2012-1-29"],
            id="date-time-format-month-with-missing-digit",
        ),
        pytest.param(
            ["--begin=20121-10-29"],
            id="date-time-format-year-with-too-many-digits",
        ),
        pytest.param(
            ["--begin=12-10-29"],
            id="date-time-format-year-with-missing-digits",
        ),
        pytest.param(
            ["--begin=2012-10-"],
            id="date-time-format-missing-day-1",
        ),
        pytest.param(
            ["--begin=2012-10"],
            id="date-time-format-missing-day-2",
        ),
        pytest.param(
            ["--begin=1351532898.1231231231"],
            id="seconds-from-origin-format-too-many-nanosecond-digits",
        ),
        pytest.param(
            ["--begin=1351532898."],
            id="seconds-from-origin-format-missing-nanoseconds",
        ),
    ],
)
def test_trimmer_failure(ctf_traces_dir, build_root_dir, cli_args):
    result = btu_cli.run_cli(
        build_root_dir,
        [str(ctf_traces_dir / "1/succeed/wk-heartbeat-u")] + cli_args,
        check=False,
        extra_env={"TZ": "EST5", "BABELTRACE_FLT_UTILS_TRIMMER_LOG_LEVEL": "E"},
    )
    assert result.returncode != 0
    assert _count_output_lines(result.stdout) == 0
    assert result.stderr, "Nothing on standard error"
    assert "Invalid date/time format" in result.stderr
