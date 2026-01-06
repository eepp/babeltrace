# SPDX-FileCopyrightText: 2013 Christian Babeux <christian.babeux@efficios.com>
# SPDX-FileCopyrightText: 2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import bt_tests_cli_utils as btu_cli


def pytest_generate_tests(metafunc):
    ctf_traces_dir = metafunc.config.ctf_traces_dir

    for fixture_name, subdir in (("succeed_trace", "succeed"), ("fail_trace", "fail")):
        if fixture_name in metafunc.fixturenames:
            traces = sorted((ctf_traces_dir / "1" / subdir).iterdir())
            metafunc.parametrize(fixture_name, traces, ids=[t.name for t in traces])


def test_succeed_trace(build_root_dir, succeed_trace):
    btu_cli.run_cli(build_root_dir, [str(succeed_trace)], check=True)


def test_fail_trace(build_root_dir, fail_trace):
    assert btu_cli.run_cli(build_root_dir, [str(fail_trace)]).returncode != 0
