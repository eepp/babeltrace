# SPDX-FileCopyrightText: 2019 Philippe Proulx <pproulx@efficios.com>
# SPDX-FileCopyrightText: 2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import bt2
import pytest
import bt_tests_utils as btu


def _find_expect_file(expect_dir, test_name, ctf_version, mip_version):
    # Try different naming patterns in order of specificity
    candidates = [
        expect_dir
        / "{}-ctf{}-mip{}.expect".format(test_name, ctf_version, mip_version),
        expect_dir / "{}-ctf{}.expect".format(test_name, ctf_version),
        expect_dir / "{}-mip{}.expect".format(test_name, mip_version),
        expect_dir / "{}.expect".format(test_name),
    ]

    for candidate in candidates:
        if candidate.exists():
            return candidate

    raise FileNotFoundError(
        "Could not find expectation file for test `{}`, CTF `{}`, MIP `{}`".format(
            test_name, ctf_version, mip_version
        )
    )


@pytest.mark.parametrize(
    ["ctf_version", "mip_version"],
    # Valid CTF/MIP combinations: CTF 1.8 with any MIP, or any CTF with
    # MIP 1 (CTF 2 + MIP 0 is invalid).
    [
        pytest.param(1, 0, id="ctf-1.8-mip-0"),
        pytest.param(1, 1, id="ctf-1.8-mip-1"),
        pytest.param(2, 1, id="ctf-2-mip-1"),
    ],
)
@pytest.mark.parametrize(
    ["test_name", "trace_name", "details_params"],
    [
        ("default", "wk-heartbeat-u", {}),
        ("default-compact", "wk-heartbeat-u", {"compact": True}),
        (
            "default-compact-without-metadata",
            "wk-heartbeat-u",
            {"compact": True, "with-metadata": False},
        ),
        (
            "default-compact-without-time",
            "wk-heartbeat-u",
            {"compact": True, "with-time": False},
        ),
        ("default-without-data", "wk-heartbeat-u", {"with-data": False}),
        (
            "default-without-data-without-metadata",
            "wk-heartbeat-u",
            {"with-data": False, "with-metadata": False},
        ),
        ("default-without-metadata", "wk-heartbeat-u", {"with-metadata": False}),
        (
            "default-without-names",
            "wk-heartbeat-u",
            {
                "with-stream-name": False,
                "with-trace-name": False,
                "with-stream-class-name": False,
            },
        ),
        ("default-without-time", "wk-heartbeat-u", {"with-time": False}),
        ("default-without-trace-name", "wk-heartbeat-u", {"with-trace-name": False}),
        ("default-without-uuid", "wk-heartbeat-u", {"with-uuid": False}),
        ("no-packet-context", "no-packet-context", {}),
    ],
)
def test_details_succeed(
    ctf_traces_dir,
    data_dir,
    test_name,
    trace_name,
    details_params,
    ctf_version,
    mip_version,
):
    # Always disable stream name (contains absolute paths from `src.ctf.fs`)
    params = {"with-stream-name": False}
    params.update(details_params)

    btu.convert_sink_text_details_test(
        bt2.AutoSourceComponentSpec(
            str(ctf_traces_dir / str(ctf_version) / "succeed" / trace_name),
            params={"trace-name": "the-trace"},
        ),
        _find_expect_file(
            data_dir / "plugins/sink.text.details/succeed",
            test_name,
            ctf_version,
            mip_version,
        ),
        details_params=params,
        mip_version=mip_version,
    )
