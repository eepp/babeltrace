# SPDX-FileCopyrightText: 2019-2025 Efficios, Inc.
# SPDX-License-Identifier: GPL-2.0-only

import pathlib
import tempfile

import bt2
import mctf
import pytest
import bt_tests_utils as btu


def _find_expect_file(expect_dir, test_name, ctf_version, mip_version):
    # Try different naming patterns in order of specificity
    candidates = [
        (
            expect_dir
            / "trace-{}-ctf{}-mip{}.expect".format(test_name, ctf_version, mip_version)
        ),
        expect_dir / "trace-{}-ctf{}.expect".format(test_name, ctf_version),
        expect_dir / "trace-{}-mip{}.expect".format(test_name, mip_version),
        expect_dir / "trace-{}.expect".format(test_name),
    ]

    for candidate in candidates:
        if candidate.exists():
            return candidate

    raise FileNotFoundError(
        "Could not find expectation file for test `{}`, CTF `{}`, MIP `{}`".format(
            test_name, ctf_version, mip_version
        )
    )


# Valid CTF/MIP combinations: CTF 1.8 with any MIP, or any CTF with
# MIP 1 (CTF 2 + MIP 0 is invalid).
_CTF_MIP_COMBOS = [
    pytest.param(1, 0, id="ctf-1.8-mip-0"),
    pytest.param(1, 1, id="ctf-1.8-mip-1"),
    pytest.param(2, 1, id="ctf-2-mip-1"),
]


@pytest.fixture
def expect_dir(data_dir):
    return data_dir / "plugins/src.ctf.fs/succeed"


# Test for generated trace using the `gen-trace-simple` binary.
def test_generated_trace_simple(build_root_dir, expect_dir, tmp_path):
    trace_dir = tmp_path / "trace"
    trace_dir.mkdir()

    # Generate trace using `gen-trace-simple`
    btu.run(
        build_root_dir,
        btu.build_dir_of_source_file(build_root_dir, __file__) / "gen-trace-simple",
        [str(trace_dir)],
        check=True,
    )

    # Validate contents
    btu.convert_sink_text_details_test(
        trace_dir,
        expect_dir / "trace-simple.expect",
        details_params={
            "with-trace-name": False,
            "with-stream-name": False,
            "with-uuid": False,
            "with-uid": False,
        },
    )


# Test that traces exist in both CTF 1.8 and CTF 2
@pytest.mark.parametrize(["ctf_version", "mip_version"], _CTF_MIP_COMBOS)
@pytest.mark.parametrize(
    "trace_name",
    [
        "smalltrace",
        "2packets",
        "barectf-event-before-packet",
        "session-rotation",
        "lttng-tracefile-rotation",
        "array-align-elem",
        "struct-array-align-elem",
        "meta-ctx-sequence",
    ],
)
def test_trace(ctf_traces_dir, expect_dir, trace_name, ctf_version, mip_version):
    btu.convert_sink_text_details_test(
        ctf_traces_dir / str(ctf_version) / "succeed" / trace_name,
        _find_expect_file(expect_dir, trace_name, ctf_version, mip_version),
        details_params={"with-trace-name": False, "with-stream-name": False},
        mip_version=mip_version,
    )


# Test that traces existing in only one CTF version.
@pytest.mark.parametrize(
    ["trace_name", "ctf_version", "mip_version"],
    [
        pytest.param(
            "meta-clk-cls-before-trace-cls",
            2,
            1,
            id="meta-clk-cls-before-trace-cls-ctf-2-mip-1",
        ),
        pytest.param("def-clk-freq", 1, 0, id="def-clk-freq-ctf-1.8-mip-0"),
        pytest.param("def-clk-freq", 1, 1, id="def-clk-freq-ctf-1.8-mip-1"),
    ],
)
def test_trace_single_ctf_version(
    ctf_traces_dir, expect_dir, trace_name, ctf_version, mip_version
):
    btu.convert_sink_text_details_test(
        ctf_traces_dir / str(ctf_version) / "succeed" / trace_name,
        _find_expect_file(expect_dir, trace_name, ctf_version, mip_version),
        details_params={"with-trace-name": False, "with-stream-name": False},
        mip_version=mip_version,
    )


# Test for packetized metadata with trailing byte.
def test_meta_trailing_byte(ctf_traces_dir, dummy_comp_cls, capfd):
    btu.convert(
        bt2.AutoSourceComponentSpec(
            str(ctf_traces_dir / "1/succeed/meta-trailing-byte"),
            logging_level=bt2.LoggingLevel.WARNING,
        ),
        btu.SinkComponentSpec(dummy_comp_cls),
    )

    assert (
        "Remaining buffer isn't large enough to hold a packet header"
        in capfd.readouterr().err
    )


# Test that packet end messages are correctly emitted for traces with
# event records occurring after the packet end timestamp.
@pytest.mark.parametrize(["ctf_version", "mip_version"], _CTF_MIP_COMBOS)
@pytest.mark.parametrize("trace_name", ["lttng-event-after-packet", "lttng-crash"])
def test_packet_end(
    ctf_traces_dir, expect_dir, details_comp_cls, trace_name, ctf_version, mip_version
):
    with tempfile.TemporaryDirectory(prefix="bt-test-packet-end-") as temp_dir:
        temp_path = pathlib.Path(temp_dir) / "output.txt"

        btu.convert(
            ctf_traces_dir / str(ctf_version) / "succeed" / trace_name,
            btu.SinkComponentSpec(
                details_comp_cls,
                {
                    "path": str(temp_path),
                    "with-trace-name": False,
                    "with-stream-name": False,
                    "with-metadata": False,
                    "compact": True,
                },
            ),
            mip_version=mip_version,
        )

        # Filter only `Packet end` lines from output
        filtered_output = "\n".join(
            line for line in temp_path.read_text().splitlines() if "Packet end" in line
        )

        expected = (
            _find_expect_file(expect_dir, trace_name, ctf_version, mip_version)
            .read_text()
            .strip()
        )

        assert filtered_output.strip() == expected


# Test for clock offset going back in time (generated from
# `.mctf` files).
def test_clock_offset_goes_back_in_time(expect_dir, tmp_path):
    trace_dir = tmp_path / "trace"
    trace_dir.mkdir()

    # Generate trace chunks from .mctf files
    mctf_dir = expect_dir / "clock-offset-goes-back-in-time"
    mctf.generate(str(mctf_dir / "chunk1.mctf"), str(trace_dir / "chunk1"), False)
    mctf.generate(str(mctf_dir / "chunk2.mctf"), str(trace_dir / "chunk2"), False)

    # Validate output
    btu.convert_sink_text_details_test(
        trace_dir,
        expect_dir / "trace-clock-offset-goes-back-in-time.expect",
        details_params={"with-stream-name": False},
    )


# Test the `force-clock-class-origin-unix-epoch` parameter with
# two traces.
@pytest.mark.parametrize(["ctf_version", "mip_version"], _CTF_MIP_COMBOS)
def test_force_origin_unix_epoch(ctf_traces_dir, expect_dir, ctf_version, mip_version):
    btu.convert_sink_text_details_test(
        [
            bt2.AutoSourceComponentSpec(
                str(ctf_traces_dir / str(ctf_version) / "succeed/2packets"),
                params={"force-clock-class-origin-unix-epoch": True},
            ),
            bt2.AutoSourceComponentSpec(
                str(
                    ctf_traces_dir
                    / str(ctf_version)
                    / "succeed/barectf-event-before-packet"
                ),
                params={"force-clock-class-origin-unix-epoch": True},
            ),
        ],
        _find_expect_file(
            expect_dir, "2packets-barectf-event-before-packet", ctf_version, mip_version
        ),
        details_params={
            "with-trace-name": False,
            "with-stream-name": False,
            "with-metadata": True,
            "compact": True,
        },
        mip_version=mip_version,
    )
