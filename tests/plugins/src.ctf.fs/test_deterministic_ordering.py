# SPDX-FileCopyrightText: 2019-2025 Efficios, Inc.
# SPDX-License-Identifier: GPL-2.0-only

import bt2
import pytest
import bt_tests_utils as btu

# Test the deterministic behavior of the `src.ctf.fs` component versus
# the ordering of the given input paths.
#
# In presence of multiple copies of the same packet, we want it to pick
# the copy of the packet to read in a deterministic fashion.
#
# This test is written assuming the specific implementation of the
# `src.ctf.fs` component class, which sorts its input paths
# lexicographically.
#
# There are three traces (`a-corrupted`, `b-not-corrupted`, and
# `c-corrupted`) with the same UUID and the same packet, except that
# this packet is corrupted in `a-corrupted` and `c-corrupted`. In these
# cases, there is an event with an invalid id.  When reading these
# corrupted packets, we expect babeltrace to emit an error.
#
# When reading `a-corrupted` and `b-not-corrupted` together, the copy of
# the packet from `a-corrupted` is read, and `babeltrace2` exits with an
# error.
#
# When reading `b-not-corrupted` and `c-corrupted` together, the copy of
# the packet from `b-not-corrupted` is read, and `babeltrace2` executes
# successfully.


@pytest.fixture(scope="module")
def traces_dir(ctf_traces_dir):
    return ctf_traces_dir / "1/deterministic-ordering"


@pytest.fixture(scope="module")
def trace_b_not_corrupted(traces_dir):
    return traces_dir / "b-not-corrupted"


@pytest.fixture(scope="module")
def trace_c_corrupted(traces_dir):
    return traces_dir / "c-corrupted"


# Trace with corrupted packet comes first lexicographically: expect
# a failure.
@pytest.mark.parametrize("order", ["ab", "ba"])
def test_expect_failure(
    traces_dir, trace_b_not_corrupted, src_ctf_comp_cls, dummy_comp_cls, order
):
    trace_a_corrupted = traces_dir / "a-corrupted"

    if order == "ab":
        inputs = [str(trace_a_corrupted), str(trace_b_not_corrupted)]
    else:
        inputs = [str(trace_b_not_corrupted), str(trace_a_corrupted)]

    with pytest.raises(bt2._Error) as exc_info:
        btu.convert(
            bt2.ComponentSpec(src_ctf_comp_cls, params={"inputs": inputs}),
            btu.SinkComponentSpec(dummy_comp_cls),
        )

    assert (
        "At 48 bits: no event record class exists with ID 255 within the data stream"
        in exc_info.value[0].message
    )


# Trace with non-corrupted packet comes first lexicographically: expect
# a success.
@pytest.mark.parametrize("order", ["bc", "cb"])
def test_expect_success(
    traces_dir, trace_b_not_corrupted, trace_c_corrupted, src_ctf_comp_cls, order
):
    if order == "bc":
        inputs = [str(trace_b_not_corrupted), str(trace_c_corrupted)]
    else:
        inputs = [str(trace_c_corrupted), str(trace_b_not_corrupted)]

    btu.convert_sink_text_details_test(
        bt2.ComponentSpec(src_ctf_comp_cls, params={"inputs": inputs}),
        traces_dir / "b-c.expect",
        details_params={
            "with-trace-name": False,
            "with-stream-name": False,
            "with-metadata": False,
            "compact": True,
        },
    )
