# SPDX-FileCopyrightText: 2019-2025 Efficios, Inc.
# SPDX-License-Identifier: GPL-2.0-only

import bt2
import pytest
import bt_tests_utils as btu


# Validates that a `src.ctf.fs` component handles gracefully invalid CTF
# traces and produces the expected error message.
@pytest.mark.parametrize(
    ["trace_name", "ctf_version", "expected_error_msg"],
    [
        pytest.param(
            "invalid-packet-size/trace",
            1,
            "Failed to index CTF stream file",
            id="invalid-packet-size",
        ),
        pytest.param(
            "valid-events-then-invalid-events/trace",
            1,
            "At 24 bits: no event record class exists with ID 255 within the data stream",
            id="valid-events-then-invalid-events",
        ),
        pytest.param(
            "metadata-syntax-error",
            1,
            'At line 3 in metadata stream: syntax error, unexpected CTF_RSBRAC: token="]"',
            id="metadata-syntax-error",
        ),
        pytest.param(
            "invalid-sequence-length-field-class",
            1,
            "Sequence field class's length field class is not an unsigned integer field class:",
            id="invalid-sequence-length-field-class",
        ),
        pytest.param(
            "invalid-variant-selector-field-class",
            1,
            "Variant field class's tag field class is not an enumeration field class:",
            id="invalid-variant-selector-field-class",
        ),
        pytest.param(
            "incomplete-packet-header",
            1,
            "Insufficient data in file to fulfill request",
            id="incomplete-packet-header",
        ),
        pytest.param(
            "meta-no-trace-cls-no-stream-cls",
            2,
            "Missing data stream class fragment in metadata stream.",
            id="meta-no-trace-cls-no-stream-cls",
        ),
        pytest.param(
            "empty-event-record",
            2,
            "At 0 bits: Invalid empty event record.",
            id="empty-event-record",
        ),
    ],
)
def test_fail(
    ctf_traces_dir,
    src_ctf_comp_cls,
    dummy_comp_cls,
    trace_name,
    ctf_version,
    expected_error_msg,
):
    trace_path = ctf_traces_dir / str(ctf_version) / "fail" / trace_name

    with pytest.raises(bt2._Error) as exc_info:
        btu.convert(
            bt2.ComponentSpec(src_ctf_comp_cls, params={"inputs": [str(trace_path)]}),
            btu.SinkComponentSpec(dummy_comp_cls),
        )

    assert expected_error_msg in exc_info.value[0].message
