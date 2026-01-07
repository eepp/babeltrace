# SPDX-FileCopyrightText: 2019-2025 Efficios, Inc.
# SPDX-License-Identifier: GPL-2.0-only

import re

import bt2
import pytest

_QUERY_OBJECT = "babeltrace.trace-infos"


@pytest.fixture(scope="module")
def ctf_fs_comp_cls():
    return bt2.find_plugin("ctf").source_component_classes["fs"]


def test_non_map_params(ctf_fs_comp_cls):
    with pytest.raises(bt2._Error) as exc_info:
        bt2.QueryExecutor(ctf_fs_comp_cls, _QUERY_OBJECT).query()

    assert "top-level is not a map value" in exc_info.value[0].message


_CTF_VERSIONS = [pytest.param(1, id="ctf-1.8"), pytest.param(2, id="ctf-2")]


@pytest.mark.parametrize("ctf_version", _CTF_VERSIONS)
@pytest.mark.parametrize(
    ["offset_s", "offset_ns", "expected_offset"],
    [
        pytest.param(None, None, 0, id="no-offset"),
        pytest.param(2, None, 2000000000, id="offset-s"),
        pytest.param(None, 2, 2, id="offset-ns"),
        pytest.param(-2, -2, -2000000002, id="both-negative"),
    ],
)
def test_clock_class_offset(
    ctf_fs_comp_cls, ctf_traces_dir, ctf_version, offset_s, offset_ns, expected_offset
):
    params = {
        "inputs": [
            str(ctf_traces_dir / str(ctf_version) / "intersection/3eventsintersect")
        ]
    }

    if offset_s is not None:
        params["clock-class-offset-s"] = offset_s

    if offset_ns is not None:
        params["clock-class-offset-ns"] = offset_ns

    res = bt2.QueryExecutor(ctf_fs_comp_cls, _QUERY_OBJECT, params).query()
    streams = sorted(res[0]["stream-infos"], key=lambda s: s["port-name"])
    assert streams[0]["range-ns"]["begin"] == 13515309000000000 + expected_offset
    assert streams[0]["range-ns"]["end"] == 13515309000000100 + expected_offset
    assert streams[1]["range-ns"]["begin"] == 13515309000000070 + expected_offset
    assert streams[1]["range-ns"]["end"] == 13515309000000120 + expected_offset


@pytest.mark.parametrize("ctf_version", _CTF_VERSIONS)
@pytest.mark.parametrize(
    ["param_name", "param_value"],
    [
        pytest.param("clock-class-offset-s", "2", id="offset-s-string"),
        pytest.param("clock-class-offset-s", None, id="offset-s-none"),
        pytest.param("clock-class-offset-ns", "2", id="offset-ns-string"),
        pytest.param("clock-class-offset-ns", None, id="offset-ns-none"),
    ],
)
def test_clock_class_offset_wrong_type(
    ctf_fs_comp_cls, ctf_traces_dir, ctf_version, param_name, param_value
):
    with pytest.raises(bt2._Error):
        bt2.QueryExecutor(
            ctf_fs_comp_cls,
            _QUERY_OBJECT,
            {
                "inputs": [
                    str(
                        ctf_traces_dir
                        / str(ctf_version)
                        / "intersection/3eventsintersect"
                    )
                ],
                param_name: param_value,
            },
        ).query()


@pytest.mark.parametrize("ctf_version", _CTF_VERSIONS)
def test_port_name_trace_uuid_stream_class_id_no_stream_id(
    ctf_fs_comp_cls, ctf_traces_dir, ctf_version
):
    res = bt2.QueryExecutor(
        ctf_fs_comp_cls,
        _QUERY_OBJECT,
        {
            "inputs": [
                str(ctf_traces_dir / str(ctf_version) / "intersection/3eventsintersect")
            ]
        },
    ).query()

    assert len(res) == 1
    streams = sorted(res[0]["stream-infos"], key=lambda s: s["port-name"])
    assert len(streams) == 2

    for i, stream in enumerate(streams):
        assert re.match(
            r"^\{{name: ``, uid: `7afe8fbe-79b8-4f6a-bbc7-d0c782e7ddaf`}} \| 0 \| "
            r".*[/\\]tests[/\\]data[/\\]ctf-traces[/\\]{ctf_v}[/\\]intersection[/\\]3eventsintersect[/\\]test_stream_{i}$".format(
                ctf_v=ctf_version, i=i
            ),
            str(stream["port-name"]),
        )


# This test only applies to CTF 1.8.
def test_port_name_trace_uuid_no_stream_class_id_no_stream_id(
    ctf_fs_comp_cls, ctf_traces_dir
):
    res = bt2.QueryExecutor(
        ctf_fs_comp_cls,
        _QUERY_OBJECT,
        {"inputs": [str(ctf_traces_dir / "1/succeed/succeed1")]},
    ).query()

    assert len(res) == 1
    streams = sorted(res[0]["stream-infos"], key=lambda s: s["port-name"])
    assert len(streams) == 1
    assert re.match(
        r"^\{name: ``, uid: `2a6422d0-6cee-11e0-8c08-cb07d7b3a564`} \| "
        r".*[/\\]tests[/\\]data[/\\]ctf-traces[/\\]1[/\\]succeed[/\\]succeed1[/\\]dummystream$",
        str(streams[0]["port-name"]),
    )


@pytest.mark.parametrize("ctf_version", _CTF_VERSIONS)
def test_trace_no_range(ctf_fs_comp_cls, ctf_traces_dir, ctf_version):
    # This trace has no `timestamp_begin` and `timestamp_end` in its
    # packet context. The `babeltrace.trace-infos` query should omit
    # the `range-ns` fields in the `trace` and `stream` data
    # structures.
    res = bt2.QueryExecutor(
        ctf_fs_comp_cls,
        _QUERY_OBJECT,
        {"inputs": [str(ctf_traces_dir / str(ctf_version) / "succeed/succeed1")]},
    ).query()

    assert len(res) == 1
    trace = res[0]
    stream_infos = trace["stream-infos"]
    assert len(stream_infos) == 1
    assert "range-ns" not in trace
    assert "range-ns" not in stream_infos[0]


@pytest.mark.parametrize("ctf_version", _CTF_VERSIONS)
def test_trace_with_tracefile_rotation(ctf_fs_comp_cls, ctf_traces_dir, ctf_version):
    res = bt2.QueryExecutor(
        ctf_fs_comp_cls,
        _QUERY_OBJECT,
        {
            "inputs": [
                str(
                    ctf_traces_dir
                    / str(ctf_version)
                    / "succeed/lttng-tracefile-rotation/kernel"
                )
            ]
        },
    ).query()

    assert len(res) == 1
    streams = res[0]["stream-infos"]
    assert len(streams) == 4

    # NOTE: the end timestamps are not the end timestamps found in the
    # index files, because fix_index_lttng_event_after_packet_bug()
    # changes them based on the time of the last event record in the
    # data stream.
    assert streams[0]["range-ns"]["begin"] == 1571261795455986789
    assert streams[0]["range-ns"]["end"] == 1571261797582611840
    assert streams[1]["range-ns"]["begin"] == 1571261795456368232
    assert streams[1]["range-ns"]["end"] == 1571261797577754111
    assert streams[2]["range-ns"]["begin"] == 1571261795456748255
    assert streams[2]["range-ns"]["end"] == 1571261797577727795
    assert streams[3]["range-ns"]["begin"] == 1571261795457285142
    assert streams[3]["range-ns"]["end"] == 1571261797582522088


@pytest.mark.parametrize("ctf_version", _CTF_VERSIONS)
@pytest.mark.parametrize(
    ["trace_name", "expected_begin", "expected_end"],
    [
        pytest.param(
            "lttng-event-after-packet",
            1565957300948091100,
            1565957302180016069,
            id="event-after-packet",
        ),
        pytest.param(
            "lttng-crash",
            1565891729288866738,
            1565891729293526525,
            id="lttng-crash",
        ),
    ],
)
def test_lttng_quirks(
    ctf_fs_comp_cls,
    ctf_traces_dir,
    ctf_version,
    trace_name,
    expected_begin,
    expected_end,
):
    res = bt2.QueryExecutor(
        ctf_fs_comp_cls,
        _QUERY_OBJECT,
        {"inputs": [str(ctf_traces_dir / str(ctf_version) / "succeed" / trace_name)]},
    ).query()

    assert len(res) == 1
    streams = res[0]["stream-infos"]
    assert len(streams) == 1
    assert streams[0]["range-ns"]["begin"] == expected_begin
    assert streams[0]["range-ns"]["end"] == expected_end
