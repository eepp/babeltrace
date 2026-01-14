# SPDX-FileCopyrightText: 2019-2025 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only

import pathlib
import tempfile
import contextlib

import bt2
import mctf
import pytest
import bt_tests_utils as btu

from lttng_live_server import LttngLiveServerProcess


@pytest.fixture(scope="module")
def test_data_dir(data_dir):
    return data_dir / "plugins/src.ctf.lttng-live"


# Context manager that creates and starts a faux LTTng live server
# process, waiting up to 10 seconds for it to finish on exit.
@contextlib.contextmanager
def _lttng_live_server(*args, **kwargs):
    server = LttngLiveServerProcess.from_config_file(*args, **kwargs)
    server.start()

    try:
        yield server
    finally:
        server.wait(timeout=10)

        if server.is_alive:
            # Server might still be alive if the test errored out
            # without cleanly closing the connection: just close it.
            server.close()


# Attach to a live session, output with `sink.text.details`, and assert
# the output matches `expect`.
#
# `expect` is a `pathlib.Path` (expectation file) or a string.
#
# Used by most tests below to consume trace data from the faux server.
def _convert_attach(
    live_comp_cls,
    session_url,
    expect,
    mip_version=None,
    details_params=None,
):
    btu.convert_sink_text_details_test(
        bt2.ComponentSpec(
            live_comp_cls,
            {
                "inputs": [session_url],
                # End when the session is done instead of trying to
                # reconnect indefinitely (the default).
                "session-not-found-action": "end",
            },
        ),
        expect,
        details_params=details_params,
        mip_version=mip_version,
    )


# Test the basic listing of sessions.
#
# Ensure that a multi-domain trace is seen as a single session.
@pytest.mark.parametrize(
    "session_config,max_minor_version,expected_sessions",
    [
        pytest.param(
            "list-sessions.json",
            4,
            [
                {
                    "target-hostname": "hostname",
                    "session-name": "multi-domains",
                    "timer-us": 1,
                    "stream-count": 10,
                    "client-count": 0,
                    "trace-format": "ctf-1.8",
                },
                {
                    "target-hostname": "hostname",
                    "session-name": "trace-with-index",
                    "timer-us": 1,
                    "stream-count": 5,
                    "client-count": 0,
                    "trace-format": "ctf-1.8",
                },
            ],
            id="v2.4-protocol",
        ),
        pytest.param(
            "list-sessions-2.15.json",
            15,
            [
                {
                    "target-hostname": "hostname",
                    "session-name": "multi-domains",
                    "timer-us": 1,
                    "stream-count": 10,
                    "client-count": 0,
                    "trace-format": "ctf-2.0",
                },
                {
                    "target-hostname": "hostname",
                    "session-name": "trace-with-index",
                    "timer-us": 1,
                    "stream-count": 5,
                    "client-count": 0,
                    "trace-format": "ctf-1.8",
                },
            ],
            id="v2.15-protocol",
        ),
    ],
)
def test_list_sessions(
    live_comp_cls,
    ctf_traces_dir,
    test_data_dir,
    session_config,
    max_minor_version,
    expected_sessions,
):
    with _lttng_live_server(
        str(test_data_dir / session_config),
        trace_path_prefix=str(ctf_traces_dir),
        max_minor_version=max_minor_version,
    ) as server:
        execu = bt2.QueryExecutor(live_comp_cls, "sessions", {"url": server.base_url})
        results = execu.query()
        expected = []

        for session in expected_sessions:
            session = dict(session)
            session["url"] = server.session_url(session["session-name"])
            expected.append(session)

        assert results == expected


# Attach and consume data from various sessions.
@pytest.mark.parametrize(
    "session_config,expected_file,session_name,mip_version,max_minor_version,max_query_data_response_size",
    [
        # Attach and consume data from a multi-packet UST session with
        # no discarded event records.
        pytest.param(
            "base.json",
            "cli-base.expect",
            "trace-with-index",
            0,
            4,
            None,
            id="base-v2.4",
        ),
        # Like `base-v2.4`, but with the v2.15 protocol.
        pytest.param(
            "base-2.15.json",
            "cli-base-2.15.expect",
            "trace-with-index",
            None,
            15,
            None,
            id="base-v2.15",
        ),
        # Attach and consume data from a multi-domain session with
        # discarded event records.
        pytest.param(
            "multi-domains.json",
            "cli-multi-domains.expect",
            "multi-domains",
            0,
            4,
            None,
            id="multi-domains-v2.4",
        ),
        # Like `multi-domains-v2.4`, but with the v2.15 protocol.
        pytest.param(
            "multi-domains-2.15.json",
            "cli-multi-domains-2.15.expect",
            "multi-domains",
            None,
            15,
            None,
            id="multi-domains-v2.15",
        ),
        # Attach and consume data from a multi-packet UST session with
        # no discarded event records.
        #
        # Enforce a server side limit on the stream data requests size.
        #
        # Ensure that Babeltrace respects the returned size and that
        # many requests per packet works as expected.
        #
        # The packet size of the test trace is 4 KiB. Limit requests
        # to 1 kiB.
        pytest.param(
            "rate-limited.json",
            "cli-base.expect",
            "trace-with-index",
            0,
            4,
            1024,
            id="rate-limited",
        ),
        # Attach and consume data from a multi-packet trace with
        # discarded packets and emit an inactivity beacon during the
        # discarded packets period.
        #
        #     | pkt seq:0 |<-------discarded packets------>| pkt seq:8 |
        #     0          20                                121       140
        #
        # This test was introduced to cover the following bug:
        #
        # When reading this type of trace locally, the CTF source is
        # expected to introduce a "discarded packets" message between
        # packets 0 and 8. The timestamps of this message are
        # [pkt0.end_ts, pkt8.begin_ts].
        #
        # In the context of an LTTng live source, the tracer could
        # report an inactivity period during the interval of the
        # "discarded packets" message. Those messages eventually
        # translate into a "message iterator inactivity" message with a
        # timestamp set at the end of the inactivity period.
        #
        # If the tracer reports an inactivity period that ends at a
        # point between pkt0 and pkt7 (resulting in a "message iterator
        # inactivity" message), the LTTng live source could send a
        # "discarded packets" message that starts before the preceding
        # "message iterator inactivity" message. This would break the
        # monotonicity constraint of the graph.
        pytest.param(
            "inactivity-discarded-packet.json",
            "inactivity-discarded-packet.expect",
            "7-lost-between-2-with-index",
            0,
            4,
            None,
            id="inactivity-discarded-packet",
        ),
        # Consume a metadata stream sent in two parts.
        #
        # This tests the behaviour of Babeltrace when the tracing
        # session was cleared (`lttng clear`) but the metadata is not
        # yet available to the relay.
        #
        # In such cases, when asked for metadata, the relay will return
        # the `LTTNG_VIEWER_METADATA_OK` status and a data length of 0.
        # The viewer needs to consider such case as a request to retry
        # fetching metadata.
        #
        # This emulates such behaviour by adding empty metadata packets.
        pytest.param(
            "split-metadata.json",
            "split-metadata.expect",
            "split-metadata",
            0,
            4,
            None,
            id="split-metadata",
        ),
    ],
)
def test_attach(
    live_comp_cls,
    ctf_traces_dir,
    test_data_dir,
    session_config,
    expected_file,
    session_name,
    mip_version,
    max_minor_version,
    max_query_data_response_size,
):
    with _lttng_live_server(
        str(test_data_dir / session_config),
        trace_path_prefix=str(ctf_traces_dir),
        max_minor_version=max_minor_version,
        max_query_data_response_size=max_query_data_response_size,
    ) as server:
        _convert_attach(
            live_comp_cls,
            server.session_url(session_name),
            test_data_dir / expected_file,
            mip_version,
        )


# Compare the `sink.text.details` output of `src.ctf.fs` and
# `src.ctf.lttng-live` to ensure that the trace is parsed the same way.
#
# Do the same with the session swapped on the relay daemon side. This
# validates that ordering is consistent between live and `src.ctf.fs`.
@pytest.mark.parametrize(
    "session_config",
    [
        pytest.param("multi-domains.json", id="normal-order"),
        pytest.param("multi-domains-inverse.json", id="inverse-order"),
    ],
)
def test_compare_to_ctf_fs(
    live_comp_cls, ctf_traces_dir, test_data_dir, session_config
):
    details_params = {"with-trace-name": False, "with-stream-name": False}

    # Get expected output from `src.ctf.fs` by writing to a temp file
    with tempfile.TemporaryDirectory() as temp_dir:
        output_path = pathlib.Path(temp_dir) / "output.txt"

        text_plugin = bt2.find_plugin("text")
        sink_spec = btu.SinkComponentSpec(
            text_plugin.sink_component_classes["details"],
            {"path": str(output_path), **details_params},
        )
        btu.convert(
            ctf_traces_dir / "1/succeed/multi-domains", sink_spec, mip_version=0
        )

        expected = output_path.read_text()

    with _lttng_live_server(
        str(test_data_dir / session_config),
        trace_path_prefix=str(ctf_traces_dir),
        max_minor_version=4,
    ) as server:
        _convert_attach(
            live_comp_cls,
            server.session_url("multi-domains"),
            expected,
            0,
            details_params,
        )


# Split metadata, where the new metadata requires additional stored
# value slots in CTF message iterators.
def test_stored_values(live_comp_cls, ctf_traces_dir, test_data_dir, tmp_path):
    # Generate test trace from `.mctf` file
    mctf.generate(
        str(ctf_traces_dir / "1/live/stored-values.mctf"),
        str(tmp_path / "stored-values"),
        False,
    )

    with _lttng_live_server(
        str(test_data_dir / "stored-values.json"),
        trace_path_prefix=str(tmp_path),
        max_minor_version=4,
    ) as server:
        _convert_attach(
            live_comp_cls,
            server.session_url("stored-values"),
            test_data_dir / "stored-values.expect",
            0,
        )


# Announce a new stream while an existing stream is inactive.
#
# This requires the LTTng live consumer to check for new announced
# streams when it receives inactivity beacons.
def test_new_stream_during_inactivity(
    live_comp_cls, ctf_traces_dir, test_data_dir, tmp_path
):
    # Generate test traces from `.mctf` files.
    #
    # Session name must appear in trace paths, hence the `new-streams`
    # subdirectory.
    mctf.generate(
        str(ctf_traces_dir / "1/live/new-streams/first-trace.mctf"),
        str(tmp_path / "new-streams/first-trace"),
        False,
    )
    mctf.generate(
        str(ctf_traces_dir / "1/live/new-streams/second-trace.mctf"),
        str(tmp_path / "new-streams/second-trace"),
        False,
    )

    with _lttng_live_server(
        str(test_data_dir / "new-streams.json"),
        trace_path_prefix=str(tmp_path / "new-streams"),
        max_minor_version=4,
    ) as server:
        _convert_attach(
            live_comp_cls,
            server.session_url("new-streams"),
            test_data_dir / "new-streams.expect",
            0,
        )


# Test that the component correctly handles invalid metadata sent by
# the relay.
def test_invalid_metadata(live_comp_cls, ctf_traces_dir, test_data_dir):
    with _lttng_live_server(
        str(test_data_dir / "invalid-metadata.json"),
        trace_path_prefix=str(ctf_traces_dir),
        max_minor_version=4,
    ) as server:
        src_spec = bt2.ComponentSpec(
            live_comp_cls,
            {
                "inputs": [server.session_url("invalid-metadata")],
                "session-not-found-action": "end",
            },
        )
        text_plugin = bt2.find_plugin("text")
        sink_spec = btu.SinkComponentSpec(text_plugin.sink_component_classes["details"])

        with pytest.raises(bt2._Error) as exc_info:
            btu.convert(src_spec, sink_spec)

        # Close server now to avoid waiting for the timeout since the
        # client didn't disconnect cleanly.
        server.close()

        assert "At line 12 in metadata stream: syntax error" in str(exc_info.value)
        assert 'token="perchaude"' in str(exc_info.value)
