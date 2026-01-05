# SPDX-FileCopyrightText: 2024-2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import enum
import uuid

import bt2
import pytest


# The types of messages a test source iterator is instructed to send.
class _MsgType(enum.Enum):
    # Send stream beginning and stream end messages
    STREAM = 1

    # Send a message iterator inactivity message
    MSG_ITER_INACTIVITY = 2


class _TestSourceData:
    def __init__(self, create_clk_cls_func, msg_type, clock_snapshot):
        self.create_clk_cls_func = create_clk_cls_func
        self.msg_type = msg_type
        self.clock_snapshot = clock_snapshot


def _create_no_clk_cls(comp):
    return None


# Determines if a test combination should be skipped.
def _should_skip(create_clk_cls_func_1, create_clk_cls_func_2, msg_type_1, msg_type_2):
    # It's not possible to create message iterator inactivity messages
    # without a clock class. Skip those cases.
    if (
        msg_type_1 == _MsgType.MSG_ITER_INACTIVITY
        and create_clk_cls_func_1 is _create_no_clk_cls
    ):
        return True

    if (
        msg_type_2 == _MsgType.MSG_ITER_INACTIVITY
        and create_clk_cls_func_2 is _create_no_clk_cls
    ):
        return True

    # The test scenarios depend on the message with the first clock
    # class going through the muxer first.
    #
    # Between a message with a clock snapshot and a message without a
    # clock snapshot, the muxer always picks the message without a clock
    # snapshot first.
    #
    # Message iterator inactivity messages always have a clock snapshot.
    # Therefore, if:
    #
    # First message:
    #     A message iterator inactivity message (always has a
    #     clock snapshot).
    #
    # Second message:
    #     Doesn't have a clock class (never has a clock snapshot).
    #
    # Then there's no way for the first message to go through first.
    #
    # Skip those cases.
    if (
        msg_type_1 == _MsgType.MSG_ITER_INACTIVITY
        and create_clk_cls_func_2 is _create_no_clk_cls
    ):
        return True

    return False


class _TestSourceIter(bt2._UserMessageIterator):
    def __init__(self, config, port):
        self._done = False
        self._data = port.user_data
        self._msgs = None
        self._stream = None

    def __next__(self):
        if self._done:
            raise StopIteration

        clk_cls = self._data.create_clk_cls_func(self._component)
        msg_type = self._data.msg_type
        clock_snapshot = self._data.clock_snapshot

        if msg_type == _MsgType.STREAM:
            # Store messages to return them one at a time
            if self._msgs is None:
                tc = self._component._create_trace_class()
                sc = tc.create_stream_class(default_clock_class=clk_cls)
                self._stream = tc().create_stream(sc)

                if clock_snapshot is not None:
                    sb_msg = self._create_stream_beginning_message(
                        self._stream, clock_snapshot
                    )
                else:
                    sb_msg = self._create_stream_beginning_message(self._stream)

                self._msgs = [sb_msg, self._create_stream_end_message(self._stream)]

            if self._msgs:
                return self._msgs.pop(0)
            else:
                self._done = True
                raise StopIteration
        elif msg_type == _MsgType.MSG_ITER_INACTIVITY:
            msg = self._create_message_iterator_inactivity_message(
                clk_cls, clock_snapshot
            )
            self._done = True
            return msg


class _TestSource(bt2._UserSourceComponent, message_iterator_class=_TestSourceIter):
    def __init__(self, config, params, obj):
        self._add_output_port("out", obj)


# Runs a graph with two sources connected to a muxer, then to a
# dummy sink.
#
# Returns a `bt2._Error` instance if an error occurred, or
# `None` otherwise.
def _run_graph(
    create_clk_cls_func_1,
    create_clk_cls_func_2,
    msg_type_1,
    msg_type_2,
    mip_version,
    muxer_comp_cls,
    dummy_comp_cls,
):
    graph = bt2.Graph(mip_version)

    # The test scenarios depend on the message with the first clock
    # class going through the muxer first. Between a message with a
    # clock snapshot and a message without a clock snapshot, the muxer
    # always picks the message without a clock snapshot first.
    #
    # Therefore, for the first message, only set a clock snapshot when
    # absolutely necessary, that is when the message type is "message
    # iterator inactivity".
    #
    # For the second message, always set a clock snapshot when possible,
    # that is when a clock class is defined for that message.
    clock_snapshot_1 = 10 if msg_type_1 == _MsgType.MSG_ITER_INACTIVITY else None
    clock_snapshot_2 = 20 if create_clk_cls_func_2 is not _create_no_clk_cls else None
    src_comp1 = graph.add_component(
        _TestSource,
        "source-1",
        obj=_TestSourceData(create_clk_cls_func_1, msg_type_1, clock_snapshot_1),
    )
    src_comp2 = graph.add_component(
        _TestSource,
        "source-2",
        obj=_TestSourceData(create_clk_cls_func_2, msg_type_2, clock_snapshot_2),
    )

    # Add muxer component
    muxer_comp = graph.add_component(muxer_comp_cls, "the-muxer")

    # Add dummy sink component
    sink_comp = graph.add_component(dummy_comp_cls, "the-sink")

    # Connect ports
    graph.connect_ports(src_comp1.output_ports["out"], muxer_comp.input_ports["in0"])
    graph.connect_ports(src_comp2.output_ports["out"], muxer_comp.input_ports["in1"])
    graph.connect_ports(muxer_comp.output_ports["out"], sink_comp.input_ports["in"])

    # Run the graph
    try:
        graph.run()
    except bt2._Error as e:
        return e


def _run_succeed_test(
    create_clk_cls_func,
    mip_version,
    msg_type_1,
    msg_type_2,
    muxer_comp_cls,
    dummy_comp_cls,
):
    if _should_skip(create_clk_cls_func, create_clk_cls_func, msg_type_1, msg_type_2):
        pytest.skip("Invalid test combination")

    error = _run_graph(
        create_clk_cls_func,
        create_clk_cls_func,
        msg_type_1,
        msg_type_2,
        mip_version,
        muxer_comp_cls,
        dummy_comp_cls,
    )

    assert error is None, "Unexpected error: {}".format(error)


# Clock class creation functions
def _create_unix_epoch_origin_clk_cls(comp):
    return comp._create_clock_class()


def _create_unknown_origin_uuid_a_clk_cls(comp):
    return comp._create_clock_class(
        origin_is_unix_epoch=False,
        uuid=uuid.UUID("f00aaf65-ebec-4eeb-85b2-fc255cf1aa8a"),
    )


def _create_unknown_origin_uuid_b_clk_cls(comp):
    return comp._create_clock_class(
        origin_is_unix_epoch=False,
        uuid=uuid.UUID("03482981-a77b-4d7b-94c4-592bf9e91785"),
    )


def _create_unknown_origin_no_uuid_clk_cls(comp):
    return comp._create_clock_class(origin_is_unix_epoch=False)


def _create_known_origin_clk_cls(comp):
    return comp._create_clock_class(
        origin=bt2.ClockOrigin("ze-origin-ns", "ze-origin-name", "ze-origin-uid")
    )


def _create_unknown_origin_identity_clk_cls(comp):
    return comp._create_clock_class(
        origin=bt2.unknown_clock_origin,
        namespace="ze-ns",
        name="ze-name",
        uid="ze-uid",
    )


def _create_unknown_origin_no_identity_clk_cls(comp):
    return comp._create_clock_class(origin=bt2.unknown_clock_origin)


def _create_unknown_origin_different_identity_clk_cls(comp):
    return comp._create_clock_class(
        origin=bt2.unknown_clock_origin,
        namespace="another-ns",
        name="another-name",
        uid="another-uid",
    )


# Generate all combinations of message types
_MSG_TYPE_COMBOS = [
    pytest.param(_MsgType.STREAM, _MsgType.STREAM, id="stream-stream"),
    pytest.param(_MsgType.STREAM, _MsgType.MSG_ITER_INACTIVITY, id="stream-inactivity"),
    pytest.param(_MsgType.MSG_ITER_INACTIVITY, _MsgType.STREAM, id="inactivity-stream"),
    pytest.param(
        _MsgType.MSG_ITER_INACTIVITY,
        _MsgType.MSG_ITER_INACTIVITY,
        id="inactivity-inactivity",
    ),
]


@pytest.mark.parametrize(
    ["create_clk_cls_func", "mip_version"],
    [
        pytest.param(_create_no_clk_cls, 0, id="no-clk-cls-mip-0"),
        pytest.param(_create_no_clk_cls, 1, id="no-clk-cls-mip-1"),
        pytest.param(
            _create_unix_epoch_origin_clk_cls, 0, id="unix-epoch-origin-mip-0"
        ),
        pytest.param(
            _create_unknown_origin_uuid_a_clk_cls,
            0,
            id="unknown-origin-same-uuid-mip-0",
        ),
        pytest.param(_create_known_origin_clk_cls, 1, id="known-origin-mip-1"),
        pytest.param(
            _create_unknown_origin_identity_clk_cls,
            1,
            id="unknown-origin-same-identity-mip-1",
        ),
    ],
)
@pytest.mark.parametrize(["msg_type_1", "msg_type_2"], _MSG_TYPE_COMBOS)
def test_compat_clk_classes(
    create_clk_cls_func,
    mip_version,
    msg_type_1,
    msg_type_2,
    muxer_comp_cls,
    dummy_comp_cls,
):
    _run_succeed_test(
        create_clk_cls_func,
        mip_version,
        msg_type_1,
        msg_type_2,
        muxer_comp_cls,
        dummy_comp_cls,
    )


# For the "same clock class instance" test, we need a special approach
# that creates a single clock class and reuses it.
_shared_clk_cls = None


def _create_unknown_origin_unknown_identity_shared_clk_cls(comp):
    global _shared_clk_cls

    if _shared_clk_cls is None:
        _shared_clk_cls = comp._create_clock_class(origin_is_unix_epoch=False)

    return _shared_clk_cls


_MIP_VERSIONS = [pytest.param(0, id="mip-0"), pytest.param(1, id="mip-1")]


@pytest.mark.parametrize("mip_version", _MIP_VERSIONS)
@pytest.mark.parametrize(["msg_type_1", "msg_type_2"], _MSG_TYPE_COMBOS)
def test_compat_clk_classes_same_instance(
    mip_version, msg_type_1, msg_type_2, muxer_comp_cls, dummy_comp_cls
):
    global _shared_clk_cls

    _shared_clk_cls = None
    _run_succeed_test(
        _create_unknown_origin_unknown_identity_shared_clk_cls,
        mip_version,
        msg_type_1,
        msg_type_2,
        muxer_comp_cls,
        dummy_comp_cls,
    )


@pytest.mark.parametrize(
    [
        "create_clk_cls_func_1",
        "create_clk_cls_func_2",
        "mip_version",
        "expected_cause_msg",
    ],
    [
        # No clock class followed by clock class (both MIP versions)
        pytest.param(
            _create_no_clk_cls,
            _create_unix_epoch_origin_clk_cls,
            0,
            "Expecting no clock class, got one",
            id="no-clk-cls-then-clk-cls-mip-0",
        ),
        pytest.param(
            _create_no_clk_cls,
            _create_unix_epoch_origin_clk_cls,
            1,
            "Expecting no clock class, got one",
            id="no-clk-cls-then-clk-cls-mip-1",
        ),
        # MIP 0: Unix epoch origin errors
        pytest.param(
            _create_unix_epoch_origin_clk_cls,
            _create_no_clk_cls,
            0,
            "Expecting a clock class with a Unix epoch origin, got none",
            id="unix-epoch-then-no-clk-cls-mip-0",
        ),
        pytest.param(
            _create_unix_epoch_origin_clk_cls,
            _create_unknown_origin_no_uuid_clk_cls,
            0,
            "Expecting a clock class with a Unix epoch origin, got one with an unknown origin",
            id="unix-epoch-then-unknown-origin-mip-0",
        ),
        # MIP 0: Unknown origin with UUID errors
        pytest.param(
            _create_unknown_origin_uuid_a_clk_cls,
            _create_no_clk_cls,
            0,
            "Expecting a clock class with an unknown origin and a specific UUID, got none",
            id="unknown-origin-uuid-then-no-clk-cls-mip-0",
        ),
        pytest.param(
            _create_unknown_origin_uuid_a_clk_cls,
            _create_unix_epoch_origin_clk_cls,
            0,
            "Expecting a clock class with an unknown origin and a specific UUID, got one with a Unix epoch origin",
            id="unknown-origin-uuid-then-unix-epoch-mip-0",
        ),
        pytest.param(
            _create_unknown_origin_uuid_a_clk_cls,
            _create_unknown_origin_no_uuid_clk_cls,
            0,
            "Expecting a clock class with an unknown origin and a specific UUID, got one without a UUID",
            id="unknown-origin-uuid-then-no-uuid-mip-0",
        ),
        pytest.param(
            _create_unknown_origin_uuid_a_clk_cls,
            _create_unknown_origin_uuid_b_clk_cls,
            0,
            "Expecting a clock class with an unknown origin and a specific UUID, got one with a different UUID",
            id="unknown-origin-uuid-then-different-uuid-mip-0",
        ),
        # MIP 0: Unknown origin without UUID errors
        pytest.param(
            _create_unknown_origin_no_uuid_clk_cls,
            _create_no_clk_cls,
            0,
            "Expecting a clock class, got none",
            id="unknown-origin-no-uuid-then-no-clk-cls-mip-0",
        ),
        pytest.param(
            _create_unknown_origin_no_uuid_clk_cls,
            _create_unknown_origin_no_uuid_clk_cls,
            0,
            "Unexpected clock class",
            id="unknown-origin-no-uuid-then-different-clk-cls-mip-0",
        ),
        # MIP 1: Known origin errors
        pytest.param(
            _create_unix_epoch_origin_clk_cls,
            _create_no_clk_cls,
            1,
            "Expecting a clock class with a known origin, got none",
            id="known-origin-then-no-clk-cls-mip-1",
        ),
        pytest.param(
            _create_unix_epoch_origin_clk_cls,
            _create_unknown_origin_no_identity_clk_cls,
            1,
            "Expecting a clock class with a known origin, got one with an unknown origin",
            id="known-origin-then-unknown-origin-mip-1",
        ),
        # MIP 1: Unknown origin with identity errors
        pytest.param(
            _create_unknown_origin_identity_clk_cls,
            _create_no_clk_cls,
            1,
            "Expecting a clock class with an unknown origin and a specific identity, got none",
            id="unknown-origin-identity-then-no-clk-cls-mip-1",
        ),
        pytest.param(
            _create_unknown_origin_identity_clk_cls,
            _create_unix_epoch_origin_clk_cls,
            1,
            "Expecting a clock class with an unknown origin and a specific identity, got one with a known origin",
            id="unknown-origin-identity-then-known-origin-mip-1",
        ),
        pytest.param(
            _create_unknown_origin_identity_clk_cls,
            _create_unknown_origin_no_identity_clk_cls,
            1,
            "Expecting a clock class with an unknown origin and a specific identity, got one without identity",
            id="unknown-origin-identity-then-no-identity-mip-1",
        ),
        pytest.param(
            _create_unknown_origin_identity_clk_cls,
            _create_unknown_origin_different_identity_clk_cls,
            1,
            "Expecting a clock class with an unknown origin and a specific identity, got one with a different identity",
            id="unknown-origin-identity-then-different-identity-mip-1",
        ),
        # MIP 1: Unknown origin without identity errors
        pytest.param(
            _create_unknown_origin_no_identity_clk_cls,
            _create_no_clk_cls,
            1,
            "Expecting a clock class, got none",
            id="unknown-origin-no-identity-then-no-clk-cls-mip-1",
        ),
        pytest.param(
            _create_unknown_origin_no_identity_clk_cls,
            _create_unknown_origin_no_identity_clk_cls,
            1,
            "Unexpected clock class",
            id="unknown-origin-no-identity-then-different-clk-cls-mip-1",
        ),
    ],
)
@pytest.mark.parametrize(["msg_type_1", "msg_type_2"], _MSG_TYPE_COMBOS)
def test_incompat_clk_classes(
    create_clk_cls_func_1,
    create_clk_cls_func_2,
    mip_version,
    expected_cause_msg,
    msg_type_1,
    msg_type_2,
    muxer_comp_cls,
    dummy_comp_cls,
):
    if _should_skip(
        create_clk_cls_func_1, create_clk_cls_func_2, msg_type_1, msg_type_2
    ):
        pytest.skip("Invalid test combination")

    error = _run_graph(
        create_clk_cls_func_1,
        create_clk_cls_func_2,
        msg_type_1,
        msg_type_2,
        mip_version,
        muxer_comp_cls,
        dummy_comp_cls,
    )

    assert error is not None, "Expected an error but none was raised"
    assert len(error) > 0

    cause = error[0]

    assert cause.message.startswith(
        expected_cause_msg
    ), "Cause message mismatch: expected `{}`, got `{}`".format(
        expected_cause_msg, cause.message
    )

    assert isinstance(cause, bt2._MessageIteratorErrorCause)
    assert cause.component_name == "the-muxer"
