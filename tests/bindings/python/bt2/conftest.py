# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 EfficiOS Inc.

import typing

import pytest

if typing.TYPE_CHECKING:
    import bt2


@pytest.fixture
def stream_beginning_msg() -> "bt2._StreamBeginningMessage":
    import utils

    return utils.get_stream_beginning_message()


@pytest.fixture
def const_stream_beginning_msg() -> "bt2._StreamBeginningMessageConst":
    import utils

    return utils.get_const_stream_beginning_message()


@pytest.fixture
def stream_end_msg() -> "bt2._StreamEndMessage":
    import utils

    return utils.get_stream_end_message()


@pytest.fixture
def pkt_beginning_msg() -> "bt2._PacketBeginningMessage":
    import utils

    return utils.get_packet_beginning_message()


@pytest.fixture
def const_pkt_beginning_msg() -> "bt2._PacketBeginningMessageConst":
    import utils

    return utils.get_const_packet_beginning_message()


@pytest.fixture
def pkt_end_msg() -> "bt2._PacketEndMessage":
    import utils

    return utils.get_packet_end_message()


@pytest.fixture
def ev_msg() -> "bt2._EventMessage":
    import utils

    return utils.get_event_message()


@pytest.fixture
def const_ev_msg() -> "bt2._EventMessageConst":
    import utils

    return utils.get_const_event_message()


# Fresh, default trace class.
@pytest.fixture
def def_tc() -> "bt2._TraceClass":
    import utils

    return utils.get_default_trace_class()
