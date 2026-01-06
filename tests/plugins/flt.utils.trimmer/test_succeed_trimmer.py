# SPDX-FileCopyrightText: 2019 Simon Marchi <simon.marchi@efficios.com>
# SPDX-FileCopyrightText: 2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import bt2
import pytest
import bt_tests_utils as btu

# Expected `sink.text.details` outputs organized by
# (`with-stream-msgs-cs`, `with-packet-msgs`) tuple for
# `src.test-trimmer.TheSourceOfAllEvil`, and then by
# (beginning time, end time) tuple for `flt.utils.trimmer`.
_EXPECTED = {
    # With stream message clock snapshots, with packet messages
    (True, True): {
        (
            None,
            None,
        ): """
            [100 10,100,000,000,000] {0 0 0} Stream beginning
            [200 10,200,000,000,000] {0 0 0} Packet beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [900 10,900,000,000,000] {0 0 0} Packet end
            [1000 11,000,000,000,000] {0 0 0} Stream end
        """,
        (
            "50",
            None,
        ): """
            [100 10,100,000,000,000] {0 0 0} Stream beginning
            [200 10,200,000,000,000] {0 0 0} Packet beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [900 10,900,000,000,000] {0 0 0} Packet end
            [1000 11,000,000,000,000] {0 0 0} Stream end
        """,
        (
            "10050",
            None,
        ): """
            [100 10,100,000,000,000] {0 0 0} Stream beginning
            [200 10,200,000,000,000] {0 0 0} Packet beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [900 10,900,000,000,000] {0 0 0} Packet end
            [1000 11,000,000,000,000] {0 0 0} Stream end
        """,
        (
            "10150",
            None,
        ): """
            [150 10,150,000,000,000] {0 0 0} Stream beginning
            [200 10,200,000,000,000] {0 0 0} Packet beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [900 10,900,000,000,000] {0 0 0} Packet end
            [1000 11,000,000,000,000] {0 0 0} Stream end
        """,
        (
            "10250",
            None,
        ): """
            [250 10,250,000,000,000] {0 0 0} Stream beginning
            [250 10,250,000,000,000] {0 0 0} Packet beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [900 10,900,000,000,000] {0 0 0} Packet end
            [1000 11,000,000,000,000] {0 0 0} Stream end
        """,
        (
            "10350",
            None,
        ): """
            [350 10,350,000,000,000] {0 0 0} Stream beginning
            [350 10,350,000,000,000] {0 0 0} Packet beginning
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [900 10,900,000,000,000] {0 0 0} Packet end
            [1000 11,000,000,000,000] {0 0 0} Stream end
        """,
        (
            "10850",
            None,
        ): """
            [850 10,850,000,000,000] {0 0 0} Stream beginning
            [850 10,850,000,000,000] {0 0 0} Packet beginning
            [900 10,900,000,000,000] {0 0 0} Packet end
            [1000 11,000,000,000,000] {0 0 0} Stream end
        """,
        ("11050", None): "",
        (
            None,
            "11050",
        ): """
            [100 10,100,000,000,000] {0 0 0} Stream beginning
            [200 10,200,000,000,000] {0 0 0} Packet beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [900 10,900,000,000,000] {0 0 0} Packet end
            [1000 11,000,000,000,000] {0 0 0} Stream end
        """,
        (
            None,
            "10950",
        ): """
            [100 10,100,000,000,000] {0 0 0} Stream beginning
            [200 10,200,000,000,000] {0 0 0} Packet beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [900 10,900,000,000,000] {0 0 0} Packet end
            [950 10,950,000,000,000] {0 0 0} Stream end
        """,
        (
            None,
            "10450",
        ): """
            [100 10,100,000,000,000] {0 0 0} Stream beginning
            [200 10,200,000,000,000] {0 0 0} Packet beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [450 10,450,000,000,000] {0 0 0} Packet end
            [450 10,450,000,000,000] {0 0 0} Stream end
        """,
        (
            None,
            "10350",
        ): """
            [100 10,100,000,000,000] {0 0 0} Stream beginning
            [200 10,200,000,000,000] {0 0 0} Packet beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [350 10,350,000,000,000] {0 0 0} Packet end
            [350 10,350,000,000,000] {0 0 0} Stream end
        """,
        (
            None,
            "10250",
        ): """
            [100 10,100,000,000,000] {0 0 0} Stream beginning
            [200 10,200,000,000,000] {0 0 0} Packet beginning
            [250 10,250,000,000,000] {0 0 0} Packet end
            [250 10,250,000,000,000] {0 0 0} Stream end
        """,
        (
            None,
            "10150",
        ): """
            [100 10,100,000,000,000] {0 0 0} Stream beginning
            [150 10,150,000,000,000] {0 0 0} Stream end
        """,
        (None, "10050"): "",
        (None, "50"): "",
    },
    # Without stream message clock snapshots, with packet messages
    (False, True): {
        (
            None,
            None,
        ): """
            [Unknown] {0 0 0} Stream beginning
            [200 10,200,000,000,000] {0 0 0} Packet beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [900 10,900,000,000,000] {0 0 0} Packet end
            [Unknown] {0 0 0} Stream end
        """,
        (
            "50",
            None,
        ): """
            [Unknown] {0 0 0} Stream beginning
            [200 10,200,000,000,000] {0 0 0} Packet beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [900 10,900,000,000,000] {0 0 0} Packet end
            [Unknown] {0 0 0} Stream end
        """,
        (
            "10050",
            None,
        ): """
            [Unknown] {0 0 0} Stream beginning
            [200 10,200,000,000,000] {0 0 0} Packet beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [900 10,900,000,000,000] {0 0 0} Packet end
            [Unknown] {0 0 0} Stream end
        """,
        (
            "10150",
            None,
        ): """
            [Unknown] {0 0 0} Stream beginning
            [200 10,200,000,000,000] {0 0 0} Packet beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [900 10,900,000,000,000] {0 0 0} Packet end
            [Unknown] {0 0 0} Stream end
        """,
        (
            "10250",
            None,
        ): """
            [250 10,250,000,000,000] {0 0 0} Stream beginning
            [250 10,250,000,000,000] {0 0 0} Packet beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [900 10,900,000,000,000] {0 0 0} Packet end
            [Unknown] {0 0 0} Stream end
        """,
        (
            "10350",
            None,
        ): """
            [350 10,350,000,000,000] {0 0 0} Stream beginning
            [350 10,350,000,000,000] {0 0 0} Packet beginning
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [900 10,900,000,000,000] {0 0 0} Packet end
            [Unknown] {0 0 0} Stream end
        """,
        (
            "10850",
            None,
        ): """
            [850 10,850,000,000,000] {0 0 0} Stream beginning
            [850 10,850,000,000,000] {0 0 0} Packet beginning
            [900 10,900,000,000,000] {0 0 0} Packet end
            [Unknown] {0 0 0} Stream end
        """,
        ("11050", None): "",
        (
            None,
            "11050",
        ): """
            [Unknown] {0 0 0} Stream beginning
            [200 10,200,000,000,000] {0 0 0} Packet beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [900 10,900,000,000,000] {0 0 0} Packet end
            [Unknown] {0 0 0} Stream end
        """,
        (
            None,
            "10950",
        ): """
            [Unknown] {0 0 0} Stream beginning
            [200 10,200,000,000,000] {0 0 0} Packet beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [900 10,900,000,000,000] {0 0 0} Packet end
            [Unknown] {0 0 0} Stream end
        """,
        (
            None,
            "10450",
        ): """
            [Unknown] {0 0 0} Stream beginning
            [200 10,200,000,000,000] {0 0 0} Packet beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [450 10,450,000,000,000] {0 0 0} Packet end
            [450 10,450,000,000,000] {0 0 0} Stream end
        """,
        (
            None,
            "10350",
        ): """
            [Unknown] {0 0 0} Stream beginning
            [200 10,200,000,000,000] {0 0 0} Packet beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [350 10,350,000,000,000] {0 0 0} Packet end
            [350 10,350,000,000,000] {0 0 0} Stream end
        """,
        (
            None,
            "10250",
        ): """
            [Unknown] {0 0 0} Stream beginning
            [200 10,200,000,000,000] {0 0 0} Packet beginning
            [250 10,250,000,000,000] {0 0 0} Packet end
            [250 10,250,000,000,000] {0 0 0} Stream end
        """,
        (
            None,
            "10150",
        ): """
            [Unknown] {0 0 0} Stream beginning
            [Unknown] {0 0 0} Stream end
        """,
        (
            None,
            "10050",
        ): """
            [Unknown] {0 0 0} Stream beginning
            [Unknown] {0 0 0} Stream end
        """,
        (
            None,
            "50",
        ): """
            [Unknown] {0 0 0} Stream beginning
            [Unknown] {0 0 0} Stream end
        """,
    },
    # With stream message clock snapshots, without packet messages
    (True, False): {
        (
            None,
            None,
        ): """
            [100 10,100,000,000,000] {0 0 0} Stream beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [1000 11,000,000,000,000] {0 0 0} Stream end
        """,
        (
            "50",
            None,
        ): """
            [100 10,100,000,000,000] {0 0 0} Stream beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [1000 11,000,000,000,000] {0 0 0} Stream end
        """,
        (
            "10050",
            None,
        ): """
            [100 10,100,000,000,000] {0 0 0} Stream beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [1000 11,000,000,000,000] {0 0 0} Stream end
        """,
        (
            "10250",
            None,
        ): """
            [250 10,250,000,000,000] {0 0 0} Stream beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [1000 11,000,000,000,000] {0 0 0} Stream end
        """,
        (
            "10350",
            None,
        ): """
            [350 10,350,000,000,000] {0 0 0} Stream beginning
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [1000 11,000,000,000,000] {0 0 0} Stream end
        """,
        (
            "10850",
            None,
        ): """
            [850 10,850,000,000,000] {0 0 0} Stream beginning
            [1000 11,000,000,000,000] {0 0 0} Stream end
        """,
        ("11050", None): "",
        (
            None,
            "11050",
        ): """
            [100 10,100,000,000,000] {0 0 0} Stream beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [1000 11,000,000,000,000] {0 0 0} Stream end
        """,
        (
            None,
            "10950",
        ): """
            [100 10,100,000,000,000] {0 0 0} Stream beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [950 10,950,000,000,000] {0 0 0} Stream end
        """,
        (
            None,
            "10450",
        ): """
            [100 10,100,000,000,000] {0 0 0} Stream beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [450 10,450,000,000,000] {0 0 0} Stream end
        """,
        (
            None,
            "10350",
        ): """
            [100 10,100,000,000,000] {0 0 0} Stream beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [350 10,350,000,000,000] {0 0 0} Stream end
        """,
        (
            None,
            "10250",
        ): """
            [100 10,100,000,000,000] {0 0 0} Stream beginning
            [250 10,250,000,000,000] {0 0 0} Stream end
        """,
        (
            None,
            "10150",
        ): """
            [100 10,100,000,000,000] {0 0 0} Stream beginning
            [150 10,150,000,000,000] {0 0 0} Stream end
        """,
        (None, "10050"): "",
        (None, "50"): "",
    },
    # Without stream message clock snapshots, without packet messages
    (False, False): {
        (
            None,
            None,
        ): """
            [Unknown] {0 0 0} Stream beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [Unknown] {0 0 0} Stream end
        """,
        (
            "50",
            None,
        ): """
            [Unknown] {0 0 0} Stream beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [Unknown] {0 0 0} Stream end
        """,
        (
            "10050",
            None,
        ): """
            [Unknown] {0 0 0} Stream beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [Unknown] {0 0 0} Stream end
        """,
        (
            "10350",
            None,
        ): """
            [350 10,350,000,000,000] {0 0 0} Stream beginning
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [Unknown] {0 0 0} Stream end
        """,
        ("11050", None): "",
        (
            None,
            "11050",
        ): """
            [Unknown] {0 0 0} Stream beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [400 10,400,000,000,000] {0 0 0} Event `event 2` (1)
            [Unknown] {0 0 0} Stream end
        """,
        (
            None,
            "10350",
        ): """
            [Unknown] {0 0 0} Stream beginning
            [300 10,300,000,000,000] {0 0 0} Event `event 1` (0)
            [350 10,350,000,000,000] {0 0 0} Stream end
        """,
        (
            None,
            "10150",
        ): """
            [Unknown] {0 0 0} Stream beginning
            [Unknown] {0 0 0} Stream end
        """,
        (
            None,
            "50",
        ): """
            [Unknown] {0 0 0} Stream beginning
            [Unknown] {0 0 0} Stream end
        """,
    },
}


# IDs for the (`with-stream-msgs-cs`, `with-packet-msgs`) parameter pairs
_STREAM_PACKET_IDS = {
    (True, True): "with-stream-cs-with-packets",
    (True, False): "with-stream-cs-without-packets",
    (False, True): "without-stream-cs-with-packets",
    (False, False): "without-stream-cs-without-packets",
}


@pytest.mark.parametrize(
    "with_stream_msgs_cs,with_packet_msgs,begin_time,end_time",
    [
        pytest.param(
            stream_cs,
            packets,
            begin,
            end,
            id="{}-{}-to-{}".format(
                _STREAM_PACKET_IDS[(stream_cs, packets)], begin, end
            ),
        )
        for (stream_cs, packets), times in _EXPECTED.items()
        for (begin, end) in times.keys()
    ],
)
def test_trimming(
    data_dir,
    trimmer_comp_cls,
    with_stream_msgs_cs,
    with_packet_msgs,
    begin_time,
    end_time,
):
    # Filter component spec (trimmer) if begin or end time is set
    trimmer_params = {}

    if begin_time is not None or end_time is not None:
        if begin_time is not None:
            trimmer_params["begin"] = begin_time

        if end_time is not None:
            trimmer_params["end"] = end_time

    btu.convert_sink_text_details_test(
        bt2.ComponentSpec(
            btu.find_comp_cls_in_path(
                data_dir / "plugins/flt.utils.trimmer",
                "test-trimmer",
                btu.CompClsType.SOURCE,
                "TheSourceOfAllEvil",
            ),
            params={
                "with-stream-msgs-cs": with_stream_msgs_cs,
                "with-packet-msgs": with_packet_msgs,
            },
        ),
        _EXPECTED[(with_stream_msgs_cs, with_packet_msgs)][(begin_time, end_time)],
        bt2.ComponentSpec(
            trimmer_comp_cls,
            params=trimmer_params,
        ),
        details_params={"compact": True, "with-metadata": False},
    )
