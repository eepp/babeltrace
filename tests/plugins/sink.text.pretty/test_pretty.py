# SPDX-FileCopyrightText: 2020 EfficiOS, Inc.
# SPDX-License-Identifier: GPL-2.0-only

import pathlib
import tempfile

import bt2
import pytest
import bt_tests_utils as btu


# Tests that the component returns an error if the graph is configured
# while the input port of the component is left disconnected.
def test_unconnected_port_raises(pretty_comp_cls):
    graph = bt2.Graph()
    graph.add_component(pretty_comp_cls, "snk")

    with pytest.raises(bt2._Error) as exc_info:
        graph.run()

    assert (
        'Single input port is not connected: port-name="in"'
        in exc_info.value[0].message
    )


def test_basic_bit_array_fields_with_flags(ctf_traces_dir, data_dir, pretty_comp_cls):
    with tempfile.TemporaryDirectory(prefix="bt-test-pretty-") as temp_dir:
        temp_path = pathlib.Path(temp_dir) / "output.txt"

        btu.convert(
            ctf_traces_dir / "2/succeed/fl-bm",
            btu.SinkComponentSpec(
                pretty_comp_cls,
                {"path": str(temp_path)},
            ),
        )

        expected = (data_dir / "plugins/sink.text.pretty/fl-bm-ctf2.expect").read_text()
        assert temp_path.read_text() == expected
