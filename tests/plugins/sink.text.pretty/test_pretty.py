# SPDX-FileCopyrightText: 2020 EfficiOS, Inc.
# SPDX-License-Identifier: GPL-2.0-only

import bt2
import pytest


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
