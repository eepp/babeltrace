# SPDX-FileCopyrightText: 2019 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import bt2


def test_python_plugin_provider(src_tests_dir):
    plugin_path = (
        src_tests_dir
        / "python-plugin-provider"
        / "bt_plugin_test_python_plugin_provider.py"
    )
    pset = bt2.find_plugins_in_path(str(plugin_path))
    assert len(pset) == 1
    plugin = pset[0]
    assert plugin.name == "sparkling"
    assert plugin.author == "Philippe Proulx"
    assert plugin.description == "A delicious plugin."
    assert plugin.version.major == 1
    assert plugin.version.minor == 2
    assert plugin.version.patch == 3
    assert plugin.version.extra == "EXTRA"
    assert plugin.license == "MIT"
    assert len(plugin.source_component_classes) == 1
    assert len(plugin.filter_component_classes) == 1
    assert len(plugin.sink_component_classes) == 1
    assert plugin.source_component_classes["MySource"].name == "MySource"
    assert plugin.filter_component_classes["MyFilter"].name == "MyFilter"
    assert plugin.sink_component_classes["MySink"].name == "MySink"
