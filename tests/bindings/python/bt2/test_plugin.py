# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019-2026 EfficiOS Inc.

import pathlib

import bt2
import pytest
import bt_tests_utils as btu


@pytest.fixture(scope="module")
def plugins_path(build_root_dir: pathlib.Path):
    return build_root_dir / "src/plugins"


class TestSet:
    def test_create(self, plugins_path):
        pset = bt2.find_plugins_in_path(str(plugins_path))
        assert len(pset) >= 3

    def test_getitem(self, plugins_path):
        pset = bt2.find_plugins_in_path(str(plugins_path))
        assert pset[0].path.startswith(str(plugins_path))

    def test_iter(self, plugins_path):
        names = {plugin.name for plugin in bt2.find_plugins_in_path(str(plugins_path))}
        assert "ctf" in names
        assert "utils" in names
        assert "text" in names


class TestFind:
    def test_nonexistent_dir(self):
        with pytest.raises(ValueError):
            bt2.find_plugins_in_path(
                "/this/does/not/exist/246703df-cb85-46d5-8406-5e8dc4a88b41"
            )

    def test_none_existing_dir(self, plugins_path):
        plugins = bt2.find_plugins_in_path(str(plugins_path), recurse=False)
        assert plugins is None

    def test_dir(self, plugins_path):
        pset = bt2.find_plugins_in_path(str(plugins_path))
        assert len(pset) >= 3

    def test_file(self, plugins_path, os_type):
        if os_type in (btu.OsType.CYGWIN, btu.OsType.MINGW):
            extension = "dll"
        else:
            extension = "so"

        plugin_name = "babeltrace-plugin-utils.{}".format(extension)
        path = plugins_path / "utils/.libs" / plugin_name
        pset = bt2.find_plugins_in_path(str(path))
        assert len(pset) == 1

    def test_find_plugin_none(self):
        plugin = bt2.find_plugin(
            "this-does-not-exist-246703df-cb85-46d5-8406-5e8dc4a88b41"
        )
        assert plugin is None

    def test_find_plugin_existing(self):
        plugin = bt2.find_plugin("ctf")
        assert plugin is not None


class TestProps:
    @pytest.fixture(scope="class")
    def ctf_plugin(self):
        return bt2.find_plugin("ctf")

    def test_name(self, ctf_plugin):
        assert ctf_plugin.name == "ctf"

    def test_path(self, ctf_plugin, plugins_path):
        plugin_path = pathlib.Path(ctf_plugin.path).resolve()
        assert str(plugin_path).startswith(str(plugins_path.resolve()))

    def test_author(self, ctf_plugin):
        assert ctf_plugin.author == "EfficiOS <https://www.efficios.com/>"

    def test_license(self, ctf_plugin):
        assert ctf_plugin.license == "MIT"

    def test_description(self, ctf_plugin):
        assert ctf_plugin.description == "CTF input and output"

    def test_version(self, ctf_plugin):
        assert ctf_plugin.version is not None
        assert ctf_plugin.version.major == 2
        assert ctf_plugin.version.minor == 0
        assert ctf_plugin.version.patch == 0
        assert ctf_plugin.version.extra is None

    def test_src_comp_classes_len(self, ctf_plugin):
        assert len(ctf_plugin.source_component_classes) == 2

    def test_src_comp_classes_getitem(self, ctf_plugin):
        assert ctf_plugin.source_component_classes["fs"].name == "fs"

    def test_src_comp_classes_getitem_invalid(self, ctf_plugin):
        with pytest.raises(KeyError):
            ctf_plugin.source_component_classes["lol"]

    def test_src_comp_classes_iter(self, ctf_plugin):
        plugins = {}

        for cc_name, cc in ctf_plugin.source_component_classes.items():
            plugins[cc_name] = cc

        assert "fs" in plugins
        assert "lttng-live" in plugins
        assert plugins["fs"].name == "fs"
        assert plugins["lttng-live"].name == "lttng-live"

    def test_filter_comp_classes_len(self):
        plugin = bt2.find_plugin("utils", find_in_user_dir=False, find_in_sys_dir=False)
        assert len(plugin.filter_component_classes) == 2

    def test_sink_comp_classes_len(self, ctf_plugin):
        assert len(ctf_plugin.sink_component_classes) == 1
