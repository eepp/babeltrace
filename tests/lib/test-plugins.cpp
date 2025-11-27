/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2017 Philippe Proulx <pproulx@efficios.com>
 */

#include <string>

#include <glib.h>

#include <babeltrace2/babeltrace.h>

#include "cpp-common/bt2/exc.hpp"
#include "cpp-common/bt2/graph.hpp"
#include "cpp-common/bt2/plugin-load.hpp"
#include "cpp-common/bt2/query-executor.hpp"
#include "cpp-common/bt2/value.hpp"
#include "cpp-common/bt2c/call.hpp"
#include "cpp-common/bt2c/fmt.hpp" /* IWYU pragma: keep */
#include "cpp-common/vendor/fmt/core.h"

#define CATCH_CONFIG_MAIN

#include "catch.hpp"

#define NON_EXISTING_PATH "/this/hopefully/does/not/exist/5bc75f8d-0dba-4043-a509-d7984b97e42b.so"

namespace {

int intEnvVar(const char * const name)
{
    if (const auto val = getenv(name)) {
        return atoi(val);
    }

    return -1;
}

std::string testPluginPath(const char * const plugin_name)
{
    return fmt::format("{}" G_DIR_SEPARATOR_S "plugin-{}." G_MODULE_SUFFIX, PLUGINS_DIR,
                       plugin_name);
}

} /* namespace */

TEST_CASE("Minimal plugin")
{
    g_setenv("BT_TEST_PLUGIN_INITIALIZE_CALLED", "0", 1);
    g_setenv("BT_TEST_PLUGIN_FINALIZE_CALLED", "0", 1);

    {
        const auto minimalPath = testPluginPath("minimal");
        const auto plugins = bt2::findAllPluginsFromFile(minimalPath, false);

        REQUIRE(plugins);
        CHECK(intEnvVar("BT_TEST_PLUGIN_INITIALIZE_CALLED") == 1);
        REQUIRE(plugins->length() == 1);

        const auto plugin = (*plugins)[0];

        CHECK(plugin->name() == "test_minimal");
        CHECK(plugin->description() == "Minimal Babeltrace plugin with no component classes");
        CHECK_FALSE(plugin->version().has_value());
        CHECK(plugin->author() == "Janine Sutto");
        CHECK(plugin->license() == "Beerware");
        CHECK(plugin->path() == minimalPath);
        CHECK(plugin->sourceComponentClasses().length() == 0);
        CHECK(plugin->filterComponentClasses().length() == 0);
        CHECK(plugin->sinkComponentClasses().length() == 0);
        CHECK(intEnvVar("BT_TEST_PLUGIN_FINALIZE_CALLED") == 0);
    }

    CHECK(intEnvVar("BT_TEST_PLUGIN_FINALIZE_CALLED") == 1);
}

class SfsPluginFixture
{
protected:
    bt2::ConstPlugin _plugin()
    {
        REQUIRE((_mPlugins && _mPlugins->length() == 1));
        return *(*_mPlugins)[0];
    }

    bt2::ConstPluginSet::Shared _mPlugins =
        bt2::findAllPluginsFromFile(testPluginPath("sfs"), false);
};

TEST_CASE_METHOD(SfsPluginFixture, "sfs plugin: plugin set contains one plugin")
{
    REQUIRE(_mPlugins);
    CHECK(_mPlugins->length() == 1);
}

TEST_CASE_METHOD(SfsPluginFixture, "sfs plugin: expected version")
{
    const auto version = this->_plugin().version();

    REQUIRE(version.has_value());
    CHECK(version->major() == 1);
    CHECK(version->minor() == 2);
    CHECK(version->patch() == 3);
    CHECK(version->extra() == "yes");
}

TEST_CASE_METHOD(SfsPluginFixture, "sfs plugin: expected component class counts")
{
    CHECK(this->_plugin().sourceComponentClasses().length() == 1);
    CHECK(this->_plugin().filterComponentClasses().length() == 1);
    CHECK(this->_plugin().sinkComponentClasses().length() == 1);
}

TEST_CASE_METHOD(SfsPluginFixture, "sfs plugin: expected source component class")
{
    const auto sourceCompCls = this->_plugin().sourceComponentClasses()["source"];

    CHECK(sourceCompCls);
}

TEST_CASE_METHOD(SfsPluginFixture, "sfs plugin: expected sink component class help")
{
    const auto sinkCompCls = this->_plugin().sinkComponentClasses()["sink"];

    REQUIRE(sinkCompCls);
    CHECK(sinkCompCls->help() ==
          "Bacon ipsum dolor amet strip steak cupim pastrami venison shoulder.\n"
          "Prosciutto beef ribs flank meatloaf pancetta brisket kielbasa drumstick\n"
          "venison tenderloin cow tail. Beef short loin shoulder meatball, sirloin\n"
          "ground round brisket salami cupim pork bresaola turkey bacon boudin.\n");
}

TEST_CASE_METHOD(SfsPluginFixture, "sfs plugin: expected filter component class")
{
    CHECK(this->_plugin().filterComponentClasses()["filter"]);
}

TEST_CASE_METHOD(SfsPluginFixture, "sfs plugin: expected query object")
{
    const auto filterCompCls = this->_plugin().filterComponentClasses()["filter"];

    REQUIRE(filterCompCls);

    const auto params = bt2::createValue(INT64_C(23));
    const auto results =
        bt2::QueryExecutor::create(*filterCompCls, "get-something", *params)->query();

    REQUIRE(results);
    REQUIRE(results->isArray());
    REQUIRE(results->asArray().length() == 2);

    CHECK(results->asArray()[0].asString().value() == "get-something");
    CHECK(results->asArray()[1] == *params);
}

TEST_CASE_METHOD(SfsPluginFixture, "sfs plugin: add sink component to graph")
{
    const auto sinkCompCls = this->_plugin().sinkComponentClasses()["sink"];

    REQUIRE(sinkCompCls);

    const auto graph = bt2::Graph::create(0);
    const auto sinkComponent = graph->addComponent(*sinkCompCls, "the-sink");

    CHECK(sinkComponent.name() == "the-sink");
}

TEST_CASE("bt2::findAllPluginsFromDir() with nonexistent path")
{
    CHECK(bt2c::call([] {
        try {
            bt2::findAllPluginsFromDir(NON_EXISTING_PATH, BT_FALSE, BT_FALSE);
            return false;
        } catch (const bt2::Error&) {
            bt_current_thread_clear_error();
            return true;
        }
    }));
}

TEST_CASE("bt2::findAllPluginsFromDir() with valid path")
{
    const auto plugins = bt2::findAllPluginsFromDir(PLUGINS_DIR, BT_FALSE, BT_FALSE);

    REQUIRE(plugins);

    /* 2 or 4, if `.la` files are considered or not */
    CHECK((plugins->length() == 2 || plugins->length() == 4));
}

TEST_CASE("bt2::findPlugin() with unknown plugin name")
{
    CHECK_FALSE(bt2::findPlugin(NON_EXISTING_PATH, true, false, false, false, false));
}

TEST_CASE("bt2::findPlugin() finds a plugin using `BABELTRACE_PLUGIN_PATH`")
{
    g_setenv("BABELTRACE_PLUGIN_PATH",
             fmt::format("{}" G_SEARCHPATH_SEPARATOR_S G_DIR_SEPARATOR_S
                         "ec1d09e5-696c-442e-b1c3-f9c6cf7f5958" G_SEARCHPATH_SEPARATOR_S
                             G_SEARCHPATH_SEPARATOR_S G_SEARCHPATH_SEPARATOR_S
                         "{}" G_SEARCHPATH_SEPARATOR_S
                         "8db46494-a398-466a-9649-c765ae077629" G_SEARCHPATH_SEPARATOR_S,
                         NON_EXISTING_PATH, PLUGINS_DIR)
                 .c_str(),
             1);

    const auto plugin = bt2::findPlugin("test_minimal", true, false, false, false, false);

    REQUIRE(plugin);
    CHECK(plugin->author() == "Janine Sutto");
}
