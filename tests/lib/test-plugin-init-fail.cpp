/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2024 EfficiOS, Inc.
 */

#include <babeltrace2/babeltrace.h>

#include "cpp-common/bt2/exc.hpp"
#include "cpp-common/bt2/plugin-load.hpp"
#include "cpp-common/bt2c/c-string-view.hpp"

#define CATCH_CONFIG_MAIN

#include "catch.hpp"

TEST_CASE("bt2::findAllPluginsFromDir() fails on load error")
{
    REQUIRE_THROWS_AS(bt2::findAllPluginsFromDir(PLUGIN_DIR, false, true), bt2::Error);

    const auto error = bt_current_thread_take_error();

    REQUIRE(error);

    /*
     * The last error cause must be the one which the initialization
     * function of our plugin appended.
     */
    CHECK(bt2c::CStringView {bt_error_cause_get_message(
              bt_error_borrow_cause_by_index(error, 0))} == "This is the error message");
    bt_error_release(error);
}

TEST_CASE("bt2::findAllPluginsFromDir() doesn't fail on load error")
{
    CHECK(!bt2::findAllPluginsFromDir(PLUGIN_DIR, false, false));
}
