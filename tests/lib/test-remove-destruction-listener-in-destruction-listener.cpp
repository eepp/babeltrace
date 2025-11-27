/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2019 Efficios, Inc.
 */

/*
 * Test that removing a trace class or trace destruction listener from within
 * a destruction listener of the same object works.
 */

#include <babeltrace2/babeltrace.h>

#include "utils/run-in.hpp"

#define CATCH_CONFIG_MAIN

#include "catch.hpp"

TEST_CASE("Remove destruction listener in destruction listener")
{
    struct ListenerData final
    {
        bool called = false;
        bt_listener_id idToRemove = 0;
    };

    static ListenerData traceClsData1, traceClsData2, traceClsData3, traceClsData4, traceClsData5,
        traceData1, traceData2, traceData3, traceData4, traceData5;

    struct ThisRunIn final : public RunIn
    {
        void onCompInit(const bt2::SelfComponent self) override
        {
            bt_listener_id id;
            const auto traceCls = self.createTraceClass();

            REQUIRE(bt_trace_class_add_destruction_listener(
                        traceCls->libObjPtr(),
                        [](const bt_trace_class *, void *) {
                            traceClsData1.called = true;
                        },
                        nullptr, &id) == BT_TRACE_CLASS_ADD_LISTENER_STATUS_OK);
            traceClsData3.idToRemove = id;

            REQUIRE(bt_trace_class_add_destruction_listener(
                        traceCls->libObjPtr(),
                        [](const bt_trace_class * const tc, void *) {
                            traceClsData2.called = true;

                            /* Remove self */
                            REQUIRE(bt_trace_class_remove_destruction_listener(
                                        tc, traceClsData2.idToRemove) ==
                                    BT_TRACE_CLASS_REMOVE_LISTENER_STATUS_OK);
                        },
                        nullptr, &id) == BT_TRACE_CLASS_ADD_LISTENER_STATUS_OK);
            traceClsData2.idToRemove = id;

            REQUIRE(bt_trace_class_add_destruction_listener(
                        traceCls->libObjPtr(),
                        [](const bt_trace_class * const tc, void *) {
                            traceClsData3.called = true;

                            /* Remove an already called listener */
                            REQUIRE(bt_trace_class_remove_destruction_listener(
                                        tc, traceClsData3.idToRemove) ==
                                    BT_TRACE_CLASS_REMOVE_LISTENER_STATUS_OK);
                        },
                        nullptr, &id) == BT_TRACE_CLASS_ADD_LISTENER_STATUS_OK);

            REQUIRE(bt_trace_class_add_destruction_listener(
                        traceCls->libObjPtr(),
                        [](const bt_trace_class * const tc, void *) {
                            traceClsData4.called = true;

                            /* Remove a not-yet called listener */
                            REQUIRE(bt_trace_class_remove_destruction_listener(
                                        tc, traceClsData4.idToRemove) ==
                                    BT_TRACE_CLASS_REMOVE_LISTENER_STATUS_OK);
                        },
                        nullptr, &id) == BT_TRACE_CLASS_ADD_LISTENER_STATUS_OK);

            REQUIRE(bt_trace_class_add_destruction_listener(
                        traceCls->libObjPtr(),
                        [](const bt_trace_class *, void *) {
                            traceClsData5.called = true;
                        },
                        nullptr, &id) == BT_TRACE_CLASS_ADD_LISTENER_STATUS_OK);
            traceClsData4.idToRemove = id;

            const auto trace = traceCls->instantiate();

            REQUIRE(bt_trace_add_destruction_listener(
                        trace->libObjPtr(),
                        [](const bt_trace *, void *) {
                            traceData1.called = true;
                        },
                        nullptr, &id) == BT_TRACE_ADD_LISTENER_STATUS_OK);
            traceData3.idToRemove = id;

            REQUIRE(bt_trace_add_destruction_listener(
                        trace->libObjPtr(),
                        [](const bt_trace * const t, void *) {
                            traceData2.called = true;

                            /* Remove self */
                            REQUIRE(
                                bt_trace_remove_destruction_listener(t, traceData2.idToRemove) ==
                                BT_TRACE_REMOVE_LISTENER_STATUS_OK);
                        },
                        nullptr, &id) == BT_TRACE_ADD_LISTENER_STATUS_OK);
            traceData2.idToRemove = id;

            REQUIRE(bt_trace_add_destruction_listener(
                        trace->libObjPtr(),
                        [](const bt_trace * const t, void *) {
                            traceData3.called = true;

                            /* Remove an already called listener */
                            REQUIRE(
                                bt_trace_remove_destruction_listener(t, traceData3.idToRemove) ==
                                BT_TRACE_REMOVE_LISTENER_STATUS_OK);
                        },
                        nullptr, &id) == BT_TRACE_ADD_LISTENER_STATUS_OK);

            REQUIRE(bt_trace_add_destruction_listener(
                        trace->libObjPtr(),
                        [](const bt_trace * const t, void *) {
                            traceData4.called = true;

                            /* Remove a not-yet called listener */
                            REQUIRE(
                                bt_trace_remove_destruction_listener(t, traceData4.idToRemove) ==
                                BT_TRACE_REMOVE_LISTENER_STATUS_OK);
                        },
                        nullptr, &id) == BT_TRACE_ADD_LISTENER_STATUS_OK);

            REQUIRE(bt_trace_add_destruction_listener(
                        trace->libObjPtr(),
                        [](const bt_trace *, void *) {
                            traceData5.called = true;
                        },
                        nullptr, &id) == BT_TRACE_ADD_LISTENER_STATUS_OK);
            traceData4.idToRemove = id;
        }
    };

    ThisRunIn thisRunIn;

    runIn(thisRunIn, 0);

    /* Check that the expected trace destruction listeners were called */
    CHECK(traceData1.called);
    CHECK(traceData2.called);
    CHECK(traceData3.called);
    CHECK(traceData4.called);
    CHECK_FALSE(traceData5.called);

    /* Check that the expected TC destruction listeners were called */
    CHECK(traceClsData1.called);
    CHECK(traceClsData2.called);
    CHECK(traceClsData3.called);
    CHECK(traceClsData4.called);
    CHECK_FALSE(traceClsData5.called);
}
