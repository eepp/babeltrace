/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2019 Philippe Proulx <pproulx@efficios.com>
 */

#include <babeltrace2/babeltrace.h>

#include "cpp-common/bt2/component-class-dev.hpp"
#include "cpp-common/bt2/graph.hpp"

#define CATCH_CONFIG_MAIN

#include "catch.hpp"

namespace {

struct TestData final
{
    bt_graph_simple_sink_component_initialize_func_status initStatus;
    bt_graph_simple_sink_component_consume_func_status consumeStatus;
    bool initFuncCalled = false;
    bool consumeFuncCalled = false;
    bool finiFuncCalled = false;
};

bt_graph_simple_sink_component_initialize_func_status
simpleSinkInitFunc(bt_message_iterator * const iter, void * const data)
{
    REQUIRE(iter);
    REQUIRE(data);

    auto& testData = *static_cast<TestData *>(data);

    testData.initFuncCalled = true;
    return testData.initStatus;
}

bt_graph_simple_sink_component_consume_func_status
simpleSinkConsumeFunc(bt_message_iterator * const iter, void * const data)
{
    REQUIRE(iter);
    REQUIRE(data);

    auto& testData = *static_cast<TestData *>(data);

    testData.consumeFuncCalled = true;
    return testData.consumeStatus;
}

void simpleSinkFiniFunc(void * const data)
{
    REQUIRE(data);

    auto& testData = *static_cast<TestData *>(data);

    testData.finiFuncCalled = true;
}

class DummySource;

class DummySourceMsgIter final : public bt2::UserMessageIterator<DummySourceMsgIter, DummySource>
{
public:
    explicit DummySourceMsgIter(const bt2::SelfMessageIterator self,
                                const bt2::SelfMessageIteratorConfiguration,
                                const bt2::SelfComponentOutputPort) :
        bt2::UserMessageIterator<DummySourceMsgIter, DummySource> {self, "DUMMY-SRC-MSG-ITER"}
    {
    }

    void _next(bt2::ConstMessageArray&)
    {
    }
};

class DummySource final : public bt2::UserSourceComponent<DummySource, DummySourceMsgIter>
{
public:
    static constexpr auto name = "dummy-source";

    explicit DummySource(const bt2::SelfSourceComponent self, bt2::ConstMapValue, void *) :
        bt2::UserSourceComponent<DummySource, DummySourceMsgIter> {self, "DUMMY-SRC"}
    {
        this->_addOutputPort("out");
    }
};

class SimpleSinkTestFixture
{
protected:
    explicit SimpleSinkTestFixture(const bool doConnect = true) :
        _graph {bt2::Graph::create(0)},
        _srcComp {_graph->addComponent(*bt2::createComponentClass<DummySource>(), "the-source")}
    {
        this->_addSimpleSink();

        if (doConnect) {
            this->_connectPorts();
        }
    }

    void _addSimpleSink()
    {
        REQUIRE(bt_graph_add_simple_sink_component(_graph->libObjPtr(), "the-sink",
                                                   simpleSinkInitFunc, simpleSinkConsumeFunc,
                                                   simpleSinkFiniFunc, &_testData,
                                                   &_sinkComp) == BT_GRAPH_ADD_COMPONENT_STATUS_OK);
        REQUIRE(_sinkComp);
    }

    void _connectPorts() const
    {
        const auto srcOutPort = _srcComp.outputPorts()["out"];

        REQUIRE(srcOutPort);

        const auto sinkInPort = bt_component_sink_borrow_input_port_by_name_const(_sinkComp, "in");

        REQUIRE(sinkInPort);

        _graph->connectPorts(*srcOutPort, bt2::ConstInputPort {sinkInPort});
    }

    void _runOnce(const bt_graph_simple_sink_component_initialize_func_status initStatus,
                  const bt_graph_simple_sink_component_consume_func_status consumeStatus,
                  const bt_graph_run_once_status expectedStatus)
    {
        _testData.initStatus = initStatus;
        _testData.consumeStatus = consumeStatus;

        const auto status = bt_graph_run_once(_graph->libObjPtr());

        REQUIRE(status == expectedStatus);

        if (status < 0) {
            const auto err = bt_current_thread_take_error();

            REQUIRE(err);
            bt_error_release(err);
        }
    }

    bt2::Graph::Shared _graph;
    bt2::ConstSourceComponent _srcComp;
    const bt_component_sink *_sinkComp = nullptr;
    TestData _testData;
};

class SimpleSinkTestFixtureNoConnect : public SimpleSinkTestFixture
{
protected:
    explicit SimpleSinkTestFixtureNoConnect() : SimpleSinkTestFixture {false}
    {
    }
};

} /* namespace */

TEST_CASE_METHOD(SimpleSinkTestFixtureNoConnect, "Has input port named `in`")
{
    CHECK(bt_component_sink_borrow_input_port_by_name_const(_sinkComp, "in"));
}

TEST_CASE_METHOD(SimpleSinkTestFixture, "Input port is connectable")
{
}

TEST_CASE_METHOD(SimpleSinkTestFixture, "Run once with init OK, consume OK")
{
    this->_runOnce(BT_GRAPH_SIMPLE_SINK_COMPONENT_INITIALIZE_FUNC_STATUS_OK,
                   BT_GRAPH_SIMPLE_SINK_COMPONENT_CONSUME_FUNC_STATUS_OK,
                   BT_GRAPH_RUN_ONCE_STATUS_OK);
    CHECK(_testData.initFuncCalled);
    CHECK(_testData.consumeFuncCalled);
}

TEST_CASE_METHOD(SimpleSinkTestFixture, "Run once with init error")
{
    this->_runOnce(BT_GRAPH_SIMPLE_SINK_COMPONENT_INITIALIZE_FUNC_STATUS_ERROR,
                   BT_GRAPH_SIMPLE_SINK_COMPONENT_CONSUME_FUNC_STATUS_OK,
                   BT_GRAPH_RUN_ONCE_STATUS_ERROR);
}

TEST_CASE_METHOD(SimpleSinkTestFixture, "Run once with init memory error")
{
    this->_runOnce(BT_GRAPH_SIMPLE_SINK_COMPONENT_INITIALIZE_FUNC_STATUS_MEMORY_ERROR,
                   BT_GRAPH_SIMPLE_SINK_COMPONENT_CONSUME_FUNC_STATUS_OK,
                   BT_GRAPH_RUN_ONCE_STATUS_MEMORY_ERROR);
}

TEST_CASE_METHOD(SimpleSinkTestFixture, "Run once with consume error")
{
    this->_runOnce(BT_GRAPH_SIMPLE_SINK_COMPONENT_INITIALIZE_FUNC_STATUS_OK,
                   BT_GRAPH_SIMPLE_SINK_COMPONENT_CONSUME_FUNC_STATUS_ERROR,
                   BT_GRAPH_RUN_ONCE_STATUS_ERROR);
}

TEST_CASE_METHOD(SimpleSinkTestFixture, "Run once with consume memory error")
{
    this->_runOnce(BT_GRAPH_SIMPLE_SINK_COMPONENT_INITIALIZE_FUNC_STATUS_OK,
                   BT_GRAPH_SIMPLE_SINK_COMPONENT_CONSUME_FUNC_STATUS_MEMORY_ERROR,
                   BT_GRAPH_RUN_ONCE_STATUS_MEMORY_ERROR);
}

TEST_CASE_METHOD(SimpleSinkTestFixture, "Run once with consume again")
{
    this->_runOnce(BT_GRAPH_SIMPLE_SINK_COMPONENT_INITIALIZE_FUNC_STATUS_OK,
                   BT_GRAPH_SIMPLE_SINK_COMPONENT_CONSUME_FUNC_STATUS_AGAIN,
                   BT_GRAPH_RUN_ONCE_STATUS_AGAIN);
}

TEST_CASE_METHOD(SimpleSinkTestFixture, "Run once with consume end")
{
    this->_runOnce(BT_GRAPH_SIMPLE_SINK_COMPONENT_INITIALIZE_FUNC_STATUS_OK,
                   BT_GRAPH_SIMPLE_SINK_COMPONENT_CONSUME_FUNC_STATUS_END,
                   BT_GRAPH_RUN_ONCE_STATUS_END);
}

TEST_CASE_METHOD(SimpleSinkTestFixture, "Finalize function called")
{
    this->_runOnce(BT_GRAPH_SIMPLE_SINK_COMPONENT_INITIALIZE_FUNC_STATUS_OK,
                   BT_GRAPH_SIMPLE_SINK_COMPONENT_CONSUME_FUNC_STATUS_END,
                   BT_GRAPH_RUN_ONCE_STATUS_END);
    CHECK_FALSE(_testData.finiFuncCalled);
    _graph.reset();
    CHECK(_testData.finiFuncCalled);
}
