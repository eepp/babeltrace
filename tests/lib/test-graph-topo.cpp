/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2017 Philippe Proulx <pproulx@efficios.com>
 */

#include <vector>

#include <babeltrace2/babeltrace.h>

#include "cpp-common/bt2/component-class-dev.hpp"
#include "cpp-common/bt2/component-port.hpp"
#include "cpp-common/bt2/graph.hpp"

#define CATCH_CONFIG_MAIN

#include "catch.hpp"

namespace {

enum class CurrentTest
{
    Simple,
    SrcPortConnectedError,
    SinkPortConnectedError,
    SrcAddsPortInPortConnected,
};

CurrentTest currentTest;

enum class EventType
{
    SrcCompOutputPortConnected,
    SinkCompInputPortConnected,
    GraphSrcOutputPortAdded,
    GraphSinkInputPortAdded,
};

struct Event final
{
    EventType type;
    const bt_component *comp;
    const bt_port *selfPort;
    const bt_port *otherPort;

    static Event createSrcCompOutputPortConnected(const bt2::ConstComponent compParam,
                                                  const bt2::ConstOutputPort selfPortParam,
                                                  const bt2::ConstInputPort otherPortParam)
    {
        return Event {EventType::SrcCompOutputPortConnected, compParam.libObjPtr(),
                      bt_port_output_as_port_const(selfPortParam.libObjPtr()),
                      bt_port_input_as_port_const(otherPortParam.libObjPtr())};
    }

    static Event createSinkCompInputPortConnected(const bt2::ConstComponent compParam,
                                                  const bt2::ConstInputPort selfPortParam,
                                                  const bt2::ConstOutputPort otherPortParam)
    {
        return Event {EventType::SinkCompInputPortConnected, compParam.libObjPtr(),
                      bt_port_input_as_port_const(selfPortParam.libObjPtr()),
                      bt_port_output_as_port_const(otherPortParam.libObjPtr())};
    }

    static Event createGraphSrcOutputPortAdded(const bt2::ConstComponent compParam,
                                               const bt2::ConstOutputPort portParam)
    {
        return Event {EventType::GraphSrcOutputPortAdded, compParam.libObjPtr(),
                      bt_port_output_as_port_const(portParam.libObjPtr()), nullptr};
    }

    static Event createGraphSinkInputPortAdded(const bt2::ConstComponent compParam,
                                               const bt2::ConstInputPort portParam)
    {
        return Event {EventType::GraphSinkInputPortAdded, compParam.libObjPtr(),
                      bt_port_input_as_port_const(portParam.libObjPtr()), nullptr};
    }

    bool operator==(const Event& other) const noexcept
    {
        if (type != other.type) {
            return false;
        }

        switch (type) {
        case EventType::SrcCompOutputPortConnected:
        case EventType::SinkCompInputPortConnected:
            return comp == other.comp && selfPort == other.selfPort && otherPort == other.otherPort;

        case EventType::GraphSrcOutputPortAdded:
        case EventType::GraphSinkInputPortAdded:
            return comp == other.comp && selfPort == other.selfPort;
        }

        return false;
    }
};

std::vector<Event> events;

class TestSource;

class TestSourceMsgIter final : public bt2::UserMessageIterator<TestSourceMsgIter, TestSource>
{
public:
    explicit TestSourceMsgIter(const bt2::SelfMessageIterator self,
                               const bt2::SelfMessageIteratorConfiguration,
                               const bt2::SelfComponentOutputPort) :
        bt2::UserMessageIterator<TestSourceMsgIter, TestSource> {self, "TEST-SRC-MSG-ITER"}
    {
    }

    void _next(bt2::ConstMessageArray&)
    {
        throw bt2::Error {};
    }
};

class TestSource final : public bt2::UserSourceComponent<TestSource, TestSourceMsgIter>
{
public:
    static constexpr const char *name = "test-source";

    explicit TestSource(const bt2::SelfSourceComponent selfComp, bt2::ConstMapValue, void *) :
        bt2::UserSourceComponent<TestSource, TestSourceMsgIter> {selfComp, "TEST-SRC"}
    {
        this->_addOutputPort("out");
    }

    void _outputPortConnected(const bt2::SelfComponentOutputPort selfPort,
                              const bt2::ConstInputPort otherPort)
    {
        events.push_back(Event::createSrcCompOutputPortConnected(
            selfPort.component().asConstComponent(), selfPort.asConstPort(), otherPort));

        switch (currentTest) {
        case CurrentTest::SrcAddsPortInPortConnected:
            this->_addOutputPort("hello");
            break;

        case CurrentTest::SrcPortConnectedError:
            throw bt2::Error {};

        default:
            break;
        }
    }
};

class TestSink final : public bt2::UserSinkComponent<TestSink>
{
public:
    static constexpr const char *name = "test-sink";

    explicit TestSink(const bt2::SelfSinkComponent selfComp, bt2::ConstMapValue, void *) :
        bt2::UserSinkComponent<TestSink> {selfComp, "TEST-SINK"}
    {
        this->_addInputPort("in");
    }

    bool _consume()
    {
        return false;
    }

    void _inputPortConnected(const bt2::SelfComponentInputPort selfPort,
                             const bt2::ConstOutputPort otherPort)
    {
        events.push_back(Event::createSinkCompInputPortConnected(
            selfPort.component().asConstComponent(), selfPort.asConstPort(), otherPort));

        if (currentTest == CurrentTest::SinkPortConnectedError) {
            throw bt2::Error {};
        }
    }
};

bool hasEvent(const Event& event)
{
    for (const auto& ev : events) {
        if (ev == event) {
            return true;
        }
    }

    return false;
}

std::size_t eventPos(const Event& event)
{
    for (std::size_t i = 0; i < events.size(); ++i) {
        if (events[i] == event) {
            return i;
        }
    }

    return SIZE_MAX;
}

bt_graph_listener_func_status graphSrcOutputPortAdded(const bt_component_source * const comp,
                                                      const bt_port_output * const port, void *)
{
    events.push_back(Event::createGraphSrcOutputPortAdded(bt2::ConstSourceComponent {comp},
                                                          bt2::ConstOutputPort {port}));
    return BT_GRAPH_LISTENER_FUNC_STATUS_OK;
}

bt_graph_listener_func_status graphSinkInputPortAdded(const bt_component_sink * const comp,
                                                      const bt_port_input * const port, void *)
{
    events.push_back(Event::createGraphSinkInputPortAdded(bt2::ConstSinkComponent {comp},
                                                          bt2::ConstInputPort {port}));
    return BT_GRAPH_LISTENER_FUNC_STATUS_OK;
}

class GraphTopoFixture
{
protected:
    explicit GraphTopoFixture()
    {
        events.clear();
    }

    bt2::Graph::Shared _createGraph()
    {
        auto graph = bt2::Graph::create(0);

        REQUIRE(bt_graph_add_source_component_output_port_added_listener(
                    graph->libObjPtr(), graphSrcOutputPortAdded, nullptr, nullptr) >= 0);
        REQUIRE(bt_graph_add_sink_component_input_port_added_listener(
                    graph->libObjPtr(), graphSinkInputPortAdded, nullptr, nullptr) >= 0);
        return graph;
    }

    bt2::ConstSourceComponent _createSrc(const bt2::Graph graph)
    {
        return graph.addComponent<TestSource>("src-comp");
    }

    bt2::ConstSinkComponent _createSink(const bt2::Graph graph)
    {
        return graph.addComponent<TestSink>("sink-comp");
    }
};

} /* namespace */

TEST_CASE_METHOD(GraphTopoFixture, "Empty graph")
{
    const auto graph = this->_createGraph();

    CHECK(events.empty());
}

TEST_CASE_METHOD(GraphTopoFixture, "Simple")
{
    currentTest = CurrentTest::Simple;

    const auto graph = this->_createGraph();
    const auto src = this->_createSrc(*graph);
    const auto sink = this->_createSink(*graph);
    const auto srcDefPort = *src.outputPorts()["out"];
    const auto sinkDefPort = *sink.inputPorts()["in"];

    graph->connectPorts(srcDefPort, sinkDefPort);
    CHECK(events.size() == 4);
    CHECK(hasEvent(Event::createGraphSrcOutputPortAdded(src, srcDefPort)));
    CHECK(hasEvent(Event::createGraphSinkInputPortAdded(sink, sinkDefPort)));
    CHECK(hasEvent(Event::createSrcCompOutputPortConnected(src, srcDefPort, sinkDefPort)));
    CHECK(hasEvent(Event::createSinkCompInputPortConnected(sink, sinkDefPort, srcDefPort)));
}

TEST_CASE_METHOD(GraphTopoFixture, "Source port connected error")
{
    currentTest = CurrentTest::SrcPortConnectedError;

    const auto graph = this->_createGraph();
    const auto src = this->_createSrc(*graph);
    const auto sink = this->_createSink(*graph);
    const auto srcDefPort = *src.outputPorts()["out"];
    const auto sinkDefPort = *sink.inputPorts()["in"];

    CHECK_THROWS_AS(graph->connectPorts(srcDefPort, sinkDefPort), bt2::Error);
    bt_current_thread_clear_error();
    CHECK(events.size() == 3);
    CHECK(hasEvent(Event::createGraphSrcOutputPortAdded(src, srcDefPort)));
    CHECK(hasEvent(Event::createGraphSinkInputPortAdded(sink, sinkDefPort)));
    CHECK(hasEvent(Event::createSrcCompOutputPortConnected(src, srcDefPort, sinkDefPort)));
}

TEST_CASE_METHOD(GraphTopoFixture, "Sink port connected error")
{
    currentTest = CurrentTest::SinkPortConnectedError;

    const auto graph = this->_createGraph();
    const auto src = this->_createSrc(*graph);
    const auto sink = this->_createSink(*graph);
    const auto srcDefPort = *src.outputPorts()["out"];
    const auto sinkDefPort = *sink.inputPorts()["in"];

    CHECK_THROWS_AS(graph->connectPorts(srcDefPort, sinkDefPort), bt2::Error);
    bt_current_thread_clear_error();
    CHECK(events.size() == 4);
    CHECK(hasEvent(Event::createGraphSrcOutputPortAdded(src, srcDefPort)));
    CHECK(hasEvent(Event::createGraphSinkInputPortAdded(sink, sinkDefPort)));
    CHECK(hasEvent(Event::createSrcCompOutputPortConnected(src, srcDefPort, sinkDefPort)));
    CHECK(hasEvent(Event::createSinkCompInputPortConnected(sink, sinkDefPort, srcDefPort)));
}

TEST_CASE_METHOD(GraphTopoFixture, "Source adds port in port connected")
{
    currentTest = CurrentTest::SrcAddsPortInPortConnected;

    const auto graph = this->_createGraph();
    const auto src = this->_createSrc(*graph);
    const auto sink = this->_createSink(*graph);
    const auto srcDefPort = *src.outputPorts()["out"];
    const auto sinkDefPort = *sink.inputPorts()["in"];

    graph->connectPorts(srcDefPort, sinkDefPort);
    CHECK(events.size() == 5);
    CHECK(hasEvent(Event::createGraphSrcOutputPortAdded(src, srcDefPort)));
    CHECK(hasEvent(Event::createGraphSinkInputPortAdded(sink, sinkDefPort)));

    const auto srcPortConnectedEvent =
        Event::createSrcCompOutputPortConnected(src, srcDefPort, sinkDefPort);

    CHECK(hasEvent(srcPortConnectedEvent));

    const auto graphPortAddedSrcEvent =
        Event::createGraphSrcOutputPortAdded(src, *src.outputPorts()["hello"]);

    CHECK(hasEvent(graphPortAddedSrcEvent));
    CHECK(hasEvent(Event::createSinkCompInputPortConnected(sink, sinkDefPort, srcDefPort)));
    CHECK(eventPos(srcPortConnectedEvent) < eventPos(graphPortAddedSrcEvent));
}
