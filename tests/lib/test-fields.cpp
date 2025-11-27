/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2023 EfficiOS Inc.
 */

#include <functional>

#include "utils/run-in.hpp"

#define CATCH_CONFIG_MAIN

#include "catch.hpp"

namespace {

class StringFieldRunIn final : public RunIn
{
public:
    explicit StringFieldRunIn(std::function<void(bt2::StringField)> testFn) :
        _mTestFn {std::move(testFn)}
    {
    }

    void onMsgIterInit(const bt2::SelfMessageIterator self) override
    {
        const auto traceCls = self.component().createTraceClass();
        const auto streamCls = traceCls->createStreamClass();
        const auto eventCls = streamCls->createEventClass();

        {
            const auto payloadCls = traceCls->createStructureFieldClass();

            payloadCls->appendMember("str", *traceCls->createStringFieldClass());
            eventCls->payloadFieldClass(*payloadCls);
        }

        const auto trace = traceCls->instantiate();
        const auto stream = streamCls->instantiate(*trace);
        const auto msg = self.createEventMessage(*eventCls, *stream);
        const auto field = (*msg->event().payloadField())["str"]->asString();

        _mTestFn(field);
    }

private:
    std::function<void(bt2::StringField)> _mTestFn;
};

class StringFieldFixture
{
protected:
    void _runWithStringField(std::function<void(bt2::StringField)> testFn)
    {
        StringFieldRunIn fieldRunIn {std::move(testFn)};

        runIn(fieldRunIn, 0);
    }
};

} /* namespace */

TEST_CASE_METHOD(StringFieldFixture, "String field `clear()` clears the value")
{
    _runWithStringField([](const bt2::StringField field) {
        *field = "pomme";
        field.clear();
        CHECK(field.value() == "");
    });
}

TEST_CASE_METHOD(StringFieldFixture, "String field `clear()` sets length to 0")
{
    _runWithStringField([](const bt2::StringField field) {
        *field = "pomme";
        field.clear();
        CHECK(field.length() == 0);
    });
}
