/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2024 EfficiOS, Inc.
 */

#include <string>

#include "cpp-common/bt2c/c-string-view.hpp"

#define CATCH_CONFIG_MAIN

#include "catch.hpp"

namespace {

class CStringViewFixture
{
protected:
    std::string _foo1 {"foo"};
    std::string _foo2 {"foo"};
    std::string _bar {"bar"};
};

} /* namespace */

TEST_CASE_METHOD(CStringViewFixture,
                 "Equality operator of `bt2c::CStringView` with equal `bt2c::CStringView`")
{
    CHECK(_foo1.data() != _foo2.data());
    CHECK(bt2c::CStringView {_foo1} == bt2c::CStringView {_foo2});
}

TEST_CASE_METHOD(CStringViewFixture,
                 "Non-equality operator of `bt2c::CStringView` with different `bt2c::CStringView`")
{
    CHECK(bt2c::CStringView {_foo1} != bt2c::CStringView {_bar});
}

TEST_CASE_METHOD(CStringViewFixture,
                 "Equality operator of `bt2c::CStringView` with equal `const char *`")
{
    CHECK(_foo1.data() != _foo2.c_str());
    CHECK(bt2c::CStringView {_foo1} == _foo2.c_str());
}

TEST_CASE_METHOD(CStringViewFixture,
                 "Non-equality operator of `bt2c::CStringView` with different `const char *`")
{
    CHECK(bt2c::CStringView {_foo1} != _bar.c_str());
}

TEST_CASE_METHOD(CStringViewFixture,
                 "Equality operator of `const char *` with equal `bt2c::CStringView`")
{
    CHECK(_foo1.c_str() != _foo2.data());
    CHECK(_foo1.c_str() == bt2c::CStringView {_foo2});
}

TEST_CASE_METHOD(CStringViewFixture,
                 "Non-equality operator of `const char *` with different `bt2c::CStringView`")
{
    CHECK(_foo1.c_str() != bt2c::CStringView {_bar});
}

TEST_CASE_METHOD(CStringViewFixture,
                 "Equality operator of `bt2c::CStringView` with equal `std::string`")
{
    CHECK(_foo1.data() != _foo2.data());
    CHECK(bt2c::CStringView {_foo1} == _foo2);
}

TEST_CASE_METHOD(CStringViewFixture,
                 "Non-equality operator of `bt2c::CStringView` with different `std::string`")
{
    CHECK(bt2c::CStringView {_foo1} != _bar);
}

TEST_CASE_METHOD(CStringViewFixture,
                 "Equality operator of `std::string` with equal `bt2c::CStringView`")
{
    CHECK(_foo1.data() != _foo2.data());
    CHECK(_foo1 == bt2c::CStringView {_foo2});
}

TEST_CASE_METHOD(CStringViewFixture,
                 "Non-equality operator of `std::string` with different `bt2c::CStringView`")
{
    CHECK(_foo1 != bt2c::CStringView {_bar});
}

TEST_CASE("bt2c::CStringView::startsWith() with matching prefix")
{
    CHECK(bt2c::CStringView {"Moutarde choux"}.startsWith("Moutarde"));
}

TEST_CASE("bt2c::CStringView::startsWith() with non-matching prefix")
{
    CHECK_FALSE(bt2c::CStringView {"Moutarde choux"}.startsWith("Choux"));
}

TEST_CASE("bt2c::CStringView::startsWith() with empty prefix")
{
    CHECK(bt2c::CStringView {"Moutarde choux"}.startsWith(""));
}

TEST_CASE("bt2c::CStringView::startsWith() with full string as prefix")
{
    CHECK(bt2c::CStringView {"Moutarde choux"}.startsWith("Moutarde choux"));
}

TEST_CASE("bt2c::CStringView::startsWith() with prefix longer than string")
{
    CHECK_FALSE(bt2c::CStringView {"Moutarde"}.startsWith("Moutarde choux"));
}

TEST_CASE("bt2c::CStringView::startsWith() with empty string and empty prefix")
{
    CHECK(bt2c::CStringView {""}.startsWith(""));
}
