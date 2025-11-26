/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2024 EfficiOS, Inc.
 */

#include "cpp-common/bt2c/uuid.hpp"
#include "cpp-common/vendor/fmt/format.h"

#define CATCH_CONFIG_MAIN

#include "catch.hpp"

namespace {

class UuidFixture
{
protected:
    static const char *_uuidStr() noexcept
    {
        return "c2281e4a-699b-4b78-903f-2f8407fe2b77";
    }

    bt2c::Uuid _mUuid {_uuidStr()};
    bt2c::UuidView _mUuidView {_mUuid};
};

} /* namespace */

TEST_CASE_METHOD(UuidFixture, "fmt::to_string() works with `bt2c::Uuid`")
{
    CHECK(fmt::to_string(_mUuid) == this->_uuidStr());
}

TEST_CASE_METHOD(UuidFixture, "fmt::to_string() works with `bt2c::UuidView`")
{
    CHECK(fmt::to_string(_mUuidView) == this->_uuidStr());
}

TEST_CASE("Default-constructed `bt2c::Uuid` is nil")
{
    CHECK(bt2c::Uuid {}.isNil());
}

TEST_CASE_METHOD(UuidFixture, "bt2c::Uuid::str() returns expected string")
{
    CHECK(_mUuid.str() == this->_uuidStr());
}

TEST_CASE_METHOD(UuidFixture, "bt2c::UuidView::str() returns expected string")
{
    CHECK(_mUuidView.str() == this->_uuidStr());
}

TEST_CASE_METHOD(UuidFixture, "Subscript operator of `bt2c::Uuid` returns expected bytes")
{
    CHECK(_mUuid[0] == 0xc2);
    CHECK(_mUuid[1] == 0x28);
    CHECK(_mUuid[2] == 0x1e);
    CHECK(_mUuid[3] == 0x4a);
    CHECK(_mUuid[4] == 0x69);
    CHECK(_mUuid[5] == 0x9b);
    CHECK(_mUuid[6] == 0x4b);
    CHECK(_mUuid[7] == 0x78);
    CHECK(_mUuid[8] == 0x90);
    CHECK(_mUuid[9] == 0x3f);
    CHECK(_mUuid[10] == 0x2f);
    CHECK(_mUuid[11] == 0x84);
    CHECK(_mUuid[12] == 0x07);
    CHECK(_mUuid[13] == 0xfe);
    CHECK(_mUuid[14] == 0x2b);
    CHECK(_mUuid[15] == 0x77);
}

TEST_CASE_METHOD(UuidFixture, "Subscript operator of `bt2c::UuidView` returns expected bytes")
{
    CHECK(_mUuidView[0] == 0xc2);
    CHECK(_mUuidView[1] == 0x28);
    CHECK(_mUuidView[2] == 0x1e);
    CHECK(_mUuidView[3] == 0x4a);
    CHECK(_mUuidView[4] == 0x69);
    CHECK(_mUuidView[5] == 0x9b);
    CHECK(_mUuidView[6] == 0x4b);
    CHECK(_mUuidView[7] == 0x78);
    CHECK(_mUuidView[8] == 0x90);
    CHECK(_mUuidView[9] == 0x3f);
    CHECK(_mUuidView[10] == 0x2f);
    CHECK(_mUuidView[11] == 0x84);
    CHECK(_mUuidView[12] == 0x07);
    CHECK(_mUuidView[13] == 0xfe);
    CHECK(_mUuidView[14] == 0x2b);
    CHECK(_mUuidView[15] == 0x77);
}

TEST_CASE("bt2c::Uuid::size() returns 16")
{
    CHECK(bt2c::Uuid::size() == 16);
}

TEST_CASE("bt2c::UuidView::size() returns 16")
{
    CHECK(bt2c::UuidView::size() == 16);
}

TEST_CASE_METHOD(UuidFixture, "Equality operator of `bt2c::Uuid` with equal UUID")
{
    CHECK(_mUuid == bt2c::Uuid {this->_uuidStr()});
}

TEST_CASE_METHOD(UuidFixture, "Equality operator of `bt2c::Uuid` with different UUID")
{
    CHECK_FALSE(_mUuid == bt2c::Uuid {"f8718be6-0037-4cd8-81ec-582f70ee5d08"});
}

TEST_CASE_METHOD(UuidFixture, "Non-equality operator of `bt2c::Uuid` with different UUID")
{
    CHECK(_mUuid != bt2c::Uuid {"f8718be6-0037-4cd8-81ec-582f70ee5d08"});
}

TEST_CASE_METHOD(UuidFixture, "Less-than operator of `bt2c::Uuid`")
{
    const bt2c::Uuid uuid2 {"f8718be6-0037-4cd8-81ec-582f70ee5d08"};

    CHECK(_mUuid < uuid2);
    CHECK_FALSE(uuid2 < _mUuid);
}

TEST_CASE_METHOD(UuidFixture, "Equality operator of `bt2c::UuidView` with equal UUID")
{
    CHECK(_mUuidView == bt2c::UuidView {bt2c::Uuid {this->_uuidStr()}});
}

TEST_CASE_METHOD(UuidFixture, "Non-equality operator of `bt2c::UuidView` with different UUID")
{
    CHECK(_mUuidView != bt2c::UuidView {bt2c::Uuid {"f8718be6-0037-4cd8-81ec-582f70ee5d08"}});
}

TEST_CASE_METHOD(UuidFixture, "Less-than operator of `bt2c::UuidView`")
{
    const bt2c::Uuid uuid2 {"f8718be6-0037-4cd8-81ec-582f70ee5d08"};
    const bt2c::UuidView uuidView2 {uuid2};

    CHECK(_mUuidView < uuidView2);
    CHECK_FALSE(uuidView2 < _mUuidView);
}

TEST_CASE("bt2c::Uuid::generate() generates different UUIDs")
{
    CHECK(bt2c::Uuid::generate() != bt2c::Uuid::generate());
}

TEST_CASE("bt2c::Uuid::generate() generates non-nil UUID")
{
    CHECK_FALSE(bt2c::Uuid::generate().isNil());
}

TEST_CASE_METHOD(UuidFixture, "`bt2c::Uuid` is iterable")
{
    auto it = _mUuid.begin();

    REQUIRE(it != _mUuid.end());
    CHECK(*it == 0xc2);
    ++it;
    REQUIRE(it != _mUuid.end());
    CHECK(*it == 0x28);
}

TEST_CASE_METHOD(UuidFixture, "`bt2c::UuidView` is iterable")
{
    auto it = _mUuidView.begin();

    REQUIRE(it != _mUuidView.end());
    CHECK(*it == 0xc2);
    ++it;
    REQUIRE(it != _mUuidView.end());
    CHECK(*it == 0x28);
}

TEST_CASE_METHOD(UuidFixture, "bt2c::Uuid::data() returns non-null pointer")
{
    REQUIRE(_mUuid.data());
    CHECK(_mUuid.data()[0] == 0xc2);
    CHECK(_mUuid.data()[15] == 0x77);
}

TEST_CASE_METHOD(UuidFixture, "bt2c::UuidView::data() returns non-null pointer")
{
    REQUIRE(_mUuidView.data());
    CHECK(_mUuidView.data()[0] == 0xc2);
    CHECK(_mUuidView.data()[15] == 0x77);
}

TEST_CASE("bt2c::Uuid::isValidUuidStr() with valid string")
{
    CHECK(bt2c::Uuid::isValidUuidStr("c2281e4a-699b-4b78-903f-2f8407fe2b77"));
}

TEST_CASE("bt2c::Uuid::isValidUuidStr() with invalid string")
{
    CHECK_FALSE(bt2c::Uuid::isValidUuidStr("meow mix"));
    CHECK_FALSE(bt2c::Uuid::isValidUuidStr("c2281e4a-699b-4b78-903f"));
    CHECK_FALSE(bt2c::Uuid::isValidUuidStr(""));
}

TEST_CASE_METHOD(UuidFixture, "`bt2c::Uuid` to `bt2c::UuidView` conversion")
{
    const bt2c::UuidView view = _mUuid;

    CHECK(view == _mUuidView);
}

TEST_CASE_METHOD(UuidFixture, "`bt2c::UuidView` to `bt2c::Uuid` conversion")
{
    const bt2c::Uuid uuid = _mUuidView;

    CHECK(uuid == _mUuid);
}

TEST_CASE_METHOD(UuidFixture, "`bt2c::Uuid` constructed from raw bytes")
{
    static const std::uint8_t bytes[] = {0xc2, 0x28, 0x1e, 0x4a, 0x69, 0x9b, 0x4b, 0x78,
                                         0x90, 0x3f, 0x2f, 0x84, 0x07, 0xfe, 0x2b, 0x77};

    CHECK(bt2c::Uuid {bytes} == _mUuid);
}

TEST_CASE_METHOD(UuidFixture, "`bt2c::UuidView` constructed from raw bytes")
{
    static const std::uint8_t bytes[] = {0xc2, 0x28, 0x1e, 0x4a, 0x69, 0x9b, 0x4b, 0x78,
                                         0x90, 0x3f, 0x2f, 0x84, 0x07, 0xfe, 0x2b, 0x77};

    CHECK(bt2c::UuidView {bytes} == _mUuidView);
}

TEST_CASE("bt2c::UuidView::isNil() with nil UUID")
{
    CHECK(bt2c::UuidView {bt2c::Uuid {}}.isNil());
}

TEST_CASE("bt2c::UuidView::isNil() with non-nil UUID")
{
    CHECK_FALSE(bt2c::UuidView {bt2c::Uuid {"c2281e4a-699b-4b78-903f-2f8407fe2b77"}}.isNil());
}

TEST_CASE("`bt2c::Uuid` copy construction")
{
    const bt2c::Uuid uuid {"c2281e4a-699b-4b78-903f-2f8407fe2b77"};

    CHECK(bt2c::Uuid {uuid} == uuid);
}

TEST_CASE("`bt2c::Uuid` copy assignment")
{
    const bt2c::Uuid uuid {"c2281e4a-699b-4b78-903f-2f8407fe2b77"};
    bt2c::Uuid copy;

    copy = uuid;
    CHECK(copy == uuid);
}

TEST_CASE("`bt2c::UuidView` copy construction")
{
    const bt2c::Uuid uuid {"c2281e4a-699b-4b78-903f-2f8407fe2b77"};
    const bt2c::UuidView view {uuid};

    CHECK(bt2c::UuidView {view} == view);
}

TEST_CASE("`bt2c::UuidView` copy assignment")
{
    const bt2c::Uuid uuid1 {"c2281e4a-699b-4b78-903f-2f8407fe2b77"};
    const bt2c::Uuid uuid2 {"f8718be6-0037-4cd8-81ec-582f70ee5d08"};
    const bt2c::UuidView view1 {uuid1};
    bt2c::UuidView copy {uuid2};

    copy = view1;
    CHECK(copy == view1);
}

TEST_CASE("`bt2c::Uuid` assignment from raw bytes")
{
    static const std::uint8_t bytes[] = {0xc2, 0x28, 0x1e, 0x4a, 0x69, 0x9b, 0x4b, 0x78,
                                         0x90, 0x3f, 0x2f, 0x84, 0x07, 0xfe, 0x2b, 0x77};
    bt2c::Uuid uuid;

    uuid = bytes;
    CHECK(uuid == bt2c::Uuid {"c2281e4a-699b-4b78-903f-2f8407fe2b77"});
}

TEST_CASE("`bt2c::UuidView` assignment from raw bytes")
{
    static const std::uint8_t bytes[] = {0xc2, 0x28, 0x1e, 0x4a, 0x69, 0x9b, 0x4b, 0x78,
                                         0x90, 0x3f, 0x2f, 0x84, 0x07, 0xfe, 0x2b, 0x77};
    const bt2c::Uuid other {"f8718be6-0037-4cd8-81ec-582f70ee5d08"};
    bt2c::UuidView view {other};

    view = bytes;
    CHECK(view == bt2c::UuidView {bt2c::Uuid {"c2281e4a-699b-4b78-903f-2f8407fe2b77"}});
}
