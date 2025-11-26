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
