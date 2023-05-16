/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <array>
#include <sstream>
#include <string>

#include "common/assert.h"
#include "cpp-common/bt2-value-from-json-val.hpp"
#include "utils.hpp"
#include "../../../metadata/json/strings.hpp"

namespace ctf {
namespace src {

namespace bt2c = bt2_common;

nonstd::optional<bt2::MapValue::Shared> bt2ValueOfObj(const bt2c::JsonObjVal& jsonObjVal,
                                                      const std::string& key)
{
    const auto jsonUserAttrsVal = jsonObjVal[key];

    if (!jsonUserAttrsVal) {
        return nonstd::nullopt;
    }

    return bt2c::bt2ValueFromJsonVal(*jsonUserAttrsVal)->asMap().shared();
}

std::string absFieldLocStr(const FieldLoc& fieldLoc, const FieldLoc::Items::const_iterator end)
{
    std::ostringstream ss;

    BT_ASSERT(fieldLoc.scope());
    ss << '[' << scopeStr(*fieldLoc.scope());

    for (auto it = fieldLoc.begin(); it != end; ++it) {
        BT_ASSERT(*it);
        ss << ", `" << **it << '`';
    }

    ss << ']';
    return ss.str();
}

} /* namespace src */
} /* namespace ctf */
