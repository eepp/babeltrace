/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <array>

#include "cpp-common/bt2-value-from-json-val.hpp"
#include "utils.hpp"
#include "../../../metadata/json/strings.hpp"

namespace ctf {
namespace src {

namespace bt2c = bt2_common;

nonstd::optional<bt2c::Uuid> uuidOfObj(const bt2c::JsonObjVal& jsonObjVal)
{
    const auto jsonUuidVal = jsonObjVal[json_strings::uuid];

    if (!jsonUuidVal) {
        return nonstd::nullopt;
    }

    std::array<bt2c::Uuid::Val, bt2c::Uuid::size()> uuid;
    auto& jsonArrayUuidVal = jsonUuidVal->asArray();

    std::transform(jsonArrayUuidVal.begin(), jsonArrayUuidVal.end(), uuid.begin(),
                   [](const bt2c::JsonVal::UP& jsonUuidElemVal) {
                       return static_cast<bt2c::Uuid::Val>(*jsonUuidElemVal->asUInt());
                   });

    return bt2c::Uuid {uuid.data()};
}

nonstd::optional<bt2::MapValue::Shared> bt2ValueOfObj(const bt2c::JsonObjVal& jsonObjVal,
                                                      const std::string& key)
{
    const auto jsonUserAttrsVal = jsonObjVal[key];

    if (!jsonUserAttrsVal) {
        return nonstd::nullopt;
    }

    return bt2c::bt2ValueFromJsonVal(*jsonUserAttrsVal)->asMap().shared();
}

} /* namespace src */
} /* namespace ctf */
