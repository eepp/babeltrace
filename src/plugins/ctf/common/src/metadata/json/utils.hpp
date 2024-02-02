/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _CTF_SRC_METADATA_JSON_UTILS_HPP
#define _CTF_SRC_METADATA_JSON_UTILS_HPP

#include <sstream>
#include <string>

#include "common/common.h"
#include "cpp-common/bt2/value.hpp"
#include "cpp-common/bt2c/json-val.hpp"
#include "cpp-common/bt2c/text-loc-str.hpp"
#include "cpp-common/bt2c/text-loc.hpp"

#include "../../../metadata/json/strings.hpp"
#include "../../metadata/ctf-ir.hpp"

namespace ctf {
namespace src {

/*
 * Returns the UUID of the JSON object value `jsonObjVal`, or
 * `bt2s::nullopt` if there's no such property.
 */
bt2s::optional<bt2c::Uuid> uuidOfObj(const bt2c::JsonObjVal& jsonObjVal);

/*
 * Returns the object of the JSON object value `jsonObjVal` having the
 * key `key` as a libbabeltrace2 value object, or `bt2s::nullopt` if
 * there's no such key.
 */
bt2::MapValue::Shared bt2ValueOfObj(const bt2c::JsonObjVal& jsonObjVal, const std::string& key);

/*
 * Returns the user attributes of the JSON object value `jsonObjVal`, or
 * `bt2s::nullopt` if there's no such property.
 */
static inline bt2::MapValue::Shared userAttrsOfObj(const bt2c::JsonObjVal& jsonObjVal)
{
    return bt2ValueOfObj(jsonObjVal, json_strings::userAttrs);
}

/*
 * Returns the raw integer value from the JSON unsigned or signed
 * integer value `jsonIntVal`, casted as `ValT`.
 */
template <typename ValT>
ValT rawIntValFromJsonIntVal(const bt2c::JsonVal& jsonIntVal) noexcept
{
    if (jsonIntVal.isUInt()) {
        return static_cast<ValT>(*jsonIntVal.asUInt());
    } else {
        return static_cast<ValT>(*jsonIntVal.asSInt());
    }
}

/*
 * Returns the optional raw string value from the property named
 * `propName` within `jsonObjVal`.
 */
static inline bt2s::optional<std::string> optStrOfObj(const bt2c::JsonObjVal& jsonObjVal,
                                                      const char * const propName)
{
    const auto jsonVal = jsonObjVal[propName];

    if (jsonVal) {
        return *jsonVal->asStr();
    }

    return bt2s::nullopt;
}

static inline const char *scopeStr(const ir::FieldLocScope scope) noexcept
{
    switch (scope) {
    case ir::FieldLocScope::PKT_HEADER:
        return "packet header";
    case ir::FieldLocScope::PKT_CTX:
        return "packet context";
    case ir::FieldLocScope::EVENT_RECORD_HEADER:
        return "event record header";
    case ir::FieldLocScope::EVENT_RECORD_COMMON_CTX:
        return "common event record context";
    case ir::FieldLocScope::EVENT_RECORD_SPEC_CTX:
        return "specific event record context";
    case ir::FieldLocScope::EVENT_RECORD_PAYLOAD:
        return "event record payload";
    default:
        bt_common_abort();
    }
}

static inline std::string textLocStr(const bt2c::TextLoc& loc)
{
    return bt2c::textLocStr(loc, bt2c::TextLocStrFmt::Offset);
}

static inline std::string textLocStr(const bt2c::JsonVal& val)
{
    return textLocStr(val.loc());
}

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_JSON_UTILS_HPP */
