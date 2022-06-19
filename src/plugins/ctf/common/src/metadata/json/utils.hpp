/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _CTF_SRC_METADATA_JSON_UTILS_HPP
#define _CTF_SRC_METADATA_JSON_UTILS_HPP

#include <string>
#include <sstream>

#include "common/common.h"
#include "cpp-common/json-val.hpp"
#include "cpp-common/optional.hpp"
#include "cpp-common/uuid.hpp"
#include "cpp-common/bt2/value.hpp"
#include "cpp-common/text-loc.hpp"
#include "cpp-common/text-loc-str.hpp"
#include "../../../metadata/json/strings.hpp"
#include "../../metadata/ctf-ir.hpp"

namespace ctf {
namespace src {

/*
 * Returns the UUID of the JSON object value `jsonObjVal`, or
 * `nonstd::nullopt` if there's no such property.
 */
nonstd::optional<bt2_common::Uuid> uuidOfObj(const bt2_common::JsonObjVal& jsonObjVal);

/*
 * Returns the object of the JSON object value `jsonObjVal` having the
 * key `key` as a libbabeltrace2 value object, or `nonstd::nullopt` if
 * there's no such key.
 */
nonstd::optional<bt2::MapValue::Shared> bt2ValueOfObj(const bt2_common::JsonObjVal& jsonObjVal,
                                                      const std::string& key);

/*
 * Returns the user attributes of the JSON object value `jsonObjVal`, or
 * `nonstd::nullopt` if there's no such property.
 */
static inline nonstd::optional<bt2::MapValue::Shared>
userAttrsOfObj(const bt2_common::JsonObjVal& jsonObjVal)
{
    return bt2ValueOfObj(jsonObjVal, json_strings::userAttrs);
}

/*
 * Returns the raw integer value from the JSON unsigned or signed
 * integer value `jsonIntVal`, casted as `ValT`.
 */
template <typename ValT>
ValT rawIntValFromJsonIntVal(const bt2_common::JsonVal& jsonIntVal) noexcept
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
static inline nonstd::optional<std::string> optStrOfObj(const bt2_common::JsonObjVal& jsonObjVal,
                                                        const char * const propName)
{
    const auto jsonVal = jsonObjVal[propName];

    if (jsonVal) {
        return *jsonVal->asStr();
    }

    return nonstd::nullopt;
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

static inline std::string textLocStr(const bt2_common::TextLoc& loc)
{
    return bt2_common::textLocStr(loc, bt2_common::TextLocStrFmt::OFFSET);
}

static inline std::string textLocStr(const bt2_common::JsonVal& val)
{
    return textLocStr(val.loc());
}

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_JSON_UTILS_HPP */
