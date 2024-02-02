/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include "../../../metadata/json/strings.hpp"
#include "json-fcs-with-role.hpp"

namespace ctf {
namespace src {

namespace {

namespace strings = json_strings;

const bt2c::JsonArrayVal *rolesOfJsonObj(const bt2c::JsonObjVal& jsonObj) noexcept
{
    const auto jsonRoles = jsonObj[strings::roles];

    if (!jsonRoles) {
        /* No roles */
        return nullptr;
    }

    return &jsonRoles->asArray();
}

void jsonFcsWithRole(const bt2c::JsonVal& jsonFc, const std::unordered_set<std::string>& roleNames,
                     const bool withMetadataStreamUuidRole,
                     std::unordered_set<const bt2c::JsonVal *>& set)
{
    auto& jsonFcObj = jsonFc.asObj();

    /* Type */
    auto& type = jsonFcObj.rawStrVal(strings::type);

    if (type == strings::fixedLenUInt || type == strings::fixedLenUEnum ||
        type == strings::varLenUInt || type == strings::varLenUEnum) {
        /* Unsigned integer field class */
        const auto jsonRoles = rolesOfJsonObj(jsonFcObj);

        if (!jsonRoles) {
            /* No roles */
            return;
        }

        for (auto& jsonRole : *jsonRoles) {
            if (roleNames.find(*jsonRole->asStr()) != roleNames.end()) {
                set.insert(&jsonFc);
                return;
            }
        }
    } else if (type == strings::staticLenBlob) {
        /* Static-length BLOB field class */
        const auto jsonRoles = rolesOfJsonObj(jsonFcObj);

        if (jsonRoles && !jsonRoles->isEmpty() && withMetadataStreamUuidRole) {
            /* The only valid role is the metadata stream UUID */
            set.insert(&jsonFc);
        }
    } else if (type == strings::structure) {
        const auto jsonMemberClasses = jsonFcObj[strings::memberClasses];

        if (!jsonMemberClasses) {
            return;
        }

        for (auto& jsonMemberCls : jsonMemberClasses->asArray()) {
            jsonFcsWithRole(*jsonMemberCls->asObj()[strings::fc], roleNames,
                            withMetadataStreamUuidRole, set);
        }
    } else if (type == strings::staticLenArray || type == strings::dynLenArray) {
        jsonFcsWithRole(*jsonFcObj[strings::elemFc], roleNames, withMetadataStreamUuidRole, set);
    } else if (type == strings::optional) {
        jsonFcsWithRole(*jsonFcObj[strings::fc], roleNames, withMetadataStreamUuidRole, set);
    } else if (type == strings::variant) {
        auto& jsonOpts = jsonFcObj[strings::opts]->asArray();

        for (auto& jsonOpt : jsonOpts) {
            jsonFcsWithRole(*jsonOpt->asObj()[strings::fc], roleNames, withMetadataStreamUuidRole,
                            set);
        }
    }
}

} /* namespace */

std::unordered_set<const bt2c::JsonVal *>
jsonFcsWithRole(const bt2c::JsonVal& jsonFc, const std::unordered_set<std::string>& roleNames,
                const bool withMetadataStreamUuidRole)
{
    std::unordered_set<const bt2c::JsonVal *> set;

    jsonFcsWithRole(jsonFc, roleNames, withMetadataStreamUuidRole, set);
    return set;
}

} /* namespace src */
} /* namespace ctf */
