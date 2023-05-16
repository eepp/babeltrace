/*
 * Copyright (c) 2022-2023 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#define BT_LOG_TAG  "PLUGIN/CTF/CTF-2-FC-BUILDER"
#define BT_CLOG_CFG this->_logCfg()
#include "cpp-common/cfg-logging-error-reporting-throw.hpp"

#include "common/assert.h"
#include "cpp-common/contains.hpp"
#include "../../../metadata/json/strings.hpp"
#include "utils.hpp"
#include "val-req.hpp"
#include "../ctf-ir.hpp"

#include "ctf-2-fc-builder.hpp"

namespace ctf {
namespace src {

namespace bt2c = bt2_common;
namespace strings = json_strings;

namespace {

/*
 * Creates and returns the set of unsigned integer field roles of the
 * JSON unsigned integer field class value `jsonFc`.
 */
ir::UIntFieldRoles uIntFieldRolesOfJsonUIntFc(const bt2c::JsonObjVal& jsonFc)
{
    ir::UIntFieldRoles roles;
    const auto jsonRoles = jsonFc[strings::roles];

    if (!jsonRoles) {
        /* No roles */
        return roles;
    }

    for (auto& jsonRole : jsonRoles->asArray()) {
        auto& roleName = *jsonRole->asStr();

        if (roleName == strings::dataStreamClsId) {
            roles.insert(ir::UIntFieldRole::DATA_STREAM_CLS_ID);
        } else if (roleName == strings::dataStreamId) {
            roles.insert(ir::UIntFieldRole::DATA_STREAM_ID);
        } else if (roleName == strings::pktMagicNumber) {
            roles.insert(ir::UIntFieldRole::PKT_MAGIC_NUMBER);
        } else if (roleName == strings::defClkTs) {
            roles.insert(ir::UIntFieldRole::DEF_CLK_TS);
        } else if (roleName == strings::discEventRecordCounterSnap) {
            roles.insert(ir::UIntFieldRole::DISC_EVENT_RECORD_COUNTER_SNAP);
        } else if (roleName == strings::pktContentLen) {
            roles.insert(ir::UIntFieldRole::PKT_CONTENT_LEN);
        } else if (roleName == strings::pktTotalLen) {
            roles.insert(ir::UIntFieldRole::PKT_TOTAL_LEN);
        } else if (roleName == strings::pktEndDefClkTs) {
            roles.insert(ir::UIntFieldRole::PKT_END_DEF_CLK_TS);
        } else if (roleName == strings::pktSeqNum) {
            roles.insert(ir::UIntFieldRole::PKT_SEQ_NUM);
        } else {
            BT_ASSERT(roleName == strings::eventRecordClsId);
            roles.insert(ir::UIntFieldRole::EVENT_RECORD_CLS_ID);
        }
    }

    return roles;
}

/*
 * Creates and returns an integer range set (of type
 * `IntRangeSet<ValT>`) from the JSON integer range set value
 * `jsonIntRangeSet`.
 */
template <typename ValT>
IntRangeSet<ValT> intRangeSetFromJsonIntRangeSet(const bt2c::JsonArrayVal& jsonIntRangeSet)
{
    typename IntRangeSet<ValT>::Set ranges;

    for (auto& jsonRange : jsonIntRangeSet) {
        auto& jsonRangeArray = jsonRange->asArray();

        BT_ASSERT(jsonRangeArray.size() == 2);
        ranges.emplace(
            typename IntRangeSet<ValT>::Range {rawIntValFromJsonIntVal<ValT>(jsonRangeArray[0]),
                                               rawIntValFromJsonIntVal<ValT>(jsonRangeArray[1])});
    }

    return IntRangeSet<ValT> {std::move(ranges)};
}

/*
 * Creates and returns the enumeration field class mappings (of type
 * `EnumFcT::Mappings`) of the JSON enumeration field class value
 * `jsonFc`.
 */
template <typename EnumFcT>
typename EnumFcT::Mappings enumFcMappingsOfJsonEnumFc(const bt2c::JsonObjVal& jsonFc)
{
    typename EnumFcT::Mappings mappings;
    const auto jsonMappings = jsonFc[strings::mappings];

    for (auto& keyJsonIntRangesPair : jsonMappings->asObj()) {
        mappings.insert(std::make_pair(keyJsonIntRangesPair.first,
                                       intRangeSetFromJsonIntRangeSet<typename EnumFcT::Val>(
                                           keyJsonIntRangesPair.second->asArray())));
    }

    return mappings;
}

/*
 * Creates and returns a fixed-length unsigned enumeration field class
 * from the JSON fixed-length unsigned enumeration field class value
 * `jsonFc` and the other parameters.
 */
Fc::UP fcFromJsonFixedLenUEnumFc(const bt2c::JsonObjVal& jsonFc, const unsigned int align,
                                 const bt2c::DataLen len, const ir::ByteOrder byteOrder,
                                 const ir::DispBase prefDispBase, ir::UIntFieldRoles&& roles,
                                 ir::OptUserAttrs&& userAttrs)
{
    /* Mappings */
    auto mappings = enumFcMappingsOfJsonEnumFc<FixedLenUEnumFc>(jsonFc);

    /* Create field class */
    return createFixedLenUEnumFc(jsonFc.loc(), align, len, byteOrder, std::move(mappings),
                                 prefDispBase, std::move(roles), std::move(userAttrs));
}

/*
 * Creates and returns a fixed-length unsigned integer field class from
 * the JSON fixed-length unsigned integer field class value `jsonFc` and
 * the other parameters.
 */
Fc::UP fcFromJsonFixedLenUIntFc(const bt2c::JsonObjVal& jsonFc, const std::string& type,
                                const unsigned int align, const bt2c::DataLen len,
                                const ir::ByteOrder byteOrder, const ir::DispBase prefDispBase,
                                ir::OptUserAttrs&& userAttrs)
{
    /* Roles */
    auto roles = uIntFieldRolesOfJsonUIntFc(jsonFc);

    /* Create field class */
    if (type == strings::fixedLenUInt) {
        return createFixedLenUIntFc(jsonFc.loc(), align, len, byteOrder, prefDispBase,
                                    std::move(roles), std::move(userAttrs));
    } else {
        BT_ASSERT(type == strings::fixedLenUEnum);
        return fcFromJsonFixedLenUEnumFc(jsonFc, align, len, byteOrder, prefDispBase,
                                         std::move(roles), std::move(userAttrs));
    }
}

/*
 * Creates and returns a fixed-length signed enumeration field class
 * from the JSON fixed-length signed enumeration field class value
 * `jsonFc` and the other parameters.
 */
Fc::UP fcFromJsonFixedLenSEnumFc(const bt2c::JsonObjVal& jsonFc, const unsigned int align,
                                 const bt2c::DataLen len, const ir::ByteOrder byteOrder,
                                 const ir::DispBase prefDispBase, ir::OptUserAttrs&& userAttrs)
{
    /* Mappings */
    auto mappings = enumFcMappingsOfJsonEnumFc<FixedLenSEnumFc>(jsonFc);

    /* Create field class */
    return createFixedLenSEnumFc(jsonFc.loc(), align, len, byteOrder, std::move(mappings),
                                 prefDispBase, std::move(userAttrs));
}

/*
 * Creates and returns a fixed-length signed integer field class from
 * the JSON fixed-length signed integer field class value `jsonFc` and
 * the other parameters.
 */
Fc::UP fcFromJsonFixedLenSIntFc(const bt2c::JsonObjVal& jsonFc, const std::string& type,
                                const unsigned int align, const bt2c::DataLen len,
                                const ir::ByteOrder byteOrder, const ir::DispBase prefDispBase,
                                ir::OptUserAttrs&& userAttrs)
{
    if (type == strings::fixedLenSInt) {
        return createFixedLenSIntFc(jsonFc.loc(), align, len, byteOrder, prefDispBase,
                                    std::move(userAttrs));
    } else {
        BT_ASSERT(type == strings::fixedLenSEnum);
        return fcFromJsonFixedLenSEnumFc(jsonFc, align, len, byteOrder, prefDispBase,
                                         std::move(userAttrs));
    }
}

/*
 * Returns the preferred display base of the JSON integer field class
 * value `jsonFc`.
 */
ir::DispBase prefDispBaseOfJsonIntFc(const bt2c::JsonObjVal& jsonFc) noexcept
{
    return static_cast<ir::DispBase>(jsonFc.rawVal(strings::prefDispBase, 10ULL));
}

/*
 * Creates and returns a fixed-length integer field class from the JSON
 * fixed-length integer field class value `jsonFc` and the other
 * parameters.
 */
Fc::UP fcFromJsonFixedLenIntFc(const bt2c::JsonObjVal& jsonFc, const std::string& type,
                               const unsigned int align, const bt2c::DataLen len,
                               const ir::ByteOrder byteOrder, ir::OptUserAttrs&& userAttrs)
{
    /* Preferred display base */
    const auto prefDispBase = prefDispBaseOfJsonIntFc(jsonFc);

    /* Create field class */
    if (type == strings::fixedLenUInt || type == strings::fixedLenUEnum) {
        return fcFromJsonFixedLenUIntFc(jsonFc, type, align, len, byteOrder, prefDispBase,
                                        std::move(userAttrs));
    } else {
        BT_ASSERT(type == strings::fixedLenSInt || type == strings::fixedLenSEnum);
        return fcFromJsonFixedLenSIntFc(jsonFc, type, align, len, byteOrder, prefDispBase,
                                        std::move(userAttrs));
    }
}

/*
 * Returns the length of the JSON field class value `jsonFc`.
 */
unsigned long long lenOfJsonFc(const bt2c::JsonObjVal& jsonFc) noexcept
{
    return jsonFc.rawUIntVal(strings::len);
}

/*
 * Creates and returns a fixed-length bit array field class from the
 * JSON fixed-length bit array field class value `jsonFc` and the other
 * parameters.
 */
Fc::UP fcFromJsonFixedLenBitArrayFc(const bt2c::JsonObjVal& jsonFc, const std::string& type,
                                    ir::OptUserAttrs&& userAttrs)
{
    /* Alignment */
    const auto align = jsonFc.rawVal(strings::align, 1ULL);

    /* Length */
    const auto len = bt2c::DataLen::fromBits(lenOfJsonFc(jsonFc));

    /* Byte order */
    const auto byteOrder = jsonFc.rawStrVal(strings::byteOrder) == strings::littleEndian ?
                               ir::ByteOrder::LITTLE :
                               ir::ByteOrder::BIG;

    /* Create field class */
    if (type == strings::fixedLenBitArray) {
        return createFixedLenBitArrayFc(jsonFc.loc(), align, len, byteOrder, std::move(userAttrs));
    } else if (type == strings::fixedLenBool) {
        return createFixedLenBoolFc(jsonFc.loc(), align, len, byteOrder, std::move(userAttrs));
    } else if (type == strings::fixedLenUInt || type == strings::fixedLenSInt ||
               type == strings::fixedLenUEnum || type == strings::fixedLenSEnum) {
        return fcFromJsonFixedLenIntFc(jsonFc, type, align, len, byteOrder, std::move(userAttrs));
    } else {
        BT_ASSERT(type == strings::fixedLenFloat);
        return createFixedLenFloatFc(jsonFc.loc(), align, len, byteOrder, std::move(userAttrs));
    }
}

/*
 * Creates and returns a variable-length unsigned enumeration field
 * class from the JSON variable-length unsigned enumeration field class
 * value `jsonFc` and the other parameters.
 */
Fc::UP fcFromJsonVarLenUEnumFc(const bt2c::JsonObjVal& jsonFc, const ir::DispBase prefDispBase,
                               ir::UIntFieldRoles&& roles, ir::OptUserAttrs&& userAttrs)
{
    /* Mappings */
    auto mappings = enumFcMappingsOfJsonEnumFc<VarLenUEnumFc>(jsonFc);

    /* Create field class */
    return createVarLenUEnumFc(jsonFc.loc(), std::move(mappings), prefDispBase, std::move(roles),
                               std::move(userAttrs));
}

/*
 * Creates and returns a variable-length unsigned integer field class
 * from the JSON variable-length unsigned integer field class value
 * `jsonFc` and the other parameters.
 */
Fc::UP fcFromJsonVarLenUIntFc(const bt2c::JsonObjVal& jsonFc, const std::string& type,
                              const ir::DispBase prefDispBase, ir::OptUserAttrs&& userAttrs)
{
    /* Roles */
    auto roles = uIntFieldRolesOfJsonUIntFc(jsonFc);

    /* Create field class */
    if (type == strings::varLenUInt) {
        return createVarLenUIntFc(jsonFc.loc(), prefDispBase, std::move(roles),
                                  std::move(userAttrs));
    } else {
        BT_ASSERT(type == strings::varLenUEnum);
        return fcFromJsonVarLenUEnumFc(jsonFc, prefDispBase, std::move(roles),
                                       std::move(userAttrs));
    }
}

/*
 * Creates and returns a variable-length signed enumeration field class
 * from the JSON variable-length signed enumeration field class value
 * `jsonFc` and the other parameters.
 */
Fc::UP fcFromJsonVarLenSEnumFc(const bt2c::JsonObjVal& jsonFc, const ir::DispBase prefDispBase,
                               ir::OptUserAttrs&& userAttrs)
{
    /* Mappings */
    auto mappings = enumFcMappingsOfJsonEnumFc<VarLenSEnumFc>(jsonFc);

    /* Create field class */
    return createVarLenSEnumFc(jsonFc.loc(), std::move(mappings), prefDispBase,
                               std::move(userAttrs));
}

/*
 * Creates and returns a variable-length signed integer field class from
 * the JSON variable-length signed integer field class value `jsonFc`
 * and the other parameters.
 */
Fc::UP fcFromJsonVarLenSIntFc(const bt2c::JsonObjVal& jsonFc, const std::string& type,
                              const ir::DispBase prefDispBase, ir::OptUserAttrs&& userAttrs)
{
    if (type == strings::fixedLenSInt) {
        return createVarLenSIntFc(jsonFc.loc(), prefDispBase, std::move(userAttrs));
    } else {
        BT_ASSERT(type == strings::varLenSEnum);
        return fcFromJsonVarLenSEnumFc(jsonFc, prefDispBase, std::move(userAttrs));
    }
}

/*
 * Creates and returns a variable-length integer field class from the
 * JSON variable-length integer field class value `jsonFc` and the other
 * parameters.
 */
Fc::UP fcFromJsonVarLenIntFc(const bt2c::JsonObjVal& jsonFc, const std::string& type,
                             ir::OptUserAttrs&& userAttrs)
{
    /* Preferred display base */
    const auto prefDispBase = prefDispBaseOfJsonIntFc(jsonFc);

    if (type == strings::varLenUInt || type == strings::varLenUEnum) {
        return fcFromJsonVarLenUIntFc(jsonFc, type, prefDispBase, std::move(userAttrs));
    } else {
        BT_ASSERT(type == strings::varLenSInt || type == strings::varLenSEnum);
        return fcFromJsonVarLenSIntFc(jsonFc, type, prefDispBase, std::move(userAttrs));
    }
}

/*
 * Creates and returns the field location of the JSON field class value
 * `jsonFc` from its `key` property.
 */
FieldLoc fieldLocOfJsonFc(const bt2c::JsonObjVal& jsonFc, const std::string& key)
{
    auto& jsonLoc = jsonFc[key]->asObj();

    /* Scope (origin) */
    const auto scope = [&jsonLoc]() -> nonstd::optional<ir::FieldLocScope> {
        const auto jsonOrig = jsonLoc[strings::origin];

        if (!jsonOrig) {
            return nonstd::nullopt;
        }

        auto& scopeName = *jsonOrig->asStr();

        if (scopeName == strings::pktHeader) {
            return ir::FieldLocScope::PKT_HEADER;
        } else if (scopeName == strings::pktCtx) {
            return ir::FieldLocScope::PKT_CTX;
        } else if (scopeName == strings::eventRecordHeader) {
            return ir::FieldLocScope::EVENT_RECORD_HEADER;
        } else if (scopeName == strings::eventRecordCommonCtx) {
            return ir::FieldLocScope::EVENT_RECORD_COMMON_CTX;
        } else if (scopeName == strings::eventRecordSpecCtx) {
            return ir::FieldLocScope::EVENT_RECORD_SPEC_CTX;
        } else {
            BT_ASSERT(scopeName == strings::eventRecordPayload);
            return ir::FieldLocScope::EVENT_RECORD_PAYLOAD;
        }
    }();

    /* Path */
    auto& jsonPath = jsonLoc[strings::path]->asArray();
    FieldLoc::Items items;

    std::transform(jsonPath.begin(), jsonPath.end(), std::back_inserter(items),
                   [](const bt2c::JsonVal::UP& jsonItem) -> nonstd::optional<std::string> {
                       if (jsonItem->isNull()) {
                           /* `null` becomes `nonstd::nullopt` */
                           return nonstd::nullopt;
                       }

                       return *jsonItem->asStr();
                   });

    /* Create field location */
    return createFieldLoc(scope, std::move(items), jsonLoc.loc());
}

/*
 * Creates and returns a non-null-terminated string field class from the
 * JSON non-null-terminated string field class value `jsonFc` and the
 * other parameters.
 */
Fc::UP fcFromJsonNonNullTerminatedStrFc(const bt2c::JsonObjVal& jsonFc, const std::string& type,
                                        ir::OptUserAttrs&& userAttrs)
{
    if (type == strings::staticLenStr) {
        return createStaticLenStrFc(jsonFc.loc(), lenOfJsonFc(jsonFc), std::move(userAttrs));
    } else {
        BT_ASSERT(type == strings::dynLenStr);
        return createDynLenStrFc(jsonFc.loc(), fieldLocOfJsonFc(jsonFc, strings::lenFieldLoc),
                                 std::move(userAttrs));
    }
}

/*
 * Creates and returns a static-length BLOB field class from the JSON
 * static-length BLOB field class value `jsonFc` and the other
 * parameters.
 */
Fc::UP fcFromJsonStaticLenBlobFc(const bt2c::JsonObjVal& jsonFc, const char * const mediaType,
                                 ir::OptUserAttrs&& userAttrs)
{
    /* Has metadata stream UUID role? */
    const auto jsonRoles = jsonFc[strings::roles];
    const auto hasMetadataStreamUuidRole = jsonRoles && jsonRoles->asArray().size() > 0;

    /* Create field class */
    return createStaticLenBlobFc(jsonFc.loc(), lenOfJsonFc(jsonFc), mediaType,
                                 hasMetadataStreamUuidRole, std::move(userAttrs));
}

/*
 * Creates and returns a BLOB field class from the JSON BLOB field class
 * value `jsonFc` and the other parameters.
 */
Fc::UP fcFromJsonBlobFc(const bt2c::JsonObjVal& jsonFc, const std::string& type,
                        ir::OptUserAttrs&& userAttrs)
{
    /* Media type */
    const auto mediaType = jsonFc.rawVal(strings::mediaType, BlobFc::defaultMediaType);

    /* Create field class */
    if (type == strings::staticLenBlob) {
        return fcFromJsonStaticLenBlobFc(jsonFc, mediaType, std::move(userAttrs));
    } else {
        BT_ASSERT(type == strings::dynLenBlob);
        return createDynLenBlobFc(jsonFc.loc(), fieldLocOfJsonFc(jsonFc, strings::lenFieldLoc),
                                  mediaType, std::move(userAttrs));
    }
}

/*
 * Returns the minimum alignment of the JSON field class value `jsonFc`.
 */
unsigned long long minAlignOfJsonFc(const bt2c::JsonObjVal& jsonFc) noexcept
{
    return jsonFc.rawVal(strings::minAlign, 1ULL);
}

} /* namespace */

Ctf2FcBuilder::Ctf2FcBuilder(const bt2_common::LogCfg& logCfg,
                             bt2_common::TextLocStrFmt textLocStrFmt) :
    LoggingObj {logCfg, textLocStrFmt}
{
}

Fc::UP Ctf2FcBuilder::buildFcFromJsonVal(const bt2_common::JsonVal& jsonFc) const
{
    if (jsonFc.isStr()) {
        /* Field class alias reference */
        return this->_aliasedFc(*jsonFc.asStr(), jsonFc.loc());
    }

    auto& jsonFcObj = jsonFc.asObj();

    /* Type */
    auto& type = jsonFcObj.rawStrVal(strings::type);

    /* User attributes */
    auto userAttrs = userAttrsOfObj(jsonFcObj);

    /* Defer to specific method */
    if (type == strings::fixedLenBitArray || type == strings::fixedLenBool ||
        type == strings::fixedLenUInt || type == strings::fixedLenSInt ||
        type == strings::fixedLenUEnum || type == strings::fixedLenSEnum ||
        type == strings::fixedLenFloat) {
        return fcFromJsonFixedLenBitArrayFc(jsonFcObj, type, std::move(userAttrs));
    } else if (type == strings::varLenUInt || type == strings::varLenSInt ||
               type == strings::varLenUEnum || type == strings::varLenSEnum) {
        return fcFromJsonVarLenIntFc(jsonFcObj, type, std::move(userAttrs));
    } else if (type == strings::nullTerminatedStr) {
        return createNullTerminatedStrFc(jsonFc.loc(), std::move(userAttrs));
    } else if (type == strings::staticLenStr || type == strings::dynLenStr) {
        return fcFromJsonNonNullTerminatedStrFc(jsonFcObj, type, std::move(userAttrs));
    } else if (type == strings::staticLenBlob || type == strings::dynLenBlob) {
        return fcFromJsonBlobFc(jsonFcObj, type, std::move(userAttrs));
    } else if (type == strings::staticLenArray || type == strings::dynLenArray) {
        return this->_fcFromJsonArrayFc(jsonFcObj, type, std::move(userAttrs));
    } else if (type == strings::structure) {
        return this->_fcFromJsonStructFc(jsonFcObj, std::move(userAttrs));
    } else if (type == strings::optional) {
        return this->_fcFromJsonOptionalFc(jsonFcObj, std::move(userAttrs));
    } else {
        BT_ASSERT(type == strings::variant);
        return this->_fcFromJsonVariantFc(jsonFcObj, std::move(userAttrs));
    }
}

void Ctf2FcBuilder::addFcAlias(std::string name, Fc::UP fc, const bt2c::TextLoc& nameLoc)
{
    /* Check for duplicate */
    if (bt2c::contains(_mFcAliases, name)) {
        std::ostringstream ss;

        ss << "Duplicate field class alias named `" << name << "`.";
        BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2_common::Error, "[%s] %s",
                                        this->_locStr(nameLoc).c_str(), ss.str().c_str());
    }

    /* Add to map */
    _mFcAliases.emplace(std::move(name), std::move(fc));
}

Fc::UP Ctf2FcBuilder::_aliasedFc(const std::string& name, const bt2c::TextLoc& loc) const
{
    /* Check if the field class alias exists */
    const auto it = _mFcAliases.find(name);

    if (it == _mFcAliases.end()) {
        std::ostringstream ss;

        ss << "Cannot find field class alias `" << name << "`.";
        BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2_common::Error, "[%s] %s", this->_locStr(loc).c_str(),
                                        ss.str().c_str());
    }

    /* Return a clone of the field class alias */
    return it->second->clone();
}

Fc::UP Ctf2FcBuilder::_fcFromJsonArrayFc(const bt2c::JsonObjVal& jsonFc, const std::string& type,
                                         ir::OptUserAttrs&& userAttrs) const
{
    /* Element field class */
    Fc::UP elemFc;

    try {
        elemFc = this->buildFcFromJsonVal(*jsonFc[strings::elemFc]);
    } catch (const bt2c::Error&) {
        BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid array field class.",
                                          this->_locStr(jsonFc.loc()).c_str());
    }

    /* Minimum alignment */
    const auto minAlign = minAlignOfJsonFc(jsonFc);

    /* Create field class */
    if (type == strings::staticLenArray) {
        return createStaticLenArrayFc(jsonFc.loc(), lenOfJsonFc(jsonFc), std::move(elemFc),
                                      minAlign, std::move(userAttrs));
    } else {
        BT_ASSERT(type == strings::dynLenArray);
        return createDynLenArrayFc(jsonFc.loc(), fieldLocOfJsonFc(jsonFc, strings::lenFieldLoc),
                                   std::move(elemFc), minAlign, std::move(userAttrs));
    }
}

Fc::UP Ctf2FcBuilder::_fcFromJsonStructFc(const bt2c::JsonObjVal& jsonFc,
                                          ir::OptUserAttrs&& userAttrs) const
{
    /* Minimum alignment */
    const auto minAlign = minAlignOfJsonFc(jsonFc);

    /* Member classes */
    StructFc::MemberClasses memberClasses;
    const auto jsonMemberClasses = jsonFc[strings::memberClasses];

    try {
        if (jsonMemberClasses) {
            for (auto& jsonMemberCls : jsonMemberClasses->asArray()) {
                auto& jsonMemberClsObj = jsonMemberCls->asObj();
                auto& name = jsonMemberClsObj.rawStrVal(strings::name);

                try {
                    memberClasses.emplace_back(createStructFieldMemberCls(
                        name, this->buildFcFromJsonVal(*jsonMemberClsObj[strings::fc]),
                        userAttrsOfObj(jsonMemberClsObj)));
                } catch (const bt2c::Error&) {
                    BT_CLOGE_APPEND_CAUSE_AND_RETHROW(
                        "[%s] Invalid structure field member class `%s`.",
                        this->_locStr(jsonMemberClsObj.loc()).c_str(), name.c_str());
                }
            }
        }
    } catch (const bt2c::Error&) {
        BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid structure field class.",
                                          this->_locStr(jsonFc.loc()).c_str());
    }

    /* Create field class */
    return createStructFc(jsonFc.loc(), std::move(memberClasses), minAlign, std::move(userAttrs));
}

Fc::UP Ctf2FcBuilder::_fcFromJsonOptionalFc(const bt2c::JsonObjVal& jsonFc,
                                            ir::OptUserAttrs&& userAttrs) const
{
    try {
        /*
         * Create optional field class.
         *
         * The existence of the `selector-field-ranges` property
         * determines the expected field class type:
         *
         * Property exists:
         *     Class of optional fields with an integer selector.
         *
         * Property doesn't exist:
         *     Class of optional fields with a boolean selector.
         *
         * Note that we just trust the metadata at this point so there's
         * no validation: this can be done later with fcDepTypes().
         *
         * Also, if the optional field class has instances having an
         * integer selector, we can't know the signedness of such a
         * selector at this point. Therefore we enforce an unsigned
         * integer range set and will possibly cast to signed integer
         * ranges later once we know the selector signedness.
         */
        const auto jsonSelFieldRanges = jsonFc[strings::selFieldRanges];
        auto fieldLoc = fieldLocOfJsonFc(jsonFc, strings::selFieldLoc);
        auto fc = this->buildFcFromJsonVal(*jsonFc[strings::fc]);

        if (jsonSelFieldRanges) {
            /* Expected boolean selector */
            return createOptionalFc(jsonFc.loc(), std::move(fc), std::move(fieldLoc),
                                    std::move(userAttrs));
        } else {
            /* Expected integer selector */
            return createOptionalFc(jsonFc.loc(), std::move(fc), std::move(fieldLoc),
                                    intRangeSetFromJsonIntRangeSet<OptionalWithUIntSelFc::SelVal>(
                                        jsonSelFieldRanges->asArray()),
                                    std::move(userAttrs));
        }
    } catch (const bt2c::Error&) {
        BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid optional field class.",
                                          this->_locStr(jsonFc.loc()).c_str());
    }
}

Fc::UP Ctf2FcBuilder::_fcFromJsonVariantFc(const bt2c::JsonObjVal& jsonFc,
                                           ir::OptUserAttrs&& userAttrs) const
{
    try {
        auto& jsonOpts = jsonFc[strings::opts]->asArray();

        /*
         * We can't know the signedness of the selector at this point.
         * Therefore we enforce an unsigned integer range set and will
         * possibly cast to signed integer ranges later once we know the
         * selector signedness.
         */
        VariantWithUIntSelFc::Opts opts;

        for (auto it = jsonOpts.begin(); it != jsonOpts.end(); ++it) {
            auto& jsonOpt = (*it)->asObj();

            /* Create and append option */
            try {
                opts.emplace_back(createVariantFcOpt(
                    this->buildFcFromJsonVal(*jsonOpt[strings::fc]),
                    intRangeSetFromJsonIntRangeSet<VariantWithUIntSelFc::SelVal>(
                        jsonOpt[strings::selFieldRanges]->asArray()),
                    optStrOfObj(jsonOpt, strings::name), userAttrsOfObj(jsonOpt)));
            } catch (const bt2c::Error&) {
                BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid variant field class option #%tu.",
                                                  this->_locStr(jsonFc.loc()).c_str(),
                                                  it - jsonOpts.begin());
            }
        }

        /* Create field class */
        return createVariantFc(jsonFc.loc(), std::move(opts),
                               fieldLocOfJsonFc(jsonFc, strings::selFieldLoc),
                               std::move(userAttrs));
    } catch (const bt2c::Error&) {
        BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid variant field class.",
                                          this->_locStr(jsonFc.loc()).c_str());
    }
}

} /* namespace src */
} /* namespace ctf */
