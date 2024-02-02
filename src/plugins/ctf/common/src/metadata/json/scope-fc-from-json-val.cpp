/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <set>

#include "common/assert.h"

#include "../../../metadata/json/strings.hpp"
#include "../ctf-ir.hpp"
#include "scope-fc-from-json-val.hpp"
#include "utils.hpp"
#include "val-req.hpp"

namespace ctf {
namespace src {

namespace strings = json_strings;

namespace {

/*
 * Helper containing context to implement scopeFcFromJsonVal().
 */
class ScopeFcFromJsonVal final
{
public:
    explicit ScopeFcFromJsonVal(const bt2c::JsonObjVal& jsonFc,
                                const bt2c::JsonObjVal * const jsonTraceCls,
                                const bt2c::JsonObjVal * const jsonDataStreamCls,
                                const bt2c::JsonObjVal * const jsonEventRecordCls,
                                const bt2c::Logger& parentLogger) :
        _mLogger {parentLogger, "PLUGIN/CTF/CTF-2-META-STREAM-PARSER"},
        _mJsonTraceCls {jsonTraceCls}, _mJsonDataStreamCls {jsonDataStreamCls},
        _mJsonEventRecordCls {jsonEventRecordCls}
    {
        /*
         * Immediately convert the JSON field class value to a CTF IR
         * field class.
         */
        _mFc = this->_fcFromJsonVal(jsonFc);
    }

    Fc::UP releaseFc() noexcept
    {
        return std::move(_mFc);
    }

private:
    /* Set of JSON field class values */
    using _JsonFcSet = std::set<const bt2c::JsonVal *>;

    /* JSON dependency (field class) value type */
    enum class _JsonDepType
    {
        BOOL,
        UINT,
        SINT,
    };

    /*
     * Creates and returns a field class from the JSON field class value
     * `jsonFc`.
     */
    Fc::UP _fcFromJsonVal(const bt2c::JsonVal& jsonFc)
    {
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
            return this->_fcFromJsonFixedLenBitArrayFc(jsonFcObj, type, std::move(userAttrs));
        } else if (type == strings::varLenUInt || type == strings::varLenSInt ||
                   type == strings::varLenUEnum || type == strings::varLenSEnum) {
            return this->_fcFromJsonVarLenIntFc(jsonFcObj, type, std::move(userAttrs));
        } else if (type == strings::nullTerminatedStr) {
            return createNullTerminatedStrFc(std::move(userAttrs));
        } else if (type == strings::staticLenStr || type == strings::dynLenStr) {
            return this->_fcFromJsonNonNullTerminatedStrFc(jsonFcObj, type, std::move(userAttrs));
        } else if (type == strings::staticLenBlob || type == strings::dynLenBlob) {
            return this->_fcFromJsonBlobFc(jsonFcObj, type, std::move(userAttrs));
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

    /*
     * Creates and returns the set of unsigned integer field roles of
     * the JSON unsigned integer field class value `jsonFc`.
     */
    static ir::UIntFieldRoles _uIntFieldRolesOfJsonUIntFc(const bt2c::JsonObjVal& jsonFc)
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
     * Creates and returns an integer range set from the JSON integer
     * range set value `jsonIntRangeSet`.
     */
    template <typename ValT>
    static IntRangeSet<ValT>
    _intRangeSetFromJsonIntRangeSet(const bt2c::JsonArrayVal& jsonIntRangeSet)
    {
        typename IntRangeSet<ValT>::Set ranges;

        for (auto& jsonRange : jsonIntRangeSet) {
            auto& jsonRangeArray = jsonRange->asArray();

            ranges.insert(typename IntRangeSet<ValT>::Range {
                rawIntValFromJsonIntVal<ValT>(jsonRangeArray[0]),
                rawIntValFromJsonIntVal<ValT>(jsonRangeArray[1])});
        }

        return IntRangeSet<ValT> {std::move(ranges)};
    }

    /*
     * Creates and returns the enumeration field class mappings of the
     * JSON enumeration field class value `jsonFc`.
     */
    template <typename EnumFcT>
    static typename EnumFcT::Mappings _enumFcMappingsOfJsonEnumFc(const bt2c::JsonObjVal& jsonFc)
    {
        typename EnumFcT::Mappings mappings;
        const auto jsonMappings = jsonFc[strings::mappings];

        for (auto& keyJsonIntRangesPair : jsonMappings->asObj()) {
            mappings.insert(std::make_pair(keyJsonIntRangesPair.first,
                                           _intRangeSetFromJsonIntRangeSet<typename EnumFcT::Val>(
                                               keyJsonIntRangesPair.second->asArray())));
        }

        return mappings;
    }

    /*
     * Creates and returns a fixed-length unsigned enumeration field
     * class from the JSON fixed-length unsigned enumeration field class
     * value `jsonFc` and the other parameters.
     */
    static Fc::UP _fcFromJsonFixedLenUEnumFc(const bt2c::JsonObjVal& jsonFc,
                                             const unsigned int align, const bt2c::DataLen len,
                                             const ir::ByteOrder byteOrder,
                                             const ir::DispBase prefDispBase,
                                             ir::UIntFieldRoles&& roles,
                                             ir::OptUserAttrs&& userAttrs)
    {
        /* Mappings */
        auto mappings = _enumFcMappingsOfJsonEnumFc<FixedLenUEnumFc>(jsonFc);

        /* Create field class */
        return createFixedLenUEnumFc(align, len, byteOrder, std::move(mappings), prefDispBase,
                                     std::move(roles), std::move(userAttrs));
    }

    /*
     * Creates and returns a fixed-length unsigned integer field class
     * from the JSON fixed-length unsigned integer field class value
     * `jsonFc` and the other parameters.
     */
    static Fc::UP _fcFromJsonFixedLenUIntFc(const bt2c::JsonObjVal& jsonFc, const std::string& type,
                                            const unsigned int align, const bt2c::DataLen len,
                                            const ir::ByteOrder byteOrder,
                                            const ir::DispBase prefDispBase,
                                            ir::OptUserAttrs&& userAttrs)
    {
        /* Roles */
        auto roles = _uIntFieldRolesOfJsonUIntFc(jsonFc);

        /* Create field class */
        if (type == strings::fixedLenUInt) {
            return createFixedLenUIntFc(align, len, byteOrder, prefDispBase, std::move(roles),
                                        std::move(userAttrs));
        } else {
            BT_ASSERT(type == strings::fixedLenUEnum);
            return _fcFromJsonFixedLenUEnumFc(jsonFc, align, len, byteOrder, prefDispBase,
                                              std::move(roles), std::move(userAttrs));
        }
    }

    /*
     * Creates and returns a fixed-length signed enumeration field class
     * from the JSON fixed-length signed enumeration field class value
     * `jsonFc` and the other parameters.
     */
    static Fc::UP _fcFromJsonFixedLenSEnumFc(const bt2c::JsonObjVal& jsonFc,
                                             const unsigned int align, const bt2c::DataLen len,
                                             const ir::ByteOrder byteOrder,
                                             const ir::DispBase prefDispBase,
                                             ir::OptUserAttrs&& userAttrs)
    {
        /* Mappings */
        auto mappings = _enumFcMappingsOfJsonEnumFc<FixedLenSEnumFc>(jsonFc);

        /* Create field class */
        return createFixedLenSEnumFc(align, len, byteOrder, std::move(mappings), prefDispBase,
                                     std::move(userAttrs));
    }

    /*
     * Creates and returns a fixed-length signed integer field class
     * from the JSON fixed-length signed integer field class value
     * `jsonFc` and the other parameters.
     */
    static Fc::UP _fcFromJsonFixedLenSIntFc(const bt2c::JsonObjVal& jsonFc, const std::string& type,
                                            const unsigned int align, const bt2c::DataLen len,
                                            const ir::ByteOrder byteOrder,
                                            const ir::DispBase prefDispBase,
                                            ir::OptUserAttrs&& userAttrs)
    {
        if (type == strings::fixedLenSInt) {
            return createFixedLenSIntFc(align, len, byteOrder, prefDispBase, std::move(userAttrs));
        } else {
            BT_ASSERT(type == strings::fixedLenSEnum);
            return _fcFromJsonFixedLenSEnumFc(jsonFc, align, len, byteOrder, prefDispBase,
                                              std::move(userAttrs));
        }
    }

    /*
     * Returns the preferred display base of the JSON integer field
     * class value `jsonFc`.
     */
    static ir::DispBase _prefDispBaseOfJsonIntFc(const bt2c::JsonObjVal& jsonFc) noexcept
    {
        return static_cast<ir::DispBase>(jsonFc.rawVal(strings::prefDispBase, 10ULL));
    }

    /*
     * Creates and returns a fixed-length integer field class from the
     * JSON fixed-length integer field class value `jsonFc` and the
     * other parameters.
     */
    static Fc::UP _fcFromJsonFixedLenIntFc(const bt2c::JsonObjVal& jsonFc, const std::string& type,
                                           const unsigned int align, const bt2c::DataLen len,
                                           const ir::ByteOrder byteOrder,
                                           ir::OptUserAttrs&& userAttrs)
    {
        /* Preferred display base */
        const auto prefDispBase = _prefDispBaseOfJsonIntFc(jsonFc);

        /* Create field class */
        if (type == strings::fixedLenUInt || type == strings::fixedLenUEnum) {
            return _fcFromJsonFixedLenUIntFc(jsonFc, type, align, len, byteOrder, prefDispBase,
                                             std::move(userAttrs));
        } else {
            BT_ASSERT(type == strings::fixedLenSInt || type == strings::fixedLenSEnum);
            return _fcFromJsonFixedLenSIntFc(jsonFc, type, align, len, byteOrder, prefDispBase,
                                             std::move(userAttrs));
        }
    }

    /*
     * Returns the length of the JSON field class value `jsonFc`.
     */
    static unsigned long long _lenOfJsonFc(const bt2c::JsonObjVal& jsonFc) noexcept
    {
        return jsonFc.rawUIntVal(strings::len);
    }

    /*
     * Creates and returns a fixed-length bit array field class from the
     * JSON fixed-length bit array field class value `jsonFc` and the
     * other parameters.
     */
    static Fc::UP _fcFromJsonFixedLenBitArrayFc(const bt2c::JsonObjVal& jsonFc,
                                                const std::string& type,
                                                ir::OptUserAttrs&& userAttrs)
    {
        /* Alignment */
        const auto align = jsonFc.rawVal(strings::align, 1ULL);

        /* Length */
        const auto len = bt2c::DataLen::fromBits(_lenOfJsonFc(jsonFc));

        /* Byte order */
        const auto byteOrder = jsonFc.rawStrVal(strings::byteOrder) == strings::littleEndian ?
                                   ir::ByteOrder::LITTLE :
                                   ir::ByteOrder::BIG;

        /* Create field class */
        if (type == strings::fixedLenBitArray) {
            return createFixedLenBitArrayFc(align, len, byteOrder, std::move(userAttrs));
        } else if (type == strings::fixedLenBool) {
            return createFixedLenBoolFc(align, len, byteOrder, std::move(userAttrs));
        } else if (type == strings::fixedLenUInt || type == strings::fixedLenSInt ||
                   type == strings::fixedLenUEnum || type == strings::fixedLenSEnum) {
            return _fcFromJsonFixedLenIntFc(jsonFc, type, align, len, byteOrder,
                                            std::move(userAttrs));
        } else {
            BT_ASSERT(type == strings::fixedLenFloat);
            return createFixedLenFloatFc(align, len, byteOrder, std::move(userAttrs));
        }
    }

    /*
     * Creates and returns a variable-length unsigned enumeration field
     * class from the JSON variable-length unsigned enumeration field
     * class value `jsonFc` and the other parameters.
     */
    static Fc::UP _fcFromJsonVarLenUEnumFc(const bt2c::JsonObjVal& jsonFc,
                                           const ir::DispBase prefDispBase,
                                           ir::UIntFieldRoles&& roles, ir::OptUserAttrs&& userAttrs)
    {
        /* Mappings */
        auto mappings = _enumFcMappingsOfJsonEnumFc<VarLenUEnumFc>(jsonFc);

        /* Create field class */
        return createVarLenUEnumFc(std::move(mappings), prefDispBase, std::move(roles),
                                   std::move(userAttrs));
    }

    /*
     * Creates and returns a variable-length unsigned integer field
     * class from the JSON variable-length unsigned integer field class
     * value `jsonFc` and the other parameters.
     */
    static Fc::UP _fcFromJsonVarLenUIntFc(const bt2c::JsonObjVal& jsonFc, const std::string& type,
                                          const ir::DispBase prefDispBase,
                                          ir::OptUserAttrs&& userAttrs)
    {
        /* Roles */
        auto roles = _uIntFieldRolesOfJsonUIntFc(jsonFc);

        /* Create field class */
        if (type == strings::varLenUInt) {
            return createVarLenUIntFc(prefDispBase, std::move(roles), std::move(userAttrs));
        } else {
            BT_ASSERT(type == strings::varLenUEnum);
            return _fcFromJsonVarLenUEnumFc(jsonFc, prefDispBase, std::move(roles),
                                            std::move(userAttrs));
        }
    }

    /*
     * Creates and returns a variable-length signed enumeration field
     * class from the JSON variable-length signed enumeration field
     * class value `jsonFc` and the other parameters.
     */
    static Fc::UP _fcFromJsonVarLenSEnumFc(const bt2c::JsonObjVal& jsonFc,
                                           const ir::DispBase prefDispBase,
                                           ir::OptUserAttrs&& userAttrs)
    {
        /* Mappings */
        auto mappings = _enumFcMappingsOfJsonEnumFc<VarLenSEnumFc>(jsonFc);

        /* Create field class */
        return createVarLenSEnumFc(std::move(mappings), prefDispBase, std::move(userAttrs));
    }

    /*
     * Creates and returns a variable-length signed integer field class
     * from the JSON variable-length signed integer field class value
     * `jsonFc` and the other parameters.
     */
    static Fc::UP _fcFromJsonVarLenSIntFc(const bt2c::JsonObjVal& jsonFc, const std::string& type,
                                          const ir::DispBase prefDispBase,
                                          ir::OptUserAttrs&& userAttrs)
    {
        if (type == strings::fixedLenSInt) {
            return createVarLenSIntFc(prefDispBase, std::move(userAttrs));
        } else {
            BT_ASSERT(type == strings::varLenSEnum);
            return _fcFromJsonVarLenSEnumFc(jsonFc, prefDispBase, std::move(userAttrs));
        }
    }

    /*
     * Creates and returns a variable-length integer field class from
     * the JSON variable-length integer field class value `jsonFc` and
     * the other parameters.
     */
    static Fc::UP _fcFromJsonVarLenIntFc(const bt2c::JsonObjVal& jsonFc, const std::string& type,
                                         ir::OptUserAttrs&& userAttrs)
    {
        /* Preferred display base */
        const auto prefDispBase = _prefDispBaseOfJsonIntFc(jsonFc);

        if (type == strings::varLenUInt || type == strings::varLenUEnum) {
            return _fcFromJsonVarLenUIntFc(jsonFc, type, prefDispBase, std::move(userAttrs));
        } else {
            BT_ASSERT(type == strings::varLenSInt || type == strings::varLenSEnum);
            return _fcFromJsonVarLenSIntFc(jsonFc, type, prefDispBase, std::move(userAttrs));
        }
    }

    /*
     * Creates and returns the field location of the JSON field class
     * value `jsonFc` from its `key` property.
     */
    static std::pair<FieldLoc, bt2c::TextLoc> _fieldLocOfJsonFc(const bt2c::JsonObjVal& jsonFc,
                                                                const std::string& key)
    {
        auto& jsonLoc = jsonFc[key]->asArray();

        /* Scope */
        const auto scope = [&jsonLoc] {
            auto& scopeName = *(*jsonLoc.begin())->asStr();

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

        /* Items */
        FieldLoc::Items items;

        std::transform(jsonLoc.begin() + 1, jsonLoc.end(), std::back_inserter(items),
                       [](const bt2c::JsonVal::UP& jsonItem) {
                           return *jsonItem->asStr();
                       });

        /* Create field location */
        return {createFieldLoc(scope, std::move(items)), jsonLoc.loc()};
    }

    /*
     * Creates and returns a dynamic-length string field class from the
     * JSON dynamic-length string field class value `jsonFc` and from
     * `userAttrs`.
     */
    Fc::UP _fcFromJsonDynLenStrFc(const bt2c::JsonObjVal& jsonFc, ir::OptUserAttrs&& userAttrs)
    {
        /* Length field location */
        auto fieldLocTextLocPair = _fieldLocOfJsonFc(jsonFc, strings::lenFieldLoc);

        try {
            this->_validateLenJsonDeps(jsonFc, fieldLocTextLocPair.first,
                                       fieldLocTextLocPair.second);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_RETHROW("[{}] Invalid dynamic-length string field class.",
                                                textLocStr(jsonFc));
        }

        /* Create field class */
        return createDynLenStrFc(std::move(fieldLocTextLocPair.first), std::move(userAttrs));
    }

    /*
     * Creates and returns a non-null-terminated string field class from
     * the JSON non-null-terminated string field class value `jsonFc`
     * and the other parameters.
     */
    Fc::UP _fcFromJsonNonNullTerminatedStrFc(const bt2c::JsonObjVal& jsonFc,
                                             const std::string& type, ir::OptUserAttrs&& userAttrs)
    {
        if (type == strings::staticLenStr) {
            return createStaticLenStrFc(_lenOfJsonFc(jsonFc), std::move(userAttrs));
        } else {
            BT_ASSERT(type == strings::dynLenStr);
            return this->_fcFromJsonDynLenStrFc(jsonFc, std::move(userAttrs));
        }
    }

    /*
     * Creates and returns a static-length BLOB field class from the
     * JSON static-length BLOB field class value `jsonFc` and the other
     * parameters.
     */
    static Fc::UP _fcFromJsonStaticLenBlobFc(const bt2c::JsonObjVal& jsonFc,
                                             const char * const mediaType,
                                             ir::OptUserAttrs&& userAttrs)
    {
        /* Has metadata stream UUID role? */
        const auto jsonRoles = jsonFc[strings::roles];
        const auto hasMetadataStreamUuidRole = jsonRoles && jsonRoles->asArray().size() > 0;

        /* Create field class */
        return createStaticLenBlobFc(_lenOfJsonFc(jsonFc), mediaType, hasMetadataStreamUuidRole,
                                     std::move(userAttrs));
    }

    /*
     * Creates and returns a dynamic-length BLOB field class from the
     * JSON dynamic-length BLOB field class value `jsonFc` and the other
     * parameters.
     */
    Fc::UP _fcFromJsonDynLenBlobFc(const bt2c::JsonObjVal& jsonFc, const char * const mediaType,
                                   ir::OptUserAttrs&& userAttrs)
    {
        /* Length field location */
        auto fieldLocTextLocPair = _fieldLocOfJsonFc(jsonFc, strings::lenFieldLoc);

        try {
            this->_validateLenJsonDeps(jsonFc, fieldLocTextLocPair.first,
                                       fieldLocTextLocPair.second);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_RETHROW("[{}] Invalid dynamic-length BLOB field class.",
                                                textLocStr(jsonFc));
        }

        /* Create field class */
        return createDynLenBlobFc(std::move(fieldLocTextLocPair.first), mediaType,
                                  std::move(userAttrs));
    }

    /*
     * Creates and returns a BLOB field class from the JSON BLOB field
     * class value `jsonFc` and the other parameters.
     */
    Fc::UP _fcFromJsonBlobFc(const bt2c::JsonObjVal& jsonFc, const std::string& type,
                             ir::OptUserAttrs&& userAttrs)
    {
        /* Media type */
        const auto mediaType = jsonFc.rawVal(strings::mediaType, BlobFc::defaultMediaType);

        /* Create field class */
        if (type == strings::staticLenBlob) {
            return this->_fcFromJsonStaticLenBlobFc(jsonFc, mediaType, std::move(userAttrs));
        } else {
            BT_ASSERT(type == strings::dynLenBlob);
            return this->_fcFromJsonDynLenBlobFc(jsonFc, mediaType, std::move(userAttrs));
        }
    }

    /*
     * Creates and returns a dynamic-length array field class from the
     * JSON dynamic-length array field class value `jsonFc` and the
     * other parameters.
     */
    Fc::UP _fcFromJsonDynLenArrayFc(const bt2c::JsonObjVal& jsonFc, Fc::UP elemFc,
                                    const unsigned int minAlign, ir::OptUserAttrs&& userAttrs)
    {
        /* Length field location */
        auto fieldLocTextLocPair = _fieldLocOfJsonFc(jsonFc, strings::lenFieldLoc);

        try {
            this->_validateLenJsonDeps(jsonFc, fieldLocTextLocPair.first,
                                       fieldLocTextLocPair.second);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_RETHROW("[{}] Invalid dynamic-length array field class.",
                                                textLocStr(jsonFc));
        }

        /* Create field class */
        return createDynLenArrayFc(std::move(fieldLocTextLocPair.first), std::move(elemFc),
                                   minAlign, std::move(userAttrs));
    }

    /*
     * Returns the minimum alignment of the JSON field class value
     * `jsonFc`.
     */
    static unsigned long long _minAlignOfJsonFc(const bt2c::JsonObjVal& jsonFc) noexcept
    {
        return jsonFc.rawVal(strings::minAlign, 1ULL);
    }

    /*
     * In this order:
     *
     * 1. Marks the underlying field class at the index `index` of the
     *    JSON compound field class `jsonFc` as being currently
     *    visited.
     *
     * 2. Calls `func()`.
     *
     * 3. Cancels 1.
     */
    template <typename FuncT>
    void _withinCompoundFc(const bt2c::JsonObjVal& jsonFc, const std::size_t index, FuncT&& func)
    {
        BT_ASSERT(_mCompoundFcIndexes.find(&jsonFc) == _mCompoundFcIndexes.end());
        _mCompoundFcIndexes.emplace(std::make_pair(&jsonFc, index));
        func();
        _mCompoundFcIndexes.erase(&jsonFc);
    }

    /*
     * In this order:
     *
     * 1. Marks the JSON compound field class `jsonFc` as being
     *    currently visited.
     *
     * 2. Calls `func()`.
     *
     * 3. Cancels 1.
     */
    template <typename FuncT>
    void _withinCompoundFc(const bt2c::JsonObjVal& jsonFc, FuncT&& func)
    {
        this->_withinCompoundFc(jsonFc, 0, std::forward<FuncT>(func));
    }

    /*
     * Creates and returns am array field class from the JSON array
     * field class value `jsonFc` and the other parameters.
     */
    Fc::UP _fcFromJsonArrayFc(const bt2c::JsonObjVal& jsonFc, const std::string& type,
                              ir::OptUserAttrs&& userAttrs)
    {
        /* Element field class */
        Fc::UP elemFc;

        try {
            this->_withinCompoundFc(jsonFc, [&jsonFc, &elemFc, this] {
                elemFc = this->_fcFromJsonVal(*jsonFc[strings::elemFc]);
            });
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_RETHROW("[{}] Invalid array field class.",
                                                textLocStr(jsonFc));
        }

        /* Minimum alignment */
        const auto minAlign = this->_minAlignOfJsonFc(jsonFc);

        /* Create field class */
        if (type == strings::staticLenArray) {
            return createStaticLenArrayFc(_lenOfJsonFc(jsonFc), std::move(elemFc), minAlign,
                                          std::move(userAttrs));
        } else {
            BT_ASSERT(type == strings::dynLenArray);
            return this->_fcFromJsonDynLenArrayFc(jsonFc, std::move(elemFc), minAlign,
                                                  std::move(userAttrs));
        }
    }

    /*
     * Creates and returns a structure field class from the JSON
     * structure field class value `jsonFc` and from `userAttrs`.
     */
    Fc::UP _fcFromJsonStructFc(const bt2c::JsonObjVal& jsonFc, ir::OptUserAttrs&& userAttrs)
    {
        /* Minimum alignment */
        const auto minAlign = this->_minAlignOfJsonFc(jsonFc);

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
                            name, this->_fcFromJsonVal(*jsonMemberClsObj[strings::fc]),
                            userAttrsOfObj(jsonMemberClsObj)));
                    } catch (const bt2c::Error&) {
                        BT_CPPLOGE_APPEND_CAUSE_AND_RETHROW(
                            "[{}] Invalid structure field member class `{}`.",
                            textLocStr(*jsonMemberCls), name);
                    }
                }
            }
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_RETHROW("[{}] Invalid structure field class.",
                                                textLocStr(jsonFc));
        }

        /* Create field class */
        return createStructFc(std::move(memberClasses), minAlign, std::move(userAttrs));
    }

    /*
     * Creates and returns an optional field class from the JSON
     * optional (with an integer selector) field class value `jsonFc`
     * and the other parameters.
     */
    template <typename OptionalFcT, typename IntRangeSetValReqT>
    Fc::UP _optionalWithIntSelFcFromJsonOptionalFc(const bt2c::JsonObjVal& jsonFc,
                                                   const char * const signednessWord,
                                                   FieldLoc&& fieldLoc, Fc::UP fc,
                                                   ir::OptUserAttrs&& userAttrs)
    {
        auto& jsonSelFieldRanges = *jsonFc[strings::selFieldRanges];

        try {
            IntRangeSetValReqT {_mLogger, bt2c::TextLocStrFmt::Offset}.validate(jsonSelFieldRanges);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_RETHROW(
                "[{}] Invalid selector field ranges: expecting {} integer ranges.",
                textLocStr(jsonSelFieldRanges), signednessWord);
        }

        return createOptionalFc(std::move(fc), std::move(fieldLoc),
                                this->_intRangeSetFromJsonIntRangeSet<typename OptionalFcT::SelVal>(
                                    jsonSelFieldRanges.asArray()),
                                std::move(userAttrs));
    }

    /*
     * Creates and returns an optional field class from the JSON
     * optional field class value `jsonFc` and from `userAttrs`.
     */
    Fc::UP _fcFromJsonOptionalFc(const bt2c::JsonObjVal& jsonFc, ir::OptUserAttrs&& userAttrs)
    {
        try {
            /* Selector field location */
            auto fieldLocTextLocPair = _fieldLocOfJsonFc(jsonFc, strings::selFieldLoc);

            /* Optional field class */
            Fc::UP fc;

            this->_withinCompoundFc(jsonFc, [&jsonFc, &fc, this] {
                fc = this->_fcFromJsonVal(*jsonFc[strings::fc]);
            });

            /* Get dependencies */
            const auto jsonDeps =
                this->_findJsonDeps(jsonFc, fieldLocTextLocPair.first, fieldLocTextLocPair.second);
            const auto jsonDepType = this->_jsonDepType(**jsonDeps.begin());

            if (jsonDepType == _JsonDepType::BOOL) {
                return createOptionalFc(std::move(fc), std::move(fieldLocTextLocPair.first),
                                        std::move(userAttrs));
            } else {
                if (jsonDepType == _JsonDepType::UINT) {
                    return this->_optionalWithIntSelFcFromJsonOptionalFc<
                        OptionalWithUIntSelFc, Ctf2JsonUIntRangeSetValReq>(
                        jsonFc, "unsigned", std::move(fieldLocTextLocPair.first), std::move(fc),
                        std::move(userAttrs));
                } else {
                    BT_ASSERT(jsonDepType == _JsonDepType::SINT);
                    return this->_optionalWithIntSelFcFromJsonOptionalFc<
                        OptionalWithSIntSelFc, Ctf2JsonSIntRangeSetValReq>(
                        jsonFc, "signed", std::move(fieldLocTextLocPair.first), std::move(fc),
                        std::move(userAttrs));
                }
            }
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_RETHROW("[{}] Invalid optional field class.",
                                                textLocStr(jsonFc));
        }
    }

    /*
     * Creates and returns a variant field class from the JSON variant
     * field class value `jsonFc` and from the other parameters (generic
     * version).
     */
    template <typename VariantFcT, typename IntRangeSetValReqT>
    Fc::UP _variantFcFromJsonVariantFc(const bt2c::JsonObjVal& jsonFc,
                                       const char * const signednessWord, FieldLoc&& fieldLoc,
                                       ir::OptUserAttrs&& userAttrs)
    {
        auto& jsonOpts = jsonFc[strings::opts]->asArray();
        typename VariantFcT::Opts opts;

        for (auto it = jsonOpts.begin(); it != jsonOpts.end(); ++it) {
            auto& jsonOpt = (*it)->asObj();
            auto& jsonSelFieldRanges = *jsonOpt[strings::selFieldRanges];

            /* Validate selector field ranges */
            try {
                IntRangeSetValReqT {_mLogger, bt2c::TextLocStrFmt::Offset}.validate(
                    jsonSelFieldRanges);
            } catch (const bt2c::Error&) {
                BT_CPPLOGE_APPEND_CAUSE_AND_RETHROW(
                    "[{}] Invalid selector field ranges: expecting {} integer ranges.",
                    textLocStr(jsonSelFieldRanges), signednessWord);
            }

            Fc::UP optFc;

            /* Create field class of option */
            this->_withinCompoundFc(jsonFc, it - jsonOpts.begin(), [this, &jsonOpt, &optFc] {
                optFc = this->_fcFromJsonVal(*jsonOpt[strings::fc]);
            });

            /* Create option */
            auto opt = createVariantFcOpt(
                std::move(optFc),
                this->_intRangeSetFromJsonIntRangeSet<typename VariantFcT::SelVal>(
                    jsonSelFieldRanges.asArray()),
                optStrOfObj(jsonOpt, strings::name), userAttrsOfObj(jsonOpt));

            /* Append option */
            opts.emplace_back(std::move(opt));
        }

        return createVariantFc(std::move(opts), std::move(fieldLoc), std::move(userAttrs));
    }

    /*
     * Creates and returns a variant field class from the JSON variant
     * field class value `jsonFc` and from `userAttrs`.
     */
    Fc::UP _fcFromJsonVariantFc(const bt2c::JsonObjVal& jsonFc, ir::OptUserAttrs&& userAttrs)
    {
        try {
            /* Selector field location */
            auto fieldLocTextLocPair = _fieldLocOfJsonFc(jsonFc, strings::selFieldLoc);

            const auto jsonDeps =
                this->_findJsonDeps(jsonFc, fieldLocTextLocPair.first, fieldLocTextLocPair.second);
            const auto jsonDepType = this->_jsonDepType(**jsonDeps.begin());

            if (jsonDepType == _JsonDepType::UINT) {
                return this
                    ->_variantFcFromJsonVariantFc<VariantWithUIntSelFc, Ctf2JsonUIntRangeSetValReq>(
                        jsonFc, "unsigned", std::move(fieldLocTextLocPair.first),
                        std::move(userAttrs));
            } else if (jsonDepType == _JsonDepType::SINT) {
                return this
                    ->_variantFcFromJsonVariantFc<VariantWithSIntSelFc, Ctf2JsonSIntRangeSetValReq>(
                        jsonFc, "signed", std::move(fieldLocTextLocPair.first),
                        std::move(userAttrs));
            } else {
                BT_ASSERT(jsonDepType == _JsonDepType::BOOL);
                BT_CPPLOGE_APPEND_CAUSE_AND_THROW(
                    bt2c::Error,
                    "[{}] Selector field location {} locates one or more boolean field classes: "
                    "expecting unsigned or signed integer field classes.",
                    textLocStr(fieldLocTextLocPair.second),
                    this->_fieldLocStr(fieldLocTextLocPair.first, fieldLocTextLocPair.first.end()));
            }
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_RETHROW("[{}] Invalid variant field class.",
                                                textLocStr(jsonFc));
        }
    }

    /*
     * Returns a string representation of `fieldLoc`, considering all
     * its path items until `end` (excluded).
     */
    static std::string _fieldLocStr(const FieldLoc& fieldLoc,
                                    const FieldLoc::Items::const_iterator end)
    {
        std::ostringstream ss;

        ss << '[' << scopeStr(fieldLoc.scope());

        for (auto it = fieldLoc.begin(); it != end; ++it) {
            ss << ", `" << *it << '`';
        }

        ss << ']';
        return ss.str();
    }

    /*
     * Adds to `jsonDeps` the dependencies of `jsonDependentFc`, using
     * the field location `fieldLoc`, from `jsonBaseFc` and the field
     * location item iterator `fieldLocIt`.
     *
     * Returns `true` if `jsonDependentFc` isn't reached yet (safe to
     * continue to find dependencies).
     */
    bool _findJsonDeps(const bt2c::JsonObjVal& jsonBaseFc, const bt2c::JsonObjVal& jsonDependentFc,
                       const FieldLoc& fieldLoc, const FieldLoc::Items::const_iterator fieldLocIt,
                       _JsonFcSet& jsonDeps) const
    {
        /* Type */
        auto& type = jsonBaseFc.rawStrVal(strings::type);

        if (type == strings::fixedLenBool || type == strings::fixedLenUInt ||
            type == strings::fixedLenUEnum || type == strings::fixedLenSInt ||
            type == strings::fixedLenSEnum || type == strings::varLenUInt ||
            type == strings::varLenUEnum || type == strings::varLenSInt ||
            type == strings::varLenSEnum) {
            if (fieldLocIt != fieldLoc.end()) {
                BT_CPPLOGE_APPEND_CAUSE_AND_THROW(
                    bt2c::Error, "[{}] Cannot reach anything beyond a scalar field class for {}.",
                    textLocStr(jsonBaseFc), this->_fieldLocStr(fieldLoc, fieldLocIt + 1));
            }

            jsonDeps.insert(&jsonBaseFc);
            return true;
        } else if (type == strings::structure) {
            if (fieldLocIt == fieldLoc.end()) {
                BT_CPPLOGE_APPEND_CAUSE_AND_THROW(
                    bt2c::Error, "[{}] Field location must not locate a structure field class.",
                    textLocStr(jsonBaseFc));
            }

            /* Find the member class named `*fieldLocIt` */
            const auto jsonMemberClasses = jsonBaseFc[strings::memberClasses];

            if (jsonMemberClasses) {
                for (auto& jsonMemberCls : jsonMemberClasses->asArray()) {
                    auto& jsonMemberClsObj = jsonMemberCls->asObj();
                    const auto jsonMemberClsFc = jsonMemberClsObj[strings::fc];

                    if (jsonMemberClsFc == &jsonDependentFc) {
                        /* Reached the dependent field class */
                        return false;
                    }

                    if (jsonMemberClsObj.rawStrVal(strings::name) != *fieldLocIt) {
                        continue;
                    }

                    return this->_findJsonDeps(jsonMemberClsObj[strings::fc]->asObj(),
                                               jsonDependentFc, fieldLoc, fieldLocIt + 1, jsonDeps);
                }
            }

            /* Member class not found */
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error,
                                              "[{}] At field location {}: "
                                              "no structure field member class named `{}`.",
                                              textLocStr(jsonBaseFc),
                                              this->_fieldLocStr(fieldLoc, fieldLocIt),
                                              fieldLocIt->c_str());
        } else if (type == strings::staticLenArray || type == strings::dynLenArray) {
            if (_mCompoundFcIndexes.find(&jsonBaseFc) == _mCompoundFcIndexes.end()) {
                BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error,
                                                  "[{}] At field location {}: "
                                                  "unreachable array field element.",
                                                  textLocStr(jsonBaseFc),
                                                  this->_fieldLocStr(fieldLoc, fieldLocIt));
            }

            const auto jsonElemFc = jsonBaseFc[strings::elemFc];

            if (jsonElemFc == &jsonDependentFc) {
                /* Reached the dependent field class */
                return false;
            }

            return this->_findJsonDeps(jsonElemFc->asObj(), jsonDependentFc, fieldLoc, fieldLocIt,
                                       jsonDeps);
        } else if (type == strings::optional) {
            if (_mCompoundFcIndexes.find(&jsonBaseFc) == _mCompoundFcIndexes.end()) {
                BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error,
                                                  "[{}] At field location {}: "
                                                  "unreachable optional field.",
                                                  textLocStr(jsonBaseFc),
                                                  this->_fieldLocStr(fieldLoc, fieldLocIt));
            }

            const auto jsonOptionalFc = jsonBaseFc[strings::fc];

            if (jsonOptionalFc == &jsonDependentFc) {
                /* Reached the dependent field class */
                return false;
            }

            return this->_findJsonDeps(jsonOptionalFc->asObj(), jsonDependentFc, fieldLoc,
                                       fieldLocIt, jsonDeps);
        } else if (type == strings::variant) {
            auto& jsonOpts = jsonBaseFc[strings::opts]->asArray();
            const auto curOptIndexIt = _mCompoundFcIndexes.find(&jsonBaseFc);

            if (curOptIndexIt == _mCompoundFcIndexes.end()) {
                /*
                 * Not currently visiting this JSON variant field class
                 * value: consider all options.
                 */
                for (auto& jsonOpt : jsonOpts) {
                    auto& jsonOptObj = jsonOpt->asObj();
                    const auto jsonOptFc = jsonOptObj[strings::fc];

                    if (jsonOptFc == &jsonDependentFc) {
                        /* Reached the dependent field class */
                        return false;
                    }

                    if (!this->_findJsonDeps(jsonOptFc->asObj(), jsonDependentFc, fieldLoc,
                                             fieldLocIt, jsonDeps)) {
                        /* Reached the dependent field class */
                        return false;
                    }
                }
            } else {
                /*
                 * Currently visiting this JSON variant field class
                 * value: consider only the currently visited option.
                 */
                const auto jsonOptFc = jsonOpts[curOptIndexIt->second].asObj()[strings::fc];

                if (jsonOptFc == &jsonDependentFc) {
                    /* Reached the dependent field class */
                    return false;
                }

                return this->_findJsonDeps(jsonOptFc->asObj(), jsonDependentFc, fieldLoc,
                                           fieldLocIt, jsonDeps);
            }

            return true;
        } else {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error,
                                              "[{}] At field location {}: "
                                              "unexpected field class with type `{}`.",
                                              textLocStr(jsonBaseFc),
                                              this->_fieldLocStr(fieldLoc, fieldLocIt), type);
        }
    }

    static _JsonDepType _jsonDepType(const bt2c::JsonVal& jsonFc)
    {
        auto& type = jsonFc.asObj().rawStrVal(strings::type);

        if (type == strings::fixedLenBool) {
            return _JsonDepType::BOOL;
        } else if (type == strings::fixedLenUInt || type == strings::fixedLenUEnum ||
                   type == strings::varLenUInt || type == strings::varLenUEnum) {
            return _JsonDepType::UINT;
        } else {
            BT_ASSERT(type == strings::fixedLenSInt || type == strings::fixedLenSEnum ||
                      type == strings::varLenSInt || type == strings::varLenSEnum);
            return _JsonDepType::SINT;
        }
    };

    const bt2c::JsonObjVal& _jsonScopeFc(const FieldLoc& fieldLoc,
                                         const bt2c::TextLoc& fieldLocLoc) const
    {
        const auto jsonScopeFc = [this, &fieldLoc, &fieldLocLoc] {
            switch (fieldLoc.scope()) {
            case ir::FieldLocScope::PKT_HEADER:
                if (!_mJsonTraceCls) {
                    BT_CPPLOGE_APPEND_CAUSE_AND_THROW(
                        bt2c::Error, "[{}] Missing trace class fragment.", textLocStr(fieldLocLoc));
                }

                return (*_mJsonTraceCls)[strings::pktHeaderFc];
            case ir::FieldLocScope::PKT_CTX:
            case ir::FieldLocScope::EVENT_RECORD_HEADER:
            case ir::FieldLocScope::EVENT_RECORD_COMMON_CTX:
                if (!_mJsonDataStreamCls) {
                    BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error,
                                                      "[{}] Missing data stream class fragment.",
                                                      textLocStr(fieldLocLoc));
                }

                switch (fieldLoc.scope()) {
                case ir::FieldLocScope::PKT_CTX:
                    return (*_mJsonDataStreamCls)[strings::pktCtxFc];
                case ir::FieldLocScope::EVENT_RECORD_HEADER:
                    return (*_mJsonDataStreamCls)[strings::eventRecordHeaderFc];
                case ir::FieldLocScope::EVENT_RECORD_COMMON_CTX:
                    return (*_mJsonDataStreamCls)[strings::eventRecordCommonCtxFc];
                default:
                    bt_common_abort();
                }
            case ir::FieldLocScope::EVENT_RECORD_SPEC_CTX:
            case ir::FieldLocScope::EVENT_RECORD_PAYLOAD:
                if (!_mJsonEventRecordCls) {
                    BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error,
                                                      "[{}] Missing event record class fragment.",
                                                      textLocStr(fieldLocLoc));
                }

                if (fieldLoc.scope() == ir::FieldLocScope::EVENT_RECORD_SPEC_CTX) {
                    return (*_mJsonEventRecordCls)[strings::specCtxFc];
                } else {
                    BT_ASSERT(fieldLoc.scope() == ir::FieldLocScope::EVENT_RECORD_PAYLOAD);
                    return (*_mJsonEventRecordCls)[strings::payloadFc];
                }
            default:
                bt_common_abort();
            }
        }();

        if (!jsonScopeFc) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error, "[{}] Missing scope field class.",
                                              textLocStr(fieldLocLoc));
        }

        return jsonScopeFc->asObj();
    }

    /*
     * Finds the dependencies of `jsonDependentFc` using the field
     * location `fieldLoc`.
     *
     * This method only considers JSON boolean and integer field class
     * values as dependencies, throwing `bt2c::TextParseError` when it
     * finds anything else.
     *
     * This method doesn't add to the returned set JSON field class
     * values which occur after `jsonDependentFc` .
     *
     * This method also throws if:
     *
     * • `fieldLoc` is invalid.
     * • `fieldLoc` locates JSON field class values.
     * • `fieldLoc` doesn't locate any JSON field class value.
     */
    _JsonFcSet _findJsonDeps(const bt2c::JsonObjVal& jsonDependentFc, const FieldLoc& fieldLoc,
                             const bt2c::TextLoc& fieldLocLoc) const
    {
        try {
            /* Find dependencies and returns them */
            _JsonFcSet jsonDeps;

            this->_findJsonDeps(this->_jsonScopeFc(fieldLoc, fieldLocLoc), jsonDependentFc,
                                fieldLoc, fieldLoc.begin(), jsonDeps);

            /* Validate that `jsonDeps` contains at least one item */
            if (jsonDeps.empty()) {
                BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error,
                                                  "[{}] Field location doesn't locate anything.",
                                                  textLocStr(fieldLocLoc));
            }

            /*
             * Validate that all the items of `jsonDeps` have the same
             * type.
             */
            {
                const auto expectedType = this->_jsonDepType(**jsonDeps.begin());

                for (const auto jsonFc : jsonDeps) {
                    if (this->_jsonDepType(*jsonFc) != expectedType) {
                        BT_CPPLOGE_APPEND_CAUSE_AND_THROW(
                            bt2c::Error,
                            "[{}] Field location locates field classes having different types.",
                            textLocStr(fieldLocLoc));
                    }
                }
            }

            /* Return the set */
            return jsonDeps;
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_RETHROW("[{}] Invalid field location {}.",
                                                textLocStr(fieldLocLoc),
                                                this->_fieldLocStr(fieldLoc, fieldLoc.end()));
        }
    }

    /*
     * Validates the dependencies of the JSON dynamic-length field class
     * value `jsonDependentFc` as located by `fieldLoc`.
     */
    void _validateLenJsonDeps(const bt2c::JsonObjVal& jsonDependentFc, const FieldLoc& fieldLoc,
                              const bt2c::TextLoc& fieldLocLoc) const
    {
        const auto jsonDeps = this->_findJsonDeps(jsonDependentFc, fieldLoc, fieldLocLoc);

        BT_ASSERT(!jsonDeps.empty());

        if (this->_jsonDepType(**jsonDeps.begin()) != _JsonDepType::UINT) {
            try {
                BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error,
                                                  "[{}] Expecting an unsigned integer field class.",
                                                  textLocStr(**jsonDeps.begin()));
            } catch (const bt2c::Error&) {
                BT_CPPLOGE_APPEND_CAUSE_AND_RETHROW("[{}] Invalid field location {}.",
                                                    textLocStr(fieldLocLoc),
                                                    this->_fieldLocStr(fieldLoc, fieldLoc.end()));
            }
        }
    }

    /* Logger */
    bt2c::Logger _mLogger;

    /* Current JSON trace class value, or `nullptr` if none */
    const bt2c::JsonObjVal *_mJsonTraceCls;

    /* Current JSON data stream class value, or `nullptr` if none */
    const bt2c::JsonObjVal *_mJsonDataStreamCls;

    /* Current JSON event record class value, or `nullptr` if none */
    const bt2c::JsonObjVal *_mJsonEventRecordCls;

    /*
     * Map of JSON compound field class value to the index of the
     * currently visited immediate underlying field class, that is:
     *
     * For a JSON variant field class value V:
     *     Index of the option of V containing the field class currently
     *     being visited.
     *
     * For a JSON array field class value V:
     * For a JSON optional field class value V:
     *     0: if V is part of the map, then its element/optional field
     *     class is currently being visited.
     *
     * This is used to provide a visiting context to _findJsonDeps() so
     * as to follow the correct JSON variant field class option value as
     * well as to validate dependencies.
     *
     * Root: Structure FC                                       [0]
     *   `len`: Fixed-length unsigned integer FC                [1]
     *   `meow`: Dynamic-length array FC                        [2]
     *     Element FC: Structure FC                             [3]
     *       `tag`: Fixed-length signed integer FC              [4]
     *       `val`: Variant FC                                  [5]
     *         `boss`: Null-terminated string FC                [6]
     *         `zoom`: Structure FC                             [7]
     *           `len`: Variable-length unsigned integer FC     [8]
     *           `data`: Dynamic-length BLOB FC                 [9]
     *         `line6`: Structure FC                            [10]
     *           `len`: Fixed-length unsigned integer FC        [11]
     *
     * If _findJsonDeps() is currently visiting [9] to find its
     * dependencies, then the map would contain:
     *
     *     [5] -> 1     (visiting second option (`zoom`) of `/meow/val`)
     *
     * This means that, if the length field location of [9] is
     * `/meow/val/len`, then we must only consider the `zoom` option,
     * not the `line6` one, even though both contain a member class
     * named `len`.
     */
    std::unordered_map<const bt2c::JsonVal *, std::size_t> _mCompoundFcIndexes;

    /* Resulting field class */
    Fc::UP _mFc;
};

} /* namespace */

Fc::UP scopeFcFromJsonVal(const bt2c::JsonObjVal& jsonFc,
                          const bt2c::JsonObjVal * const jsonTraceCls,
                          const bt2c::JsonObjVal * const jsonDataStreamCls,
                          const bt2c::JsonObjVal * const jsonEventRecordCls,
                          const bt2c::Logger& parentLogger)
{
    ScopeFcFromJsonVal visitor {jsonFc, jsonTraceCls, jsonDataStreamCls, jsonEventRecordCls,
                                parentLogger};

    return visitor.releaseFc();
}

} /* namespace src */
} /* namespace ctf */
