/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <string>
#include <unordered_set>

#include "common/assert.h"

#include "../../../metadata/json/strings.hpp"
#include "val-req.hpp"

namespace ctf {
namespace src {
namespace {

namespace strings = ctf::json_strings;

/*
 * CTF 2 JSON alignment value requirement.
 */
class AlignValReq final : public bt2c::JsonValHasTypeReq
{
public:
    explicit AlignValReq(const bt2c::ValReqLogCfg& logCfg) noexcept :
        bt2c::JsonValHasTypeReq {bt2c::ValType::UINT, logCfg}
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<AlignValReq>(logCfg);
    }

protected:
    static bool _isPowOfTwo(const unsigned long long val) noexcept
    {
        return ((val & (val - 1)) == 0) && val > 0;
    }

    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        const auto val = *jsonVal.asUInt();

        if (!this->_isPowOfTwo(val)) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2c::Error,
                                                   "[{}] {} is not a power of two.",
                                                   this->_locStr(jsonVal), val);
        }
    }
};

/*
 * CTF 2 JSON byte order value requirement.
 */
class ByteOrderValReq final : public bt2c::JsonStrValInSetReq
{
public:
    explicit ByteOrderValReq(const bt2c::ValReqLogCfg& logCfg) :
        bt2c::JsonStrValInSetReq {
            bt2c::JsonStrValInSetReq::Set {strings::bigEndian, strings::littleEndian}, logCfg}
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<ByteOrderValReq>(logCfg);
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            bt2c::JsonStrValInSetReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(
                this->_logger(), bt2::Error, "[{}] Invalid byte order.", this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 JSON UUID value requirement.
 */
class UuidValReq final : public bt2c::JsonArrayValReq
{
public:
    explicit UuidValReq(const bt2c::ValReqLogCfg& logCfg) :
        bt2c::JsonArrayValReq {16, bt2c::JsonUIntValInRangeReq::shared(0, 255, logCfg), logCfg}
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<UuidValReq>(logCfg);
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            bt2c::JsonArrayValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2::Error,
                                                   "[{}] Invalid UUID.", this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 JSON field location value requirement.
 */
class FieldLocValReq final : public bt2c::JsonArrayValReq
{
public:
    explicit FieldLocValReq(const bt2c::ValReqLogCfg& logCfg) :
        bt2c::JsonArrayValReq {2, bt2s::nullopt,
                               bt2c::JsonValHasTypeReq::shared(bt2c::ValType::STR, logCfg), logCfg},
        _mScopeValReq {{
                           strings::pktHeader,
                           strings::pktCtx,
                           strings::eventRecordHeader,
                           strings::eventRecordCommonCtx,
                           strings::eventRecordSpecCtx,
                           strings::eventRecordPayload,
                       },
                       logCfg}
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<FieldLocValReq>(logCfg);
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            bt2c::JsonArrayValReq::_validate(jsonVal);

            auto& firstJsonItem = jsonVal.asArray()[0];

            try {
                _mScopeValReq.validate(firstJsonItem);
            } catch (const bt2c::Error&) {
                BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2::Error,
                                                       "[{}] Invalid scope name.",
                                                       this->_locStr(firstJsonItem));
            }
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2::Error,
                                                   "[{}] Invalid field location.",
                                                   this->_locStr(jsonVal));
        }
    }

    bt2c::JsonStrValInSetReq _mScopeValReq;
};

/*
 * CTF 2 JSON user attributes value requirement.
 */
class UserAttrsValReq final : public bt2c::JsonObjValReq
{
public:
    explicit UserAttrsValReq(const bt2c::ValReqLogCfg& logCfg) :
        bt2c::JsonObjValReq {{}, true, logCfg}
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<UserAttrsValReq>(logCfg);
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            bt2c::JsonObjValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2::Error,
                                                   "[{}] Invalid user attributes.",
                                                   this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 JSON trace environment value requirement.
 */
class TraceEnvValReq final : public bt2c::JsonObjValReq
{
public:
    explicit TraceEnvValReq(const bt2c::ValReqLogCfg& logCfg) :
        bt2c::JsonObjValReq {{}, true, logCfg}
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<TraceEnvValReq>(logCfg);
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            bt2c::JsonObjValReq::_validate(jsonVal);

            /* Validate types of entries */
            for (auto& keyJsonValPair : jsonVal.asObj()) {
                auto& jsonEntry = keyJsonValPair.second;

                if (!jsonEntry->isUInt() && !jsonEntry->isSInt() && !jsonEntry->isStr()) {
                    BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(
                        this->_logger(), bt2::Error,
                        "[{}] Entry `{}`: expecting an integer or a string.",
                        this->_locStr(*jsonEntry), keyJsonValPair.first);
                }
            }
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2::Error,
                                                   "[{}] Invalid trace environment.",
                                                   this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 JSON extensions value requirement.
 */
class ExtValReq final : public bt2c::JsonObjValReq
{
public:
    explicit ExtValReq(const bt2c::ValReqLogCfg& logCfg) : bt2c::JsonObjValReq {{}, true, logCfg}
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<ExtValReq>(logCfg);
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            bt2c::JsonObjValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(
                this->_logger(), bt2::Error, "[{}] Invalid extensions.", this->_locStr(jsonVal));
        }

        if (jsonVal.asObj().size() > 0) {
            /* Never valid */
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(
                this->_logger(), bt2::Error,
                "[{}] This version of the `ctf` plugin doesn't support any CTF 2 extension.",
                this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 JSON roles value requirement.
 */
class RolesValReq final : public bt2c::JsonArrayValReq
{
public:
    /*
     * Builds a CTF 2 JSON roles value requirement: _validate()
     * validates that a given JSON array value only contains the roles
     * `validRoles`.
     */
    explicit RolesValReq(bt2c::JsonStrValInSetReq::Set validRoles,
                         const bt2c::ValReqLogCfg& logCfg) :
        bt2c::JsonArrayValReq {bt2c::JsonStrValInSetReq::shared(std::move(validRoles), logCfg),
                               logCfg}
    {
    }

    static SP shared(bt2c::JsonStrValInSetReq::Set validRoles, const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<RolesValReq>(std::move(validRoles), logCfg);
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            bt2c::JsonArrayValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2c::Error,
                                                   "[{}] Invalid roles.", this->_locStr(jsonVal));
        }
    }
};

/*
 * Adds a JSON object value property requirement having the key
 * `key` to `propReqs`, passing `valReq` and `isRequired` to its
 * constructor.
 */
void addToPropReqs(bt2c::JsonObjValReq::PropReqs& propReqs, std::string&& key,
                   bt2c::JsonValReq::SP valReq, const bool isRequired = false)
{
    propReqs.emplace(
        std::make_pair(std::move(key), bt2c::JsonObjValPropReq {std::move(valReq), isRequired}));
}

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 object type
 * object property requirement.
 */
bt2c::JsonObjValReq::PropReqsEntry objTypePropReqEntry(std::string&& type,
                                                       const bt2c::ValReqLogCfg& logCfg)
{
    return {strings::type, {bt2c::JsonStrValInSetReq::shared(std::move(type), logCfg), true}};
}

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 user
 * attributes object property requirement.
 */
bt2c::JsonObjValReq::PropReqsEntry userAttrsPropReqEntry(const bt2c::ValReqLogCfg& logCfg)
{
    return {strings::userAttrs, {UserAttrsValReq::shared(logCfg)}};
}

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 extensions object
 * property requirement.
 */
bt2c::JsonObjValReq::PropReqsEntry extPropReqEntry(const bt2c::ValReqLogCfg& logCfg)
{
    return {strings::extensions, {ExtValReq::shared(logCfg)}};
}

/*
 * CTF 2 JSON field class value abstract requirement.
 *
 * All derived classes are required to implement a static typeStr()
 * method which returns the type string of the field class.
 */
class FcValReq : public bt2c::JsonObjValReq
{
protected:
    /*
     * Builds a CTF 2 JSON field class value requirement of type `type`,
     * adding `propReqs` to the base JSON object value property
     * requirements.
     */
    explicit FcValReq(std::string&& type, PropReqs&& propReqs, const bt2c::ValReqLogCfg& logCfg) :
        bt2c::JsonObjValReq {this->_buildPropReqs(std::move(type), std::move(propReqs), logCfg),
                             logCfg}
    {
    }

    /*
     * Builds a CTF 2 JSON field class value requirement of type `type`.
     */
    explicit FcValReq(std::string&& type, const bt2c::ValReqLogCfg& logCfg) :
        FcValReq {std::move(type), {}, logCfg}
    {
    }

private:
    static PropReqs _buildPropReqs(std::string&& type, PropReqs&& propReqs,
                                   const bt2c::ValReqLogCfg& logCfg)
    {
        propReqs.insert(objTypePropReqEntry(std::move(type), logCfg));
        propReqs.insert(userAttrsPropReqEntry(logCfg));
        propReqs.insert(extPropReqEntry(logCfg));
        return std::move(propReqs);
    }
};

/*
 * CTF 2 JSON fixed-length bit array field class value requirement.
 */
class FixedLenBitArrayFcValReq : public FcValReq
{
protected:
    /*
     * Builds a CTF 2 JSON fixed-length bit array field class value
     * requirement of type `type`, adding `propReqs` to the base JSON
     * object value property requirements.
     */
    explicit FixedLenBitArrayFcValReq(std::string&& type, PropReqs&& propReqs,
                                      const bt2c::ValReqLogCfg& logCfg) :
        FcValReq {std::move(type), this->_buildPropReqs(std::move(propReqs), logCfg), logCfg}
    {
    }

    /*
     * Builds a CTF 2 JSON fixed-length bit array field class value
     * requirement of type `type`.
     */
    explicit FixedLenBitArrayFcValReq(std::string&& type, const bt2c::ValReqLogCfg& logCfg) :
        FixedLenBitArrayFcValReq {std::move(type), {}, logCfg}
    {
    }

public:
    explicit FixedLenBitArrayFcValReq(const bt2c::ValReqLogCfg& logCfg) :
        FixedLenBitArrayFcValReq {this->typeStr(), logCfg}
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<FixedLenBitArrayFcValReq>(logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::fixedLenBitArray;
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FcValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(
                this->_logger(), bt2c::Error, "[{}] Invalid fixed-length bit array field class.",
                this->_locStr(jsonVal));
        }
    }

    static PropReqs _buildPropReqs(PropReqs&& propReqs, const bt2c::ValReqLogCfg& logCfg)
    {
        addToPropReqs(propReqs, strings::len, bt2c::JsonUIntValInRangeReq::shared(1, 64, logCfg),
                      true);
        addToPropReqs(propReqs, strings::byteOrder, ByteOrderValReq::shared(logCfg), true);
        addToPropReqs(propReqs, strings::align, AlignValReq::shared(logCfg));
        return std::move(propReqs);
    }
};

/*
 * CTF 2 JSON fixed-length boolean field class value requirement.
 */
class FixedLenBoolFcValReq final : public FixedLenBitArrayFcValReq
{
public:
    explicit FixedLenBoolFcValReq(const bt2c::ValReqLogCfg& logCfg) :
        FixedLenBitArrayFcValReq {this->typeStr(), logCfg}
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<FixedLenBoolFcValReq>(logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::fixedLenBool;
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FcValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2c::Error,
                                                   "[{}] Invalid fixed-length boolean field class.",
                                                   this->_locStr(jsonVal));
        }
    }
};

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 integer field class
 * preferred display base object property requirement.
 */
bt2c::JsonObjValReq::PropReqsEntry intFcPrefDispBasePropReqEntry(const bt2c::ValReqLogCfg& logCfg)
{
    return {strings::prefDispBase, {bt2c::JsonUIntValInSetReq::shared({2, 8, 10, 16}, logCfg)}};
}

/*
 * CTF 2 JSON fixed-length integer field class value abstract
 * requirement.
 */
class FixedLenIntFcValReq : public FixedLenBitArrayFcValReq
{
protected:
    /*
     * Builds a CTF 2 JSON fixed-length integer field class value
     * requirement of type `type`, adding `propReqs` to the base JSON
     * object value property requirements.
     */
    explicit FixedLenIntFcValReq(std::string&& type, PropReqs&& propReqs,
                                 const bt2c::ValReqLogCfg& logCfg) :
        FixedLenBitArrayFcValReq {std::move(type),
                                  this->_buildPropReqs(std::move(propReqs), logCfg), logCfg}
    {
    }

    /*
     * Builds a CTF 2 JSON fixed-length integer field class value
     * requirement of type `type`.
     */
    explicit FixedLenIntFcValReq(std::string&& type, const bt2c::ValReqLogCfg& logCfg) :
        FixedLenIntFcValReq {std::move(type), {}, logCfg}
    {
    }

private:
    static PropReqs _buildPropReqs(PropReqs&& propReqs, const bt2c::ValReqLogCfg& logCfg)
    {
        propReqs.insert(intFcPrefDispBasePropReqEntry(logCfg));
        return std::move(propReqs);
    }
};

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 unsigned
 * integer field class roles object property requirement.
 */
bt2c::JsonObjValReq::PropReqsEntry
uIntFcRolesPropReqEntry(const bt2c::JsonStrValInSetReq::Set& roles,
                        const bt2c::ValReqLogCfg& logCfg)
{
    return {strings::roles, {RolesValReq::shared(roles, logCfg)}};
}

/*
 * CTF 2 JSON fixed-length unsigned integer field class value
 * requirement.
 */
class FixedLenUIntFcValReq : public FixedLenIntFcValReq
{
protected:
    /*
     * Builds a CTF 2 JSON fixed-length unsigned integer field class
     * value requirement of type `type`, adding `propReqs` to the base
     * JSON object value property requirements.
     */
    explicit FixedLenUIntFcValReq(std::string&& type, const bt2c::JsonStrValInSetReq::Set& roles,
                                  PropReqs&& propReqs, const bt2c::ValReqLogCfg& logCfg) :
        FixedLenIntFcValReq {std::move(type),
                             this->_buildPropReqs(roles, std::move(propReqs), logCfg), logCfg}
    {
    }

    /*
     * Builds a CTF 2 JSON fixed-length unsigned integer field class
     * value requirement of type `type`.
     */
    explicit FixedLenUIntFcValReq(std::string&& type, const bt2c::JsonStrValInSetReq::Set& roles,
                                  const bt2c::ValReqLogCfg& logCfg) :
        FixedLenUIntFcValReq {std::move(type), roles, {}, logCfg}
    {
    }

public:
    explicit FixedLenUIntFcValReq(const bt2c::JsonStrValInSetReq::Set& roles,
                                  const bt2c::ValReqLogCfg& logCfg) :
        FixedLenUIntFcValReq {this->typeStr(), roles, logCfg}
    {
    }

    static SP shared(const bt2c::JsonStrValInSetReq::Set& roles, const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<FixedLenUIntFcValReq>(roles, logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::fixedLenUInt;
    }

private:
    static PropReqs _buildPropReqs(const bt2c::JsonStrValInSetReq::Set& roles, PropReqs&& propReqs,
                                   const bt2c::ValReqLogCfg& logCfg)
    {
        if (!roles.empty()) {
            propReqs.insert(uIntFcRolesPropReqEntry(roles, logCfg));
        }

        return std::move(propReqs);
    }

    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FcValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(
                this->_logger(), bt2c::Error,
                "[{}] Invalid fixed-length unsigned integer field class.", this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 JSON fixed-length signed integer field class value requirement.
 */
class FixedLenSIntFcValReq : public FixedLenIntFcValReq
{
protected:
    /*
     * Builds a CTF 2 JSON fixed-length signed integer field class value
     * requirement of type `type`, adding `propReqs` to the base JSON
     * object value property requirements.
     */
    explicit FixedLenSIntFcValReq(std::string&& type, PropReqs&& propReqs,
                                  const bt2c::ValReqLogCfg& logCfg) :
        FixedLenIntFcValReq {std::move(type), std::move(propReqs), logCfg}
    {
    }

    /*
     * Builds a CTF 2 JSON fixed-length signed integer field class value
     * requirement of type `type`.
     */
    explicit FixedLenSIntFcValReq(std::string&& type, const bt2c::ValReqLogCfg& logCfg) :
        FixedLenSIntFcValReq {std::move(type), {}, logCfg}
    {
    }

public:
    explicit FixedLenSIntFcValReq(const bt2c::ValReqLogCfg& logCfg) :
        FixedLenIntFcValReq {this->typeStr(), logCfg}
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<FixedLenSIntFcValReq>(logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::fixedLenSInt;
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FcValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(
                this->_logger(), bt2c::Error,
                "[{}] Invalid fixed-length signed integer field class.", this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 JSON enumeration field class mappings value requirement,
 *
 * An instance of this class validates that a given JSON value is
 * a CTF 2 enumeration field class mappings object, each integer value
 * within the integer ranges satisfying an instance of
 * `JsonIntValReqT`.
 */
template <typename JsonIntValReqT>
class EnumFcMappingsValReq final : public bt2c::JsonObjValReq
{
public:
    explicit EnumFcMappingsValReq(const bt2c::ValReqLogCfg& logCfg) :
        bt2c::JsonObjValReq {{}, true, logCfg}, _mRangeSetReq {logCfg}
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<EnumFcMappingsValReq>(logCfg);
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            bt2c::JsonObjValReq::_validate(jsonVal);

            /* Require at least one mapping */
            if (jsonVal.asObj().size() < 1) {
                BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2c::Error,
                                                       "[{}] Expecting at least one mapping.",
                                                       this->_locStr(jsonVal));
            }

            /* Validate range sets */
            for (auto& keyJsonValPair : jsonVal.asObj()) {
                try {
                    _mRangeSetReq.validate(*keyJsonValPair.second);
                } catch (const bt2c::Error&) {
                    BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(
                        this->_logger(), bt2c::Error, "[{}] Invalid mapping `{}`.",
                        this->_locStr(jsonVal), keyJsonValPair.first);
                }
            }
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2c::Error,
                                                   "[{}] Invalid enumeration field class mappings.",
                                                   this->_locStr(jsonVal));
        }
    }

    ctf::src::Ctf2JsonIntRangeSetValReqBase<JsonIntValReqT> _mRangeSetReq;
};

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 enumeration
 * field class mappings object property requirement.
 */
template <typename JsonIntValReqT>
bt2c::JsonObjValReq::PropReqsEntry enumFcMappingsPropReqEntry(const bt2c::ValReqLogCfg& logCfg)
{
    return {strings::mappings, {EnumFcMappingsValReq<JsonIntValReqT>::shared(logCfg), true}};
}

/*
 * CTF 2 JSON fixed-length unsigned enumeration field class value
 * requirement.
 */
class FixedLenUEnumFcValReq final : public FixedLenUIntFcValReq
{
public:
    explicit FixedLenUEnumFcValReq(const bt2c::JsonStrValInSetReq::Set& roles,
                                   const bt2c::ValReqLogCfg& logCfg) :
        /* clang-format off */
        FixedLenUIntFcValReq {this->typeStr(), roles, {
            enumFcMappingsPropReqEntry<bt2c::JsonUIntValReq>(logCfg)
        }, logCfg}
    /* clang-format on */
    {
    }

    static SP shared(const bt2c::JsonStrValInSetReq::Set& roles, const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<FixedLenUEnumFcValReq>(roles, logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::fixedLenUEnum;
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FcValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(
                this->_logger(), bt2c::Error,
                "[{}] Invalid fixed-length unsigned enumeration field class.",
                this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 JSON fixed-length signed enumeration field class value
 * requirement.
 */
class FixedLenSEnumFcValReq final : public FixedLenSIntFcValReq
{
public:
    explicit FixedLenSEnumFcValReq(const bt2c::ValReqLogCfg& logCfg) :
        /* clang-format off */
        FixedLenSIntFcValReq {this->typeStr(), {
            enumFcMappingsPropReqEntry<bt2c::JsonSIntValReq>(logCfg)
        }, logCfg}
    /* clang-format on */
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<FixedLenSEnumFcValReq>(logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::fixedLenSEnum;
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FcValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(
                this->_logger(), bt2c::Error,
                "[{}] Invalid fixed-length signed enumeration field class.",
                this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 JSON fixed-length floating-point number field class value
 * requirement.
 */
class FixedLenFloatFcValReq final : public FixedLenBitArrayFcValReq
{
public:
    explicit FixedLenFloatFcValReq(const bt2c::ValReqLogCfg& logCfg) :
        FixedLenBitArrayFcValReq {this->typeStr(), logCfg}
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<FixedLenFloatFcValReq>(logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::fixedLenFloat;
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FcValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(
                this->_logger(), bt2c::Error,
                "[{}] Invalid fixed-length floating-point number field class.",
                this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 JSON variable-length integer field class value abstract
 * requirement.
 */
class VarLenIntFcValReq : public FcValReq
{
protected:
    /*
     * Builds a CTF 2 JSON variable-length integer field class value
     * requirement of type `type`, adding `propReqs` to the base JSON
     * object value property requirements.
     */
    explicit VarLenIntFcValReq(std::string&& type, PropReqs&& propReqs,
                               const bt2c::ValReqLogCfg& logCfg) :
        FcValReq {std::move(type), this->_buildPropReqs(std::move(propReqs), logCfg), logCfg}
    {
    }

    /*
     * Builds a CTF 2 JSON variable-length integer field class value
     * requirement of type `type`.
     */
    explicit VarLenIntFcValReq(std::string&& type, const bt2c::ValReqLogCfg& logCfg) :
        VarLenIntFcValReq {std::move(type), {}, logCfg}
    {
    }

private:
    static PropReqs _buildPropReqs(PropReqs&& propReqs, const bt2c::ValReqLogCfg& logCfg)
    {
        propReqs.insert(intFcPrefDispBasePropReqEntry(logCfg));
        return std::move(propReqs);
    }
};

/*
 * CTF 2 JSON variable-length unsigned integer field class value
 * requirement.
 */
class VarLenUIntFcValReq : public VarLenIntFcValReq
{
protected:
    /*
     * Builds a CTF 2 JSON variable-length unsigned integer field class
     * value requirement of type `type`, adding `propReqs` to the base
     * JSON object value property requirements.
     */
    explicit VarLenUIntFcValReq(std::string&& type, const bt2c::JsonStrValInSetReq::Set& roles,
                                PropReqs&& propReqs, const bt2c::ValReqLogCfg& logCfg) :
        VarLenIntFcValReq {std::move(type),
                           this->_buildPropReqs(roles, std::move(propReqs), logCfg), logCfg}
    {
    }

    /*
     * Builds a CTF 2 JSON variable-length unsigned integer field class
     * value requirement of type `type`.
     */
    explicit VarLenUIntFcValReq(std::string&& type, const bt2c::JsonStrValInSetReq::Set& roles,
                                const bt2c::ValReqLogCfg& logCfg) :
        VarLenUIntFcValReq {std::move(type), roles, {}, logCfg}
    {
    }

public:
    explicit VarLenUIntFcValReq(const bt2c::JsonStrValInSetReq::Set& roles,
                                const bt2c::ValReqLogCfg& logCfg) :
        VarLenUIntFcValReq {this->typeStr(), roles, logCfg}
    {
    }

    static SP shared(const bt2c::JsonStrValInSetReq::Set& roles, const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<VarLenUIntFcValReq>(roles, logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::varLenUInt;
    }

private:
    static PropReqs _buildPropReqs(const bt2c::JsonStrValInSetReq::Set& roles, PropReqs&& propReqs,
                                   const bt2c::ValReqLogCfg& logCfg)
    {
        if (!roles.empty()) {
            propReqs.insert(uIntFcRolesPropReqEntry(roles, logCfg));
        }

        return std::move(propReqs);
    }

    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FcValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(
                this->_logger(), bt2c::Error,
                "[{}] Invalid variable-length unsigned integer field class.",
                this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 JSON variable-length signed integer field class value
 * requirement.
 */
class VarLenSIntFcValReq : public VarLenIntFcValReq
{
protected:
    /*
     * Builds a CTF 2 JSON variable-length unsigned integer field class
     * value requirement of type `type`, adding `propReqs` to the base
     * JSON object value property requirements.
     */
    explicit VarLenSIntFcValReq(std::string&& type, PropReqs&& propReqs,
                                const bt2c::ValReqLogCfg& logCfg) :
        VarLenIntFcValReq {std::move(type), std::move(propReqs), logCfg}
    {
    }

    /*
     * Builds a CTF 2 JSON variable-length unsigned integer field class
     * value requirement of type `type`.
     */
    explicit VarLenSIntFcValReq(std::string&& type, const bt2c::ValReqLogCfg& logCfg) :
        VarLenSIntFcValReq {std::move(type), {}, logCfg}
    {
    }

public:
    explicit VarLenSIntFcValReq(const bt2c::ValReqLogCfg& logCfg) :
        VarLenSIntFcValReq {this->typeStr(), logCfg}
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<VarLenSIntFcValReq>(logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::varLenSInt;
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FcValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(
                this->_logger(), bt2c::Error,
                "[{}] Invalid variable-length signed integer field class.", this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 JSON variable-length unsigned enumeration field class value
 * requirement.
 */
class VarLenUEnumFcValReq final : public VarLenUIntFcValReq
{
public:
    explicit VarLenUEnumFcValReq(const bt2c::JsonStrValInSetReq::Set& roles,
                                 const bt2c::ValReqLogCfg& logCfg) :
        /* clang-format off */
        VarLenUIntFcValReq {this->typeStr(), roles, {
            enumFcMappingsPropReqEntry<bt2c::JsonUIntValReq>(logCfg)
        }, logCfg}
    /* clang-format on */
    {
    }

    static SP shared(const bt2c::JsonStrValInSetReq::Set& roles, const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<VarLenUEnumFcValReq>(roles, logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::varLenUEnum;
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FcValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(
                this->_logger(), bt2c::Error,
                "[{}] Invalid variable-length unsigned enumeration field class.",
                this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 JSON variable-length signed enumeration field class value
 * requirement.
 */
class VarLenSEnumFcValReq final : public VarLenSIntFcValReq
{
public:
    explicit VarLenSEnumFcValReq(const bt2c::ValReqLogCfg& logCfg) :
        VarLenSIntFcValReq {this->typeStr(),
                            {enumFcMappingsPropReqEntry<bt2c::JsonSIntValReq>(logCfg)},
                            logCfg}
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<VarLenSEnumFcValReq>(logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::varLenSEnum;
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FcValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(
                this->_logger(), bt2c::Error,
                "[{}] Invalid variable-length signed enumeration field class.",
                this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 JSON null-terminated string field class value requirement.
 */
class NullTerminatedStrFcValReq final : public FcValReq
{
public:
    explicit NullTerminatedStrFcValReq(const bt2c::ValReqLogCfg& logCfg) :
        FcValReq {this->typeStr(), logCfg}
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<NullTerminatedStrFcValReq>(logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::nullTerminatedStr;
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FcValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(
                this->_logger(), bt2c::Error, "[{}] Invalid null-terminated string field class.",
                this->_locStr(jsonVal));
        }
    }
};

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 static-length field
 * class length object property requirement.
 */
bt2c::JsonObjValReq::PropReqsEntry staticLenFcLenPropReqEntry(const bt2c::ValReqLogCfg& logCfg)
{
    return {strings::len, {bt2c::JsonValHasTypeReq::shared(bt2c::ValType::UINT, logCfg), true}};
}

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 dynamic-length
 * field class length field location object property requirement.
 */
bt2c::JsonObjValReq::PropReqsEntry dynLenFcLenFieldLocPropReqEntry(const bt2c::ValReqLogCfg& logCfg)
{
    return {strings::lenFieldLoc, {FieldLocValReq::shared(logCfg), true}};
}

/*
 * CTF 2 JSON static-length string field class value requirement.
 */
class StaticLenStrFcValReq final : public FcValReq
{
public:
    explicit StaticLenStrFcValReq(const bt2c::ValReqLogCfg& logCfg) :
        FcValReq {this->typeStr(), {staticLenFcLenPropReqEntry(logCfg)}, logCfg}
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<StaticLenStrFcValReq>(logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::staticLenStr;
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FcValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2c::Error,
                                                   "[{}] Invalid static-length string field class.",
                                                   this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 JSON dynamic-length string field class value requirement.
 */
class DynLenStrFcValReq final : public FcValReq
{
public:
    explicit DynLenStrFcValReq(const bt2c::ValReqLogCfg& logCfg) :
        FcValReq {this->typeStr(), {dynLenFcLenFieldLocPropReqEntry(logCfg)}, logCfg}
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<DynLenStrFcValReq>(logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::dynLenStr;
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FcValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(
                this->_logger(), bt2c::Error, "[{}] Invalid dynamic-length string field class.",
                this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 JSON BLOB field class value abstract requirement.
 */
class BlobFcValReq : public FcValReq
{
protected:
    /*
     * Builds a CTF 2 JSON BLOB field class value requirement of type
     * `type`, adding `propReqs` to the base JSON object value property
     * requirements.
     */
    explicit BlobFcValReq(std::string&& type, PropReqs&& propReqs,
                          const bt2c::ValReqLogCfg& logCfg) :
        FcValReq {std::move(type), this->_buildPropReqs(std::move(propReqs), logCfg), logCfg}
    {
    }

    /*
     * Builds a CTF 2 JSON BLOB field class value requirement of type
     * `type`.
     */
    explicit BlobFcValReq(std::string&& type, const bt2c::ValReqLogCfg& logCfg) :
        BlobFcValReq {std::move(type), {}, logCfg}
    {
    }

private:
    static PropReqs _buildPropReqs(PropReqs&& propReqs, const bt2c::ValReqLogCfg& logCfg)
    {
        addToPropReqs(propReqs, strings::mediaType,
                      bt2c::JsonValHasTypeReq::shared(bt2c::ValType::STR, logCfg));
        return std::move(propReqs);
    }
};

/*
 * CTF 2 JSON static-length BLOB field class value requirement.
 */
class StaticLenBlobFcValReq final : public BlobFcValReq
{
public:
    explicit StaticLenBlobFcValReq(const bool acceptMetadataStreamUuidRole,
                                   const bt2c::ValReqLogCfg& logCfg) :
        BlobFcValReq {this->typeStr(), this->_buildPropReqs(acceptMetadataStreamUuidRole, logCfg),
                      logCfg}
    {
    }

    static SP shared(const bool acceptMetadataStreamUuidRole, const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<StaticLenBlobFcValReq>(acceptMetadataStreamUuidRole, logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::staticLenBlob;
    }

private:
    static PropReqs _buildPropReqs(const bool acceptMetadataStreamUuidRole,
                                   const bt2c::ValReqLogCfg& logCfg)
    {
        PropReqs propReqs;

        propReqs.insert(staticLenFcLenPropReqEntry(logCfg));

        if (acceptMetadataStreamUuidRole) {
            propReqs.insert(
                {strings::roles, RolesValReq::shared({strings::metadataStreamUuid}, logCfg)});
        }

        return propReqs;
    }

    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FcValReq::_validate(jsonVal);

            const auto jsonRoles = jsonVal.asObj()[strings::roles];

            if (jsonRoles && !jsonRoles->asArray().isEmpty()) {
                /* The only valid role is the metadata stream UUID */
                auto& jsonLen = jsonVal.asObj()[strings::len]->asUInt();

                if (*jsonLen != 16) {
                    BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(
                        this->_logger(), bt2c::Error,
                        "[{}] `{}` property: expecting 16, not {}, because the field class has the `{}` role.",
                        this->_locStr(jsonLen), strings::len, *jsonLen,
                        strings::metadataStreamUuid);
                }
            }
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2c::Error,
                                                   "[{}] Invalid static-length BLOB field class.",
                                                   this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 JSON dynamic-length BLOB field class value requirement.
 */
class DynLenBlobFcValReq final : public BlobFcValReq
{
public:
    explicit DynLenBlobFcValReq(const bt2c::ValReqLogCfg& logCfg) :
        BlobFcValReq {this->typeStr(), {dynLenFcLenFieldLocPropReqEntry(logCfg)}, logCfg}
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<DynLenBlobFcValReq>(logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::dynLenBlob;
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FcValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2c::Error,
                                                   "[{}] Invalid dynamic-length BLOB field class.",
                                                   this->_locStr(jsonVal));
        }
    }
};

class AnyFcValReq;

/*
 * CTF 2 field classes are recursive, in that some field classes may
 * contain other field classes.
 *
 * To make it possible to build a `AnyFcValReq` instance without a
 * shared pointer, the constructor of compound field class requirements
 * accepts a `const AnyFcValReq&` (raw reference) parameter. The raw
 * reference must therefore remain valid as long as the compound field
 * class using it exists.
 *
 * Because JSON value requirements work with shared pointers to `const
 * Ctf2JsonValReq` (`bt2c::JsonValReq::SP`), this `JsonAnyFcValReqWrapper`
 * class simply wraps such a `const AnyFcValReq *` value: its
 * _validate() method forwards the call. A `AnyFcValReqWrapper` instance
 * doesn't own the raw pointer.
 */
class AnyFcValReqWrapper final : public bt2c::JsonValReq
{
public:
    explicit AnyFcValReqWrapper(const AnyFcValReq& anyFcValReq, const bt2c::ValReqLogCfg& logCfg) :
        bt2c::JsonValReq {logCfg}, _mAnyFcValReq {&anyFcValReq}
    {
    }

    static SP shared(const AnyFcValReq& anyFcValReq, const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<AnyFcValReqWrapper>(anyFcValReq, logCfg);
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override;

    const AnyFcValReq *_mAnyFcValReq;
};

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 field class object
 * property requirement having the key `key`.
 */
bt2c::JsonObjValReq::PropReqsEntry anyFcPropReqEntry(std::string&& key,
                                                     const AnyFcValReq& anyFcValReq,
                                                     const bt2c::ValReqLogCfg& logCfg)
{
    return {std::move(key), {AnyFcValReqWrapper::shared(anyFcValReq, logCfg), true}};
}

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 object name object
 * property requirement.
 */
bt2c::JsonObjValReq::PropReqsEntry namePropReqEntry(const bool isRequired,
                                                    const bt2c::ValReqLogCfg& logCfg)
{
    return {strings::name,
            {bt2c::JsonValHasTypeReq::shared(bt2c::ValType::STR, logCfg), isRequired}};
}

/*
 * CTF 2 JSON structure field member class value requirement.
 */
class StructFieldMemberClsValReq final : public bt2c::JsonObjValReq
{
public:
    explicit StructFieldMemberClsValReq(const AnyFcValReq& anyFcValReq,
                                        const bt2c::ValReqLogCfg& logCfg) :
        /* clang-format off */
        bt2c::JsonObjValReq {{
            namePropReqEntry(true, logCfg),
            anyFcPropReqEntry(strings::fc, anyFcValReq, logCfg),
            userAttrsPropReqEntry(logCfg),
            extPropReqEntry(logCfg),
        }, logCfg}
    /* clang-format on */
    {
    }

    static SP shared(const AnyFcValReq& anyFcValReq, const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<StructFieldMemberClsValReq>(anyFcValReq, logCfg);
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            bt2c::JsonObjValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2c::Error,
                                                   "[{}] Invalid structure field member class.",
                                                   this->_locStr(jsonVal));
        }
    }
};

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 minimum alignment
 * object property requirement.
 */
bt2c::JsonObjValReq::PropReqsEntry minAlignPropReqEntry(const bt2c::ValReqLogCfg& logCfg)
{
    return {strings::minAlign, AlignValReq::shared(logCfg)};
}

class UniqueEntryNamesValidator final
{
public:
    explicit UniqueEntryNamesValidator(const bt2c::ValReqLogCfg& logCfg) : _mLogCfg {logCfg}
    {
    }

    /*
     * Validates that, within the JSON array value having the key `propName`
     * within the JSON object value `jsonVal`, the `name` property of each
     * (JSON object value) element, if it exists, is unique.
     *
     * Throws `TextParseError` on failure, using `elemName` to name the
     * element having a duplicate name.
     */
    void validate(const bt2c::JsonVal& jsonVal, const char * const propName,
                  const char * const elemName) const
    {
        const auto jsonEntries = jsonVal.asObj()[propName];

        if (!jsonEntries) {
            /* Empty */
            return;
        }

        /* Use a set to accumulate unique names */
        std::unordered_set<std::string> names;

        for (auto& jsonEntry : jsonEntries->asArray()) {
            const auto jsonName = jsonEntry->asObj()[strings::name];

            if (!jsonName) {
                /* No `name` property */
                continue;
            }

            auto& jsonNameStr = jsonName->asStr();

            if (names.count(*jsonNameStr) != 0) {
                /* Already in set */
                BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(
                    this->_logger(), bt2c::Error, "[{}] Duplicate {} name `{}`.",
                    bt2c::textLocStr(jsonName->loc(), _mLogCfg.textLocStrFmt()), elemName,
                    (*jsonNameStr));
            }

            /* Add to set */
            names.insert(*jsonNameStr);
        }
    }

private:
    const bt2c::Logger& _logger() const noexcept
    {
        return _mLogCfg.logger();
    }

    /* Logging configuration */
    bt2c::ValReqLogCfg _mLogCfg;
};

/*
 * CTF 2 JSON structure field class value requirement.
 */
class StructFcValReq final : public FcValReq
{
public:
    explicit StructFcValReq(const AnyFcValReq& anyFcValReq, const bt2c::ValReqLogCfg& logCfg) :
        /* clang-format off */
        FcValReq {this->typeStr(), {
            {strings::memberClasses, {
                bt2c::JsonArrayValReq::shared(
                    StructFieldMemberClsValReq::shared(anyFcValReq, logCfg),
                    logCfg
                )
            }},
            minAlignPropReqEntry(logCfg),
        }, logCfg},
        _mUniqueEntryNamesValidator {logCfg}
    /* clang-format on */
    {
    }

    static SP shared(const AnyFcValReq& anyFcValReq, const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<StructFcValReq>(anyFcValReq, logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::structure;
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FcValReq::_validate(jsonVal);

            /* Validate that member class names are unique */
            _mUniqueEntryNamesValidator.validate(jsonVal, strings::memberClasses,
                                                 "structure field member class");
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2c::Error,
                                                   "[{}] Invalid structure field class.",
                                                   this->_locStr(jsonVal));
        }
    }

    UniqueEntryNamesValidator _mUniqueEntryNamesValidator;
};

/*
 * CTF 2 JSON array field class value abstract requirement.
 */
class ArrayFcValReq : public FcValReq
{
protected:
    /*
     * Builds a CTF 2 JSON array field class value requirement of type
     * `type`, adding `propReqs` to the base JSON object value property
     * requirements.
     */
    explicit ArrayFcValReq(std::string&& type, const AnyFcValReq& anyFcValReq, PropReqs&& propReqs,
                           const bt2c::ValReqLogCfg& logCfg) :
        FcValReq {std::move(type), this->_buildPropReqs(anyFcValReq, std::move(propReqs), logCfg),
                  logCfg}
    {
    }

    /*
     * Builds a CTF 2 JSON array field class value requirement of type
     * `type`.
     */
    explicit ArrayFcValReq(std::string&& type, const AnyFcValReq& anyFcValReq,
                           const bt2c::ValReqLogCfg& logCfg) :
        ArrayFcValReq {std::move(type), anyFcValReq, {}, logCfg}
    {
    }

private:
    static PropReqs _buildPropReqs(const AnyFcValReq& anyFcValReq, PropReqs&& propReqs,
                                   const bt2c::ValReqLogCfg& logCfg)
    {
        propReqs.insert(anyFcPropReqEntry(strings::elemFc, anyFcValReq, logCfg));
        propReqs.insert(minAlignPropReqEntry(logCfg));
        return std::move(propReqs);
    }
};

/*
 * CTF 2 JSON static-length array field class value requirement.
 */
class StaticLenArrayFcValReq final : public ArrayFcValReq
{
public:
    explicit StaticLenArrayFcValReq(const AnyFcValReq& anyFcValReq,
                                    const bt2c::ValReqLogCfg& logCfg) :
        /* clang-format off */
        ArrayFcValReq {this->typeStr(), anyFcValReq, {
            staticLenFcLenPropReqEntry(logCfg)
        }, logCfg}
    /* clang-format on */
    {
    }

    static SP shared(const AnyFcValReq& anyFcValReq, const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<StaticLenArrayFcValReq>(anyFcValReq, logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::staticLenArray;
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FcValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2c::Error,
                                                   "[{}] Invalid static-length array field class.",
                                                   this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 JSON dynamic-length array field class value requirement.
 */
class DynLenArrayFcValReq final : public ArrayFcValReq
{
public:
    explicit DynLenArrayFcValReq(const AnyFcValReq& anyFcValReq, const bt2c::ValReqLogCfg& logCfg) :
        /* clang-format off */
        ArrayFcValReq {this->typeStr(), anyFcValReq, {
            dynLenFcLenFieldLocPropReqEntry(logCfg)
        }, logCfg}
    /* clang-format on */
    {
    }

    static SP shared(const AnyFcValReq& anyFcValReq, const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<DynLenArrayFcValReq>(anyFcValReq, logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::dynLenArray;
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FcValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2c::Error,
                                                   "[{}] Invalid dynamic-length array field class.",
                                                   this->_locStr(jsonVal));
        }
    }
};

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 selector field
 * location object property requirement.
 */
bt2c::JsonObjValReq::PropReqsEntry selFieldLocPropReqEntry(const bt2c::ValReqLogCfg& logCfg)
{
    return {strings::selFieldLoc, {FieldLocValReq::shared(logCfg), true}};
}

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 selector field
 * ranges object property requirement.
 */
bt2c::JsonObjValReq::PropReqsEntry selFieldRangesPropReqEntry(const bool isRequired,
                                                              const bt2c::ValReqLogCfg& logCfg)
{
    return {strings::selFieldRanges,
            {ctf::src::Ctf2JsonIntRangeSetValReq::shared(logCfg), isRequired}};
}

/*
 * CTF 2 JSON optional field class value requirement.
 */
class OptionalFcValReq final : public FcValReq
{
public:
    explicit OptionalFcValReq(const AnyFcValReq& anyFcValReq, const bt2c::ValReqLogCfg& logCfg) :
        /* clang-format off */
        FcValReq {this->typeStr(), {
            anyFcPropReqEntry(strings::fc, anyFcValReq, logCfg),
            selFieldLocPropReqEntry(logCfg),
            selFieldRangesPropReqEntry(false, logCfg),
        }, logCfg}
    /* clang-format on */
    {
    }

    static SP shared(const AnyFcValReq& anyFcValReq, const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<OptionalFcValReq>(anyFcValReq, logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::optional;
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FcValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2c::Error,
                                                   "[{}] Invalid optional field class.",
                                                   this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 JSON variant field class option class value requirement.
 */
class VariantFcOptValReq final : public bt2c::JsonObjValReq
{
public:
    explicit VariantFcOptValReq(const AnyFcValReq& anyFcValReq, const bt2c::ValReqLogCfg& logCfg) :
        /* clang-format off */
        bt2c::JsonObjValReq {{
            namePropReqEntry(false, logCfg),
            anyFcPropReqEntry(strings::fc, anyFcValReq, logCfg),
            selFieldRangesPropReqEntry(true, logCfg),
            userAttrsPropReqEntry(logCfg),
            extPropReqEntry(logCfg),
        }, logCfg}
    /* clang-format on */
    {
    }

    static SP shared(const AnyFcValReq& anyFcValReq, const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<VariantFcOptValReq>(anyFcValReq, logCfg);
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        /*
         * Not checking for integer range overlaps here because we don't
         * know the signedness of those ranges yet (depends on the
         * effective selector field class(es)).
         *
         * This will be easier to do once we know the signedness,
         * comparing only integers having the same type.
         */
        try {
            bt2c::JsonObjValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2c::Error,
                                                   "[{}] Invalid variant field class option.",
                                                   this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 JSON variant field class value requirement.
 */
class VariantFcValReq final : public FcValReq
{
public:
    explicit VariantFcValReq(const AnyFcValReq& anyFcValReq, const bt2c::ValReqLogCfg& logCfg) :
        /* clang-format off */
        FcValReq {this->typeStr(), {
            {strings::opts, {
                bt2c::JsonArrayValReq::shared(1, bt2s::nullopt,
                                              VariantFcOptValReq::shared(anyFcValReq, logCfg),
                                              logCfg),
                true
            }},
            selFieldLocPropReqEntry(logCfg),
        }, logCfg},
        _mUniqueEntryNamesValidator {logCfg}
    /* clang-format on */
    {
    }

    static SP shared(const AnyFcValReq& anyFcValReq, const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<VariantFcValReq>(anyFcValReq, logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::variant;
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FcValReq::_validate(jsonVal);

            /* Validate that option names are unique */
            _mUniqueEntryNamesValidator.validate(jsonVal, strings::opts,
                                                 "variant field class option");
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2c::Error,
                                                   "[{}] Invalid variant field class.",
                                                   this->_locStr(jsonVal));
        }
    }

    UniqueEntryNamesValidator _mUniqueEntryNamesValidator;
};

/*
 * CTF 2 JSON (any) field class value requirement.
 */
class AnyFcValReq final : public bt2c::JsonObjValReq
{
public:
    explicit AnyFcValReq(const bt2c::JsonStrValInSetReq::Set& uIntFcRoles,
                         const bool staticLenBlobHasTraceTypeUuidRole,
                         const bt2c::ValReqLogCfg& logCfg) :
        /* clang-format off */
        bt2c::JsonObjValReq {{
            {
                strings::type,
                {
                    bt2c::JsonStrValInSetReq::shared({
                        FixedLenBitArrayFcValReq::typeStr(),
                        FixedLenBoolFcValReq::typeStr(),
                        FixedLenUIntFcValReq::typeStr(),
                        FixedLenSIntFcValReq::typeStr(),
                        FixedLenUEnumFcValReq::typeStr(),
                        FixedLenSEnumFcValReq::typeStr(),
                        FixedLenFloatFcValReq::typeStr(),
                        VarLenUIntFcValReq::typeStr(),
                        VarLenSIntFcValReq::typeStr(),
                        VarLenUEnumFcValReq::typeStr(),
                        VarLenSEnumFcValReq::typeStr(),
                        NullTerminatedStrFcValReq::typeStr(),
                        StaticLenStrFcValReq::typeStr(),
                        DynLenStrFcValReq::typeStr(),
                        StaticLenBlobFcValReq::typeStr(),
                        DynLenBlobFcValReq::typeStr(),
                        StructFcValReq::typeStr(),
                        StaticLenArrayFcValReq::typeStr(),
                        DynLenArrayFcValReq::typeStr(),
                        OptionalFcValReq::typeStr(),
                        VariantFcValReq::typeStr(),
                    }, logCfg), true
                }
            }
        }, true, logCfg},
        _mFlBitArrayFcValReq {logCfg},
        _mFlBoolFcValReq {logCfg},
        _mFlUIntFcValReq {uIntFcRoles, logCfg},
        _mFlSIntFcValReq {logCfg},
        _mFlUEnumFcValReq {uIntFcRoles, logCfg},
        _mFlSEnumFcValReq {logCfg},
        _mFlFloatFcValReq {logCfg},
        _mVlUIntFcValReq {uIntFcRoles, logCfg},
        _mVlSIntFcValReq {logCfg},
        _mVlUEnumFcValReq {uIntFcRoles, logCfg},
        _mVlSEnumFcValReq {logCfg},
        _mNtStrFcValReq {logCfg},
        _mStaticLenStrFcValReq {logCfg},
        _mDynLenStrFcValReq {logCfg},
        _mStaticLenBlobFcValReq {staticLenBlobHasTraceTypeUuidRole, logCfg},
        _mDynLenBlobFcValReq {logCfg},
        _mStructFcValReq {*this, logCfg},
        _mStaticLenArrayFcValReq {*this, logCfg},
        _mDynLenArrayFcValReq {*this, logCfg},
        _mOptionalFcValReq {*this, logCfg},
        _mVariantFcValReq {*this, logCfg}
    /* clang-format on */
    {
        this->_addToFcValReqs(_mFlBitArrayFcValReq);
        this->_addToFcValReqs(_mFlBoolFcValReq);
        this->_addToFcValReqs(_mFlUIntFcValReq);
        this->_addToFcValReqs(_mFlSIntFcValReq);
        this->_addToFcValReqs(_mFlUEnumFcValReq);
        this->_addToFcValReqs(_mFlSEnumFcValReq);
        this->_addToFcValReqs(_mFlFloatFcValReq);
        this->_addToFcValReqs(_mVlUIntFcValReq);
        this->_addToFcValReqs(_mVlSIntFcValReq);
        this->_addToFcValReqs(_mVlUEnumFcValReq);
        this->_addToFcValReqs(_mVlSEnumFcValReq);
        this->_addToFcValReqs(_mNtStrFcValReq);
        this->_addToFcValReqs(_mStaticLenStrFcValReq);
        this->_addToFcValReqs(_mDynLenStrFcValReq);
        this->_addToFcValReqs(_mStaticLenBlobFcValReq);
        this->_addToFcValReqs(_mDynLenBlobFcValReq);
        this->_addToFcValReqs(_mStructFcValReq);
        this->_addToFcValReqs(_mStaticLenArrayFcValReq);
        this->_addToFcValReqs(_mDynLenArrayFcValReq);
        this->_addToFcValReqs(_mOptionalFcValReq);
        this->_addToFcValReqs(_mVariantFcValReq);
    }

    explicit AnyFcValReq(const bool staticLenBlobHasTraceTypeUuidRole,
                         const bt2c::ValReqLogCfg& logCfg) :
        AnyFcValReq {{}, staticLenBlobHasTraceTypeUuidRole, logCfg}
    {
    }

    explicit AnyFcValReq(const bt2c::JsonStrValInSetReq::Set& uIntFcRoles,
                         const bt2c::ValReqLogCfg& logCfg) :
        AnyFcValReq {uIntFcRoles, false, logCfg}
    {
    }

    explicit AnyFcValReq(const bt2c::ValReqLogCfg& logCfg) : AnyFcValReq {{}, false, logCfg}
    {
    }

private:
    template <typename JsonValReqT>
    void _addToFcValReqs(const JsonValReqT& valReq)
    {
        const auto typeStr = JsonValReqT::typeStr();

        BT_ASSERT(_mFcValReqs.find(typeStr) == _mFcValReqs.end());
        _mFcValReqs.insert(std::make_pair(typeStr, &valReq));
    }

    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            bt2c::JsonObjValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(
                this->_logger(), bt2c::Error, "[{}] Invalid field class.", this->_locStr(jsonVal));
        }

        /*
         * This part doesn't need to be catched because the specific
         * _validate() method already appends a message like
         * "Invalid xyz field class:" to the exception.
         */
        const auto it = _mFcValReqs.find(*jsonVal.asObj()[strings::type]->asStr());

        BT_ASSERT(it != _mFcValReqs.end());
        it->second->validate(jsonVal);
    }

    /* Subrequirements */
    FixedLenBitArrayFcValReq _mFlBitArrayFcValReq;
    FixedLenBoolFcValReq _mFlBoolFcValReq;
    FixedLenUIntFcValReq _mFlUIntFcValReq;
    FixedLenSIntFcValReq _mFlSIntFcValReq;
    FixedLenUEnumFcValReq _mFlUEnumFcValReq;
    FixedLenSEnumFcValReq _mFlSEnumFcValReq;
    FixedLenFloatFcValReq _mFlFloatFcValReq;
    VarLenUIntFcValReq _mVlUIntFcValReq;
    VarLenSIntFcValReq _mVlSIntFcValReq;
    VarLenUEnumFcValReq _mVlUEnumFcValReq;
    VarLenSEnumFcValReq _mVlSEnumFcValReq;
    NullTerminatedStrFcValReq _mNtStrFcValReq;
    StaticLenStrFcValReq _mStaticLenStrFcValReq;
    DynLenStrFcValReq _mDynLenStrFcValReq;
    StaticLenBlobFcValReq _mStaticLenBlobFcValReq;
    DynLenBlobFcValReq _mDynLenBlobFcValReq;
    StructFcValReq _mStructFcValReq;
    StaticLenArrayFcValReq _mStaticLenArrayFcValReq;
    DynLenArrayFcValReq _mDynLenArrayFcValReq;
    OptionalFcValReq _mOptionalFcValReq;
    VariantFcValReq _mVariantFcValReq;

    /*
     * Field class type string to JSON field class requirement.
     *
     * Values are owned by the members above.
     */
    std::unordered_map<std::string, const bt2c::JsonValReq *> _mFcValReqs;
};

void AnyFcValReqWrapper::_validate(const bt2c::JsonVal& jsonVal) const
{
    /* Delegate */
    _mAnyFcValReq->validate(jsonVal);
}

/*
 * CTF 2 JSON scope field class value requirement.
 *
 * This is like `StructFcValReq`, but provides its own
 * `AnyFcValReq` instance.
 */
class ScopeFcValReq final : public bt2c::JsonValReq
{
public:
    /*
     * `uIntFcRoles` and `staticLenBlobHasTraceTypeUuidRole` are
     * forwarded to the constructor of the underlying `AnyFcValReq`
     * instance.
     */
    explicit ScopeFcValReq(const bt2c::JsonStrValInSetReq::Set& uIntFcRoles,
                           const bool staticLenBlobHasTraceTypeUuidRole,
                           const bt2c::ValReqLogCfg& logCfg) :
        bt2c::JsonValReq {logCfg},
        _mAnyFcValReq {uIntFcRoles, staticLenBlobHasTraceTypeUuidRole, logCfg}, _mStructFcValReq {
                                                                                    _mAnyFcValReq,
                                                                                    logCfg}
    {
    }

    /*
     * `uIntFcRoles` is forwarded to the constructor of the underlying
     * `AnyFcValReq` instance.
     */
    explicit ScopeFcValReq(const bt2c::JsonStrValInSetReq::Set& uIntFcRoles,
                           const bt2c::ValReqLogCfg& logCfg) :
        ScopeFcValReq {uIntFcRoles, false, logCfg}
    {
    }

    /*
     * `staticLenBlobHasTraceTypeUuidRole` is forwarded to the constructor of the underlying
     * `AnyFcValReq` instance.
     */
    explicit ScopeFcValReq(const bool staticLenBlobHasTraceTypeUuidRole,
                           const bt2c::ValReqLogCfg& logCfg) :
        ScopeFcValReq {{}, staticLenBlobHasTraceTypeUuidRole, logCfg}
    {
    }

    explicit ScopeFcValReq(const bt2c::ValReqLogCfg& logCfg) : ScopeFcValReq {{}, false, logCfg}
    {
    }

    static SP shared(const bt2c::JsonStrValInSetReq::Set& uIntFcRoles,
                     const bool staticLenBlobHasTraceTypeUuidRole, const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<ScopeFcValReq>(uIntFcRoles, staticLenBlobHasTraceTypeUuidRole,
                                               logCfg);
    }

    static SP shared(const bt2c::JsonStrValInSetReq::Set& uIntFcRoles,
                     const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<ScopeFcValReq>(uIntFcRoles, logCfg);
    }

    static SP shared(const bool staticLenBlobHasTraceTypeUuidRole, const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<ScopeFcValReq>(staticLenBlobHasTraceTypeUuidRole, logCfg);
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<ScopeFcValReq>(logCfg);
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            _mStructFcValReq.validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2c::Error,
                                                   "[{}] Invalid scope field class.",
                                                   this->_locStr(jsonVal));
        }
    }

    AnyFcValReq _mAnyFcValReq;
    StructFcValReq _mStructFcValReq;
};

/*
 * CTF 2 JSON fragment value abstract requirement.
 */
class FragmentValReq : public bt2c::JsonObjValReq
{
protected:
    /*
     * Builds a CTF 2 JSON fragment value requirement of type `type`,
     * adding `propReqs` to the base JSON object value property
     * requirements.
     */
    explicit FragmentValReq(std::string&& type, PropReqs&& propReqs,
                            const bt2c::ValReqLogCfg& logCfg) :
        bt2c::JsonObjValReq {this->_buildPropReqs(std::move(type), std::move(propReqs), logCfg),
                             logCfg}
    {
    }

    /*
     * Builds a CTF 2 JSON fragment value requirement of type `type`.
     */
    explicit FragmentValReq(std::string&& type, const bt2c::ValReqLogCfg& logCfg) :
        FragmentValReq {std::move(type), {}, logCfg}
    {
    }

private:
    static PropReqs _buildPropReqs(std::string&& type, PropReqs&& propReqs,
                                   const bt2c::ValReqLogCfg& logCfg)
    {
        propReqs.insert(objTypePropReqEntry(std::move(type), logCfg));
        propReqs.insert(userAttrsPropReqEntry(logCfg));
        propReqs.insert(extPropReqEntry(logCfg));
        return std::move(propReqs);
    }
};

/*
 * CTF 2 preamble fragment value requirement.
 */
class PreambleFragmentValReq final : public FragmentValReq
{
public:
    explicit PreambleFragmentValReq(const bt2c::ValReqLogCfg& logCfg) :
        /* clang-format off */
        FragmentValReq {this->typeStr(), {
            {strings::version, {bt2c::JsonUIntValInSetReq::shared(2, logCfg), true}},
            {strings::uuid, {UuidValReq::shared(logCfg)}},
        }, logCfg}
    /* clang-format on */
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<PreambleFragmentValReq>(logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::preamble;
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FragmentValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2c::Error,
                                                   "[{}] Invalid preamble fragment.",
                                                   this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 JSON clock offset value requirement.
 */
class ClkOffsetValReq final : public bt2c::JsonObjValReq
{
public:
    explicit ClkOffsetValReq(const bt2c::ValReqLogCfg& logCfg) :
        /* clang-format off */
        bt2c::JsonObjValReq {{
            {strings::seconds, {bt2c::JsonAnyIntValReq::shared(logCfg)}},
            {strings::cycles, {bt2c::JsonValHasTypeReq::shared(bt2c::ValType::UINT, logCfg)}},
        }, logCfg}
    /* clang-format on */
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<ClkOffsetValReq>(logCfg);
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            bt2c::JsonObjValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(
                this->_logger(), bt2c::Error, "[{}] Invalid clock offset.", this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 clock class fragment value requirement.
 */
class ClkClsFragmentValReq final : public FragmentValReq
{
public:
    explicit ClkClsFragmentValReq(const bt2c::ValReqLogCfg& logCfg) :
        /* clang-format off */
        FragmentValReq {this->typeStr(), {
            namePropReqEntry(true, logCfg),
            {strings::freq, {bt2c::JsonUIntValInRangeReq::shared(1, bt2s::nullopt, logCfg), true}},
            {strings::descr, {bt2c::JsonValHasTypeReq::shared(bt2c::ValType::STR, logCfg)}},
            {strings::uuid, {UuidValReq::shared(logCfg)}},
            {strings::originIsUnixEpoch, {bt2c::JsonValHasTypeReq::shared(bt2c::ValType::BOOL, logCfg)}},
            {strings::offset, {ClkOffsetValReq::shared(logCfg)}},
            {strings::precision, {bt2c::JsonValHasTypeReq::shared(bt2c::ValType::UINT, logCfg)}},
        }, logCfg}
    /* clang-format on */
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<ClkClsFragmentValReq>(logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::clkCls;
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FragmentValReq::_validate(jsonVal);

            /*
             * Validate that `seconds` within `offset`, if it exists, is
             * less than `frequency`.
             */
            auto& jsonObj = jsonVal.asObj();
            const auto jsonOffset = jsonObj[strings::offset];

            if (jsonOffset) {
                const auto jsonCycles = jsonOffset->asObj()[strings::cycles];

                if (jsonCycles) {
                    const auto cycles = *jsonCycles->asUInt();
                    const auto freq = *jsonObj[strings::freq]->asUInt();

                    if (cycles >= freq) {
                        BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(
                            this->_logger(), bt2c::Error,
                            "[{}] Invalid `{}` property of `{}` property: "
                            "value {} is greater than the value of the `{}` property ({}).",
                            this->_locStr(*jsonCycles), strings::cycles, strings::offset, cycles,
                            strings::freq, freq);
                    }
                }
            }
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2c::Error,
                                                   "[{}] Invalid clock class fragment.",
                                                   this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 trace class fragment value requirement.
 */
class TraceClsFragmentValReq final : public FragmentValReq
{
public:
    explicit TraceClsFragmentValReq(const bt2c::ValReqLogCfg& logCfg) :
        /* clang-format off */
        FragmentValReq {this->typeStr(), {
            {strings::uuid, {UuidValReq::shared(logCfg)}},
            {strings::env, {TraceEnvValReq::shared(logCfg)}},
            {strings::pktHeaderFc, {
                ScopeFcValReq::shared({
                    strings::dataStreamClsId,
                    strings::dataStreamId,
                    strings::pktMagicNumber,
                }, true, logCfg)
            }},
        }, logCfg}
    /* clang-format on */
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<TraceClsFragmentValReq>(logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::traceCls;
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FragmentValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2c::Error,
                                                   "[{}] Invalid trace class fragment.",
                                                   this->_locStr(jsonVal));
        }
    }
};

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 object namespace
 * object property requirement.
 */
bt2c::JsonObjValReq::PropReqsEntry nsPropReqEntry(const bt2c::ValReqLogCfg& logCfg)
{
    return {strings::ns, {bt2c::JsonValHasTypeReq::shared(bt2c::ValType::STR, logCfg)}};
}

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 object numeric ID
 * object property requirement.
 */
bt2c::JsonObjValReq::PropReqsEntry idPropReqEntry(const bt2c::ValReqLogCfg& logCfg)
{
    return {strings::id, {bt2c::JsonValHasTypeReq::shared(bt2c::ValType::UINT, logCfg)}};
}

/*
 * CTF 2 data stream class fragment value requirement.
 */
class DataStreamClsFragmentValReq final : public FragmentValReq
{
public:
    explicit DataStreamClsFragmentValReq(const bt2c::ValReqLogCfg& logCfg) :
        /* clang-format off */
        FragmentValReq {this->typeStr(), {
            namePropReqEntry(false, logCfg),
            nsPropReqEntry(logCfg),
            idPropReqEntry(logCfg),
            {strings::defClkClsName, {bt2c::JsonValHasTypeReq::shared(bt2c::ValType::STR, logCfg)}},
            {strings::pktCtxFc, {ScopeFcValReq::shared({
                strings::defClkTs,
                strings::discEventRecordCounterSnap,
                strings::pktContentLen,
                strings::pktEndDefClkTs,
                strings::pktSeqNum,
                strings::pktTotalLen,
            }, logCfg)}},
            {strings::eventRecordHeaderFc, {ScopeFcValReq::shared({
                strings::defClkTs,
                strings::eventRecordClsId,
            }, logCfg)}},
            {strings::eventRecordCommonCtxFc, {ScopeFcValReq::shared(logCfg)}},
        }, logCfg}
    /* clang-format on */
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<DataStreamClsFragmentValReq>(logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::dataStreamCls;
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FragmentValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2c::Error,
                                                   "[{}] Invalid data stream class fragment.",
                                                   this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 event record class fragment value requirement.
 */
class EventRecordClsFragmentValReq final : public FragmentValReq
{
public:
    explicit EventRecordClsFragmentValReq(const bt2c::ValReqLogCfg& logCfg) :
        /* clang-format off */
        FragmentValReq {this->typeStr(), {
            namePropReqEntry(false, logCfg),
            nsPropReqEntry(logCfg),
            idPropReqEntry(logCfg),
            {strings::dataStreamClsId, {bt2c::JsonValHasTypeReq::shared(bt2c::ValType::UINT, logCfg)}},
            {strings::specCtxFc, {ScopeFcValReq::shared(logCfg)}},
            {strings::payloadFc, {ScopeFcValReq::shared(logCfg)}},
        }, logCfg}
    /* clang-format on */
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<EventRecordClsFragmentValReq>(logCfg);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::eventRecordCls;
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FragmentValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2c::Error,
                                                   "[{}] Invalid event record class fragment.",
                                                   this->_locStr(jsonVal));
        }
    }
};

} /* namespace */

namespace internal {

/*
 * CTF 2 JSON (any) fragment value requirement (implementation).
 */
class Ctf2JsonAnyFragmentValReqImpl final : public bt2c::JsonObjValReq
{
public:
    explicit Ctf2JsonAnyFragmentValReqImpl(const bt2c::ValReqLogCfg& logCfg) :
        /* clang-format off */
        bt2c::JsonObjValReq {{
            {
                strings::type, {
                    bt2c::JsonStrValInSetReq::shared({
                        PreambleFragmentValReq::typeStr(),
                        TraceClsFragmentValReq::typeStr(),
                        ClkClsFragmentValReq::typeStr(),
                        DataStreamClsFragmentValReq::typeStr(),
                        EventRecordClsFragmentValReq::typeStr(),
                    }, logCfg), true
                }
            }
        }, true, logCfg},
        _preambleFragmentValReq {logCfg},
        _traceClsFragmentValReq {logCfg},
        _clkClsFragmentValReq {logCfg},
        _dataStreamClsFragmentValReq {logCfg},
        _eventRecordClsFragmentValReq {logCfg}
    /* clang-format on */
    {
        this->_addToFcValReqs(_preambleFragmentValReq);
        this->_addToFcValReqs(_traceClsFragmentValReq);
        this->_addToFcValReqs(_clkClsFragmentValReq);
        this->_addToFcValReqs(_dataStreamClsFragmentValReq);
        this->_addToFcValReqs(_eventRecordClsFragmentValReq);
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<Ctf2JsonAnyFragmentValReqImpl>(logCfg);
    }

private:
    template <typename JsonValReqT>
    void _addToFcValReqs(const JsonValReqT& valReq)
    {
        const auto typeStr = JsonValReqT::typeStr();

        BT_ASSERT(_fragValReqs.find(typeStr) == _fragValReqs.end());
        _fragValReqs.insert(std::make_pair(typeStr, &valReq));
    }

    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            bt2c::JsonObjValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(
                this->_logger(), bt2c::Error, "[{}] Invalid fragment.", this->_locStr(jsonVal));
        }

        /*
         * This part doesn't need to be catched because the specific
         * _validate() method already appends a message like
         * "Invalid xyz fragment:" to the exception.
         */
        const auto it = _fragValReqs.find(*jsonVal.asObj()[strings::type]->asStr());

        BT_ASSERT(it != _fragValReqs.end());
        it->second->validate(jsonVal);
    }

    /* Subrequirements */
    PreambleFragmentValReq _preambleFragmentValReq;
    TraceClsFragmentValReq _traceClsFragmentValReq;
    ClkClsFragmentValReq _clkClsFragmentValReq;
    DataStreamClsFragmentValReq _dataStreamClsFragmentValReq;
    EventRecordClsFragmentValReq _eventRecordClsFragmentValReq;

    /*
     * Fragment type string to JSON fragment requirement.
     *
     * Values are owned by the members above.
     */
    std::unordered_map<std::string, const bt2c::JsonValReq *> _fragValReqs;
};

} /* namespace internal */

Ctf2JsonAnyFragmentValReq::Ctf2JsonAnyFragmentValReq(const bt2c::Logger& parentLogger,
                                                     const bt2c::TextLocStrFmt textLocStrFmt) :
    bt2c::JsonValReq {bt2c::ValReqLogCfg {parentLogger, textLocStrFmt}},
    _mImpl {new internal::Ctf2JsonAnyFragmentValReqImpl {
        bt2c::ValReqLogCfg {parentLogger, textLocStrFmt}}}
{
}

Ctf2JsonAnyFragmentValReq::~Ctf2JsonAnyFragmentValReq()
{
}

void Ctf2JsonAnyFragmentValReq::_validate(const bt2c::JsonVal& jsonVal) const
{
    _mImpl->validate(jsonVal);
}

} /* namespace src */
} /* namespace ctf */
