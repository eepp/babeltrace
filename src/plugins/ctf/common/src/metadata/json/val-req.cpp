/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <cassert>
#include <unordered_set>
#include <string>

#include "common/assert.h"
#include "cpp-common/text-parse-error.hpp"
#include "../../../metadata/json/strings.hpp"
#include "utils.hpp"
#include "val-req.hpp"

namespace ctf {
namespace src {
namespace {

namespace bt2c = bt2_common;
namespace strings = ctf::json_strings;

/*
 * CTF 2 JSON alignment value requirement.
 */
class AlignValReq final : public bt2c::JsonValHasTypeReq
{
public:
    explicit AlignValReq() noexcept : bt2c::JsonValHasTypeReq {bt2c::ValType::UINT}
    {
    }

    static SP shared()
    {
        return std::make_shared<AlignValReq>();
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
            std::ostringstream ss;

            ss << val << " is not a power of two.";
            throwTextParseError(ss, jsonVal);
        }
    }
};

/*
 * CTF 2 JSON byte order value requirement.
 */
class ByteOrderValReq final : public bt2c::JsonStrValInSetReq
{
public:
    explicit ByteOrderValReq() :
        bt2c::JsonStrValInSetReq {
            bt2c::JsonStrValInSetReq::Set {strings::bigEndian, strings::littleEndian}}
    {
    }

    static SP shared()
    {
        return std::make_shared<ByteOrderValReq>();
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            bt2c::JsonStrValInSetReq::_validate(jsonVal);
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid byte order:", jsonVal.loc());
            throw;
        }
    }
};

/*
 * CTF 2 JSON UUID value requirement.
 */
class UuidValReq final : public bt2c::JsonArrayValReq
{
public:
    explicit UuidValReq() : bt2c::JsonArrayValReq {16, bt2c::JsonUIntValInRangeReq::shared(0, 255)}
    {
    }

    static SP shared()
    {
        return std::make_shared<UuidValReq>();
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            bt2c::JsonArrayValReq::_validate(jsonVal);
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid UUID:", jsonVal.loc());
            throw;
        }
    }
};

/*
 * CTF 2 JSON field location value requirement.
 */
class FieldLocValReq final : public bt2c::JsonArrayValReq
{
public:
    explicit FieldLocValReq() :
        bt2c::JsonArrayValReq {2, nonstd::nullopt,
                               bt2c::JsonValHasTypeReq::shared(bt2c::ValType::STR)},
        _mScopeValReq {{
            strings::pktHeader,
            strings::pktCtx,
            strings::eventRecordHeader,
            strings::eventRecordCommonCtx,
            strings::eventRecordSpecCtx,
            strings::eventRecordPayload,
        }}
    {
    }

    static SP shared()
    {
        return std::make_shared<FieldLocValReq>();
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            bt2c::JsonArrayValReq::_validate(jsonVal);

            auto& firstJsonItem = jsonVal.asArray()[0];

            try {
                _mScopeValReq.validate(firstJsonItem);
            } catch (bt2c::TextParseError& exc) {
                exc.appendErrorMsg("Invalid scope name:", firstJsonItem.loc());
                throw;
            }
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid field location:", jsonVal.loc());
            throw;
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
    explicit UserAttrsValReq() : bt2c::JsonObjValReq {{}, true}
    {
    }

    static SP shared()
    {
        return std::make_shared<UserAttrsValReq>();
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            bt2c::JsonObjValReq::_validate(jsonVal);
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid user attributes:", jsonVal.loc());
            throw;
        }
    }
};

/*
 * CTF 2 JSON trace environment value requirement.
 */
class TraceEnvValReq final : public bt2c::JsonObjValReq
{
public:
    explicit TraceEnvValReq() : bt2c::JsonObjValReq {{}, true}
    {
    }

    static SP shared()
    {
        return std::make_shared<TraceEnvValReq>();
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
                    std::ostringstream ss;

                    ss << "Entry `" << keyJsonValPair.first
                       << "`: expecting an integer or a string.";
                    throwTextParseError(ss, *jsonEntry);
                }
            }
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid trace environment:", jsonVal.loc());
            throw;
        }
    }
};

/*
 * CTF 2 JSON extensions value requirement.
 */
class ExtValReq final : public bt2c::JsonObjValReq
{
public:
    explicit ExtValReq() : bt2c::JsonObjValReq {{}, true}
    {
    }

    static SP shared()
    {
        return std::make_shared<ExtValReq>();
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            bt2c::JsonObjValReq::_validate(jsonVal);
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid extensions:", jsonVal.loc());
            throw;
        }

        if (jsonVal.asObj().size() > 0) {
            /* Never valid */
            throwTextParseError(
                "This version of the `ctf` plugin doesn't support any CTF 2 extension.", jsonVal);
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
    explicit RolesValReq(bt2c::JsonStrValInSetReq::Set validRoles) :
        bt2c::JsonArrayValReq {bt2c::JsonStrValInSetReq::shared(std::move(validRoles))}
    {
    }

    static SP shared(bt2c::JsonStrValInSetReq::Set validRoles)
    {
        return std::make_shared<RolesValReq>(std::move(validRoles));
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            bt2c::JsonArrayValReq::_validate(jsonVal);
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid roles:", jsonVal.loc());
            throw;
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
bt2c::JsonObjValReq::PropReqsEntry objTypePropReqEntry(std::string&& type)
{
    return {strings::type, {bt2c::JsonStrValInSetReq::shared(std::move(type)), true}};
}

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 user
 * attributes object property requirement.
 */
bt2c::JsonObjValReq::PropReqsEntry userAttrsPropReqEntry()
{
    return {strings::userAttrs, {UserAttrsValReq::shared()}};
}

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 extensions object
 * property requirement.
 */
bt2c::JsonObjValReq::PropReqsEntry extPropReqEntry()
{
    return {strings::extensions, {ExtValReq::shared()}};
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
    explicit FcValReq(std::string&& type, PropReqs&& propReqs = {}) :
        bt2c::JsonObjValReq {this->_buildPropReqs(std::move(type), std::move(propReqs))}
    {
    }

private:
    static PropReqs _buildPropReqs(std::string&& type, PropReqs&& propReqs)
    {
        propReqs.insert(objTypePropReqEntry(std::move(type)));
        propReqs.insert(userAttrsPropReqEntry());
        propReqs.insert(extPropReqEntry());
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
    explicit FixedLenBitArrayFcValReq(std::string&& type, PropReqs&& propReqs = {}) :
        FcValReq {std::move(type), this->_buildPropReqs(std::move(propReqs))}
    {
    }

public:
    explicit FixedLenBitArrayFcValReq() : FixedLenBitArrayFcValReq {this->typeStr()}
    {
    }

    static SP shared()
    {
        return std::make_shared<FixedLenBitArrayFcValReq>();
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
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid fixed-length bit array field class:", jsonVal.loc());
            throw;
        }
    }

    static PropReqs _buildPropReqs(PropReqs&& propReqs)
    {
        addToPropReqs(propReqs, strings::len, bt2c::JsonUIntValInRangeReq::shared(1, 64), true);
        addToPropReqs(propReqs, strings::byteOrder, ByteOrderValReq::shared(), true);
        addToPropReqs(propReqs, strings::align, AlignValReq::shared());
        return std::move(propReqs);
    }
};

/*
 * CTF 2 JSON fixed-length boolean field class value requirement.
 */
class FixedLenBoolFcValReq final : public FixedLenBitArrayFcValReq
{
public:
    explicit FixedLenBoolFcValReq() : FixedLenBitArrayFcValReq {this->typeStr()}
    {
    }

    static SP shared()
    {
        return std::make_shared<FixedLenBoolFcValReq>();
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
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid fixed-length boolean field class:", jsonVal.loc());
            throw;
        }
    }
};

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 integer field class
 * preferred display base object property requirement.
 */
bt2c::JsonObjValReq::PropReqsEntry intFcPrefDispBasePropReqEntry()
{
    return {strings::prefDispBase, {bt2c::JsonUIntValInSetReq::shared({2, 8, 10, 16})}};
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
    explicit FixedLenIntFcValReq(std::string&& type, PropReqs&& propReqs = {}) :
        FixedLenBitArrayFcValReq {std::move(type), this->_buildPropReqs(std::move(propReqs))}
    {
    }

private:
    static PropReqs _buildPropReqs(PropReqs&& propReqs)
    {
        propReqs.insert(intFcPrefDispBasePropReqEntry());
        return std::move(propReqs);
    }
};

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 unsigned integer
 * field class roles object property requirement.
 */
bt2c::JsonObjValReq::PropReqsEntry
uIntFcRolesPropReqEntry(const bt2c::JsonStrValInSetReq::Set& roles)
{
    return {strings::roles, {RolesValReq::shared(roles)}};
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
                                  PropReqs&& propReqs = {}) :
        FixedLenIntFcValReq {std::move(type), this->_buildPropReqs(roles, std::move(propReqs))}
    {
    }

public:
    explicit FixedLenUIntFcValReq(const bt2c::JsonStrValInSetReq::Set& roles) :
        FixedLenUIntFcValReq {this->typeStr(), roles}
    {
    }

    static SP shared(const bt2c::JsonStrValInSetReq::Set& roles)
    {
        return std::make_shared<FixedLenUIntFcValReq>(roles);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::fixedLenUInt;
    }

private:
    static PropReqs _buildPropReqs(const bt2c::JsonStrValInSetReq::Set& roles, PropReqs&& propReqs)
    {
        if (!roles.empty()) {
            propReqs.insert(uIntFcRolesPropReqEntry(roles));
        }

        return std::move(propReqs);
    }

    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FcValReq::_validate(jsonVal);
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid fixed-length unsigned integer field class:", jsonVal.loc());
            throw;
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
    explicit FixedLenSIntFcValReq(std::string&& type, PropReqs&& propReqs = {}) :
        FixedLenIntFcValReq {std::move(type), std::move(propReqs)}
    {
    }

public:
    explicit FixedLenSIntFcValReq() : FixedLenIntFcValReq {this->typeStr()}
    {
    }

    static SP shared()
    {
        return std::make_shared<FixedLenSIntFcValReq>();
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
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid fixed-length signed integer field class:", jsonVal.loc());
            throw;
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
    explicit EnumFcMappingsValReq() : bt2c::JsonObjValReq {{}, true}
    {
    }

    static SP shared()
    {
        return std::make_shared<EnumFcMappingsValReq>();
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            bt2c::JsonObjValReq::_validate(jsonVal);

            /* Require at least one mapping */
            if (jsonVal.asObj().size() < 1) {
                throwTextParseError("Expecting at least one mapping.", jsonVal);
            }

            /* Validate range sets */
            for (auto& keyJsonValPair : jsonVal.asObj()) {
                try {
                    _mRangeSetReq.validate(*keyJsonValPair.second);
                } catch (bt2c::TextParseError& exc) {
                    std::ostringstream ss;

                    ss << "In mapping `" << keyJsonValPair.first << "`:";
                    exc.appendErrorMsg(ss.str(), jsonVal.loc());
                    throw;
                }
            }
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid enumeration field class mappings:", jsonVal.loc());
            throw;
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
bt2c::JsonObjValReq::PropReqsEntry enumFcMappingsPropReqEntry()
{
    return {strings::mappings, {EnumFcMappingsValReq<JsonIntValReqT>::shared(), true}};
}

/*
 * CTF 2 JSON fixed-length unsigned enumeration field class value
 * requirement.
 */
class FixedLenUEnumFcValReq final : public FixedLenUIntFcValReq
{
public:
    explicit FixedLenUEnumFcValReq(const bt2c::JsonStrValInSetReq::Set& roles) :
        /* clang-format off */
        FixedLenUIntFcValReq {this->typeStr(), roles, {
            enumFcMappingsPropReqEntry<bt2c::JsonUIntValReq>()
        }}
    /* clang-format on */
    {
    }

    static SP shared(const bt2c::JsonStrValInSetReq::Set& roles)
    {
        return std::make_shared<FixedLenUEnumFcValReq>(roles);
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
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid fixed-length unsigned enumeration field class:",
                               jsonVal.loc());
            throw;
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
    explicit FixedLenSEnumFcValReq() :
        /* clang-format off */
        FixedLenSIntFcValReq {this->typeStr(), {
            enumFcMappingsPropReqEntry<bt2c::JsonSIntValReq>()
        }}
    /* clang-format on */
    {
    }

    static SP shared()
    {
        return std::make_shared<FixedLenSEnumFcValReq>();
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
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid fixed-length signed enumeration field class:",
                               jsonVal.loc());
            throw;
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
    explicit FixedLenFloatFcValReq() : FixedLenBitArrayFcValReq {this->typeStr()}
    {
    }

    static SP shared()
    {
        return std::make_shared<FixedLenFloatFcValReq>();
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
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid fixed-length floating-point number field class:",
                               jsonVal.loc());
            throw;
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
    explicit VarLenIntFcValReq(std::string&& type, PropReqs&& propReqs = {}) :
        FcValReq {std::move(type), this->_buildPropReqs(std::move(propReqs))}
    {
    }

private:
    static PropReqs _buildPropReqs(PropReqs&& propReqs)
    {
        propReqs.insert(intFcPrefDispBasePropReqEntry());
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
                                PropReqs&& propReqs = {}) :
        VarLenIntFcValReq {std::move(type), this->_buildPropReqs(roles, std::move(propReqs))}
    {
    }

public:
    explicit VarLenUIntFcValReq(const bt2c::JsonStrValInSetReq::Set& roles) :
        VarLenUIntFcValReq {this->typeStr(), roles}
    {
    }

    static SP shared(const bt2c::JsonStrValInSetReq::Set& roles)
    {
        return std::make_shared<VarLenUIntFcValReq>(roles);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::varLenUInt;
    }

private:
    static PropReqs _buildPropReqs(const bt2c::JsonStrValInSetReq::Set& roles, PropReqs&& propReqs)
    {
        if (!roles.empty()) {
            propReqs.insert(uIntFcRolesPropReqEntry(roles));
        }

        return std::move(propReqs);
    }

    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            FcValReq::_validate(jsonVal);
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid variable-length unsigned integer field class:",
                               jsonVal.loc());
            throw;
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
    explicit VarLenSIntFcValReq(std::string&& type, PropReqs&& propReqs = {}) :
        VarLenIntFcValReq {std::move(type), std::move(propReqs)}
    {
    }

public:
    explicit VarLenSIntFcValReq() : VarLenSIntFcValReq {this->typeStr()}
    {
    }

    static SP shared()
    {
        return std::make_shared<VarLenSIntFcValReq>();
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
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid variable-length signed integer field class:",
                               jsonVal.loc());
            throw;
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
    explicit VarLenUEnumFcValReq(const bt2c::JsonStrValInSetReq::Set& roles) :
        /* clang-format off */
        VarLenUIntFcValReq {this->typeStr(), roles, {
            enumFcMappingsPropReqEntry<bt2c::JsonUIntValReq>()
        }}
    /* clang-format on */
    {
    }

    static SP shared(const bt2c::JsonStrValInSetReq::Set& roles)
    {
        return std::make_shared<VarLenUEnumFcValReq>(roles);
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
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid variable-length unsigned enumeration field class:",
                               jsonVal.loc());
            throw;
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
    explicit VarLenSEnumFcValReq() :
        VarLenSIntFcValReq {this->typeStr(), {enumFcMappingsPropReqEntry<bt2c::JsonSIntValReq>()}}
    {
    }

    static SP shared()
    {
        return std::make_shared<VarLenSEnumFcValReq>();
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
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid variable-length signed enumeration field class:",
                               jsonVal.loc());
            throw;
        }
    }
};

/*
 * CTF 2 JSON null-terminated string field class value requirement.
 */
class NullTerminatedStrFcValReq final : public FcValReq
{
public:
    explicit NullTerminatedStrFcValReq() : FcValReq {this->typeStr()}
    {
    }

    static SP shared()
    {
        return std::make_shared<NullTerminatedStrFcValReq>();
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
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid null-terminated string field class:", jsonVal.loc());
            throw;
        }
    }
};

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 static-length field
 * class length object property requirement.
 */
bt2c::JsonObjValReq::PropReqsEntry staticLenFcLenPropReqEntry()
{
    return {strings::len, {bt2c::JsonValHasTypeReq::shared(bt2c::ValType::UINT), true}};
}

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 dynamic-length
 * field class length field location object property requirement.
 */
bt2c::JsonObjValReq::PropReqsEntry dynLenFcLenFieldLocPropReqEntry()
{
    return {strings::lenFieldLoc, {FieldLocValReq::shared(), true}};
}

/*
 * CTF 2 JSON static-length string field class value requirement.
 */
class StaticLenStrFcValReq final : public FcValReq
{
public:
    explicit StaticLenStrFcValReq() : FcValReq {this->typeStr(), {staticLenFcLenPropReqEntry()}}
    {
    }

    static SP shared()
    {
        return std::make_shared<StaticLenStrFcValReq>();
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
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid static-length string field class:", jsonVal.loc());
            throw;
        }
    }
};

/*
 * CTF 2 JSON dynamic-length string field class value requirement.
 */
class DynLenStrFcValReq final : public FcValReq
{
public:
    explicit DynLenStrFcValReq() : FcValReq {this->typeStr(), {dynLenFcLenFieldLocPropReqEntry()}}
    {
    }

    static SP shared()
    {
        return std::make_shared<DynLenStrFcValReq>();
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
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid dynamic-length string field class:", jsonVal.loc());
            throw;
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
    explicit BlobFcValReq(std::string&& type, PropReqs&& propReqs = {}) :
        FcValReq {std::move(type), this->_buildPropReqs(std::move(propReqs))}
    {
    }

private:
    static PropReqs _buildPropReqs(PropReqs&& propReqs)
    {
        addToPropReqs(propReqs, strings::mediaType,
                      bt2c::JsonValHasTypeReq::shared(bt2c::ValType::STR));
        return std::move(propReqs);
    }
};

/*
 * CTF 2 JSON static-length BLOB field class value requirement.
 */
class StaticLenBlobFcValReq final : public BlobFcValReq
{
public:
    explicit StaticLenBlobFcValReq(const bool acceptMetadataStreamUuidRole) :
        BlobFcValReq {this->typeStr(), this->_buildPropReqs(acceptMetadataStreamUuidRole)}
    {
    }

    static SP shared(const bool acceptMetadataStreamUuidRole)
    {
        return std::make_shared<StaticLenBlobFcValReq>(acceptMetadataStreamUuidRole);
    }

    static constexpr const char *typeStr() noexcept
    {
        return strings::staticLenBlob;
    }

private:
    static PropReqs _buildPropReqs(const bool acceptMetadataStreamUuidRole)
    {
        PropReqs propReqs;

        propReqs.insert(staticLenFcLenPropReqEntry());

        if (acceptMetadataStreamUuidRole) {
            propReqs.insert({strings::roles, RolesValReq::shared({strings::metadataStreamUuid})});
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
                    std::ostringstream ss;

                    ss << "`" << strings::len << "` property: expecting 16, not " << *jsonLen
                       << ", because the field class has the `" << strings::metadataStreamUuid
                       << "`role.";
                    throwTextParseError(ss, jsonLen);
                }
            }
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid static-length BLOB field class:", jsonVal.loc());
            throw;
        }
    }
};

/*
 * CTF 2 JSON dynamic-length BLOB field class value requirement.
 */
class DynLenBlobFcValReq final : public BlobFcValReq
{
public:
    explicit DynLenBlobFcValReq() :
        BlobFcValReq {this->typeStr(), {dynLenFcLenFieldLocPropReqEntry()}}
    {
    }

    static SP shared()
    {
        return std::make_shared<DynLenBlobFcValReq>();
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
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid dynamic-length BLOB field class:", jsonVal.loc());
            throw;
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
    explicit AnyFcValReqWrapper(const AnyFcValReq& anyFcValReq) : _mAnyFcValReq {&anyFcValReq}
    {
    }

    static SP shared(const AnyFcValReq& anyFcValReq)
    {
        return std::make_shared<AnyFcValReqWrapper>(anyFcValReq);
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
                                                     const AnyFcValReq& anyFcValReq)
{
    return {std::move(key), {AnyFcValReqWrapper::shared(anyFcValReq), true}};
}

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 object name object
 * property requirement.
 */
bt2c::JsonObjValReq::PropReqsEntry namePropReqEntry(const bool isRequired)
{
    return {strings::name, {bt2c::JsonValHasTypeReq::shared(bt2c::ValType::STR), isRequired}};
}

/*
 * CTF 2 JSON structure field member class value requirement.
 */
class StructFieldMemberClsValReq final : public bt2c::JsonObjValReq
{
public:
    explicit StructFieldMemberClsValReq(const AnyFcValReq& anyFcValReq) :
        /* clang-format off */
        bt2c::JsonObjValReq {{
            namePropReqEntry(true),
            anyFcPropReqEntry(strings::fc, anyFcValReq),
            userAttrsPropReqEntry(),
            extPropReqEntry(),
        }}
    /* clang-format on */
    {
    }

    static SP shared(const AnyFcValReq& anyFcValReq)
    {
        return std::make_shared<StructFieldMemberClsValReq>(anyFcValReq);
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            bt2c::JsonObjValReq::_validate(jsonVal);
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid structure field member class:", jsonVal.loc());
            throw;
        }
    }
};

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 minimum alignment
 * object property requirement.
 */
bt2c::JsonObjValReq::PropReqsEntry minAlignPropReqEntry()
{
    return {strings::minAlign, AlignValReq::shared()};
}

/*
 * Validates that, within the JSON array value having the key `propName`
 * within the JSON object value `jsonVal`, the `name` property of each
 * (JSON object value) element, if it exists, is unique.
 *
 * Throws `TextParseError` on failure, using `elemName` to name the
 * element having a duplicate name.
 */
void validateUniqueEntryNames(const bt2c::JsonVal& jsonVal, const char * const propName,
                              const char * const elemName)
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
            std::ostringstream ss;

            ss << "Duplicate " << elemName << " name `" << *jsonNameStr << "`.";
            throwTextParseError(ss, *jsonName);
        }

        /* Add to set */
        names.insert(*jsonNameStr);
    }
}

/*
 * CTF 2 JSON structure field class value requirement.
 */
class StructFcValReq final : public FcValReq
{
public:
    explicit StructFcValReq(const AnyFcValReq& anyFcValReq) :
        /* clang-format off */
        FcValReq {this->typeStr(), {
            {strings::memberClasses, {
                bt2c::JsonArrayValReq::shared(StructFieldMemberClsValReq::shared(anyFcValReq))}
            },
            minAlignPropReqEntry(),
        }}
    /* clang-format on */
    {
    }

    static SP shared(const AnyFcValReq& anyFcValReq)
    {
        return std::make_shared<StructFcValReq>(anyFcValReq);
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
            validateUniqueEntryNames(jsonVal, strings::memberClasses,
                                     "structure field member class");
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid structure field class:", jsonVal.loc());
            throw;
        }
    }
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
    explicit ArrayFcValReq(std::string&& type, const AnyFcValReq& anyFcValReq,
                           PropReqs&& propReqs = {}) :
        FcValReq {std::move(type), this->_buildPropReqs(anyFcValReq, std::move(propReqs))}
    {
    }

private:
    static PropReqs _buildPropReqs(const AnyFcValReq& anyFcValReq, PropReqs&& propReqs)
    {
        propReqs.insert(anyFcPropReqEntry(strings::elemFc, anyFcValReq));
        propReqs.insert(minAlignPropReqEntry());
        return std::move(propReqs);
    }
};

/*
 * CTF 2 JSON static-length array field class value requirement.
 */
class StaticLenArrayFcValReq final : public ArrayFcValReq
{
public:
    explicit StaticLenArrayFcValReq(const AnyFcValReq& anyFcValReq) :
        /* clang-format off */
        ArrayFcValReq {this->typeStr(), anyFcValReq, {
            staticLenFcLenPropReqEntry()
        }}
    /* clang-format on */
    {
    }

    static SP shared(const AnyFcValReq& anyFcValReq)
    {
        return std::make_shared<StaticLenArrayFcValReq>(anyFcValReq);
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
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid static-length array field class:", jsonVal.loc());
            throw;
        }
    }
};

/*
 * CTF 2 JSON dynamic-length array field class value requirement.
 */
class DynLenArrayFcValReq final : public ArrayFcValReq
{
public:
    explicit DynLenArrayFcValReq(const AnyFcValReq& anyFcValReq) :
        /* clang-format off */
        ArrayFcValReq {this->typeStr(), anyFcValReq, {
            dynLenFcLenFieldLocPropReqEntry()
        }}
    /* clang-format on */
    {
    }

    static SP shared(const AnyFcValReq& anyFcValReq)
    {
        return std::make_shared<DynLenArrayFcValReq>(anyFcValReq);
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
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid dynamic-length array field class:", jsonVal.loc());
            throw;
        }
    }
};

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 selector field
 * location object property requirement.
 */
bt2c::JsonObjValReq::PropReqsEntry selFieldLocPropReqEntry()
{
    return {strings::selFieldLoc, {FieldLocValReq::shared(), true}};
}

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 selector field
 * ranges object property requirement.
 */
bt2c::JsonObjValReq::PropReqsEntry selFieldRangesPropReqEntry(const bool isRequired)
{
    return {strings::selFieldRanges, {ctf::src::Ctf2JsonIntRangeSetValReq::shared(), isRequired}};
}

/*
 * CTF 2 JSON optional field class value requirement.
 */
class OptionalFcValReq final : public FcValReq
{
public:
    explicit OptionalFcValReq(const AnyFcValReq& anyFcValReq) :
        /* clang-format off */
        FcValReq {this->typeStr(), {
            anyFcPropReqEntry(strings::fc, anyFcValReq),
            selFieldLocPropReqEntry(),
            selFieldRangesPropReqEntry(false),
        }}
    /* clang-format on */
    {
    }

    static SP shared(const AnyFcValReq& anyFcValReq)
    {
        return std::make_shared<OptionalFcValReq>(anyFcValReq);
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
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid optional field class:", jsonVal.loc());
            throw;
        }
    }
};

/*
 * CTF 2 JSON variant field class option class value requirement.
 */
class VariantFcOptValReq final : public bt2c::JsonObjValReq
{
public:
    explicit VariantFcOptValReq(const AnyFcValReq& anyFcValReq) :
        /* clang-format off */
        bt2c::JsonObjValReq {{
            namePropReqEntry(false),
            anyFcPropReqEntry(strings::fc, anyFcValReq),
            selFieldRangesPropReqEntry(true),
            userAttrsPropReqEntry(),
            extPropReqEntry(),
        }}
    /* clang-format on */
    {
    }

    static SP shared(const AnyFcValReq& anyFcValReq)
    {
        return std::make_shared<VariantFcOptValReq>(anyFcValReq);
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
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid variant field class option:", jsonVal.loc());
            throw;
        }
    }
};

/*
 * CTF 2 JSON variant field class value requirement.
 */
class VariantFcValReq final : public FcValReq
{
public:
    explicit VariantFcValReq(const AnyFcValReq& anyFcValReq) :
        /* clang-format off */
        FcValReq {this->typeStr(), {
            {strings::opts, {
                bt2c::JsonArrayValReq::shared(1, nonstd::nullopt,
                                        VariantFcOptValReq::shared(anyFcValReq)),
                true
            }},
            selFieldLocPropReqEntry(),
        }}
    /* clang-format on */
    {
    }

    static SP shared(const AnyFcValReq& anyFcValReq)
    {
        return std::make_shared<VariantFcValReq>(anyFcValReq);
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
            validateUniqueEntryNames(jsonVal, strings::opts, "variant field class option");
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid variant field class:", jsonVal.loc());
            throw;
        }
    }
};

/*
 * CTF 2 JSON (any) field class value requirement.
 */
class AnyFcValReq final : public bt2c::JsonObjValReq
{
public:
    explicit AnyFcValReq(const bt2c::JsonStrValInSetReq::Set& uIntFcRoles = {},
                         const bool staticLenBlobHasTraceTypeUuidRole = false) :
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
                    }), true
                }
            }
        }, true},
        _mFlUIntFcValReq {uIntFcRoles},
        _mFlUEnumFcValReq {uIntFcRoles},
        _mVlUIntFcValReq {uIntFcRoles},
        _mVlUEnumFcValReq {uIntFcRoles},
        _mStaticLenBlobFcValReq {staticLenBlobHasTraceTypeUuidRole},
        _mStructFcValReq {*this},
        _mStaticLenArrayFcValReq {*this},
        _mDynLenArrayFcValReq {*this},
        _mOptionalFcValReq {*this},
        _mVariantFcValReq {*this}
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

    static SP shared()
    {
        return std::make_shared<AnyFcValReq>();
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
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid field class:", jsonVal.loc());
            throw;
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
    explicit ScopeFcValReq(const bt2c::JsonStrValInSetReq::Set& uIntFcRoles = {},
                           const bool staticLenBlobHasTraceTypeUuidRole = false) :
        _mAnyFcValReq {uIntFcRoles, staticLenBlobHasTraceTypeUuidRole},
        _mStructFcValReq {_mAnyFcValReq}
    {
    }

    static SP shared(const bt2c::JsonStrValInSetReq::Set& uIntFcRoles = {},
                     const bool staticLenBlobHasTraceTypeUuidRole = false)
    {
        return std::make_shared<ScopeFcValReq>(uIntFcRoles, staticLenBlobHasTraceTypeUuidRole);
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            _mStructFcValReq.validate(jsonVal);
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid scope field class:", jsonVal.loc());
            throw;
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
    explicit FragmentValReq(std::string&& type, PropReqs&& propReqs = {}) :
        bt2c::JsonObjValReq {this->_buildPropReqs(std::move(type), std::move(propReqs))}
    {
    }

private:
    static PropReqs _buildPropReqs(std::string&& type, PropReqs&& propReqs)
    {
        propReqs.insert(objTypePropReqEntry(std::move(type)));
        propReqs.insert(userAttrsPropReqEntry());
        propReqs.insert(extPropReqEntry());
        return std::move(propReqs);
    }
};

/*
 * CTF 2 preamble fragment value requirement.
 */
class PreambleFragmentValReq final : public FragmentValReq
{
public:
    explicit PreambleFragmentValReq() :
        /* clang-format off */
        FragmentValReq {this->typeStr(), {
            {strings::version, {bt2c::JsonUIntValInSetReq::shared(2), true}},
            {strings::uuid, {UuidValReq::shared()}},
        }}
    /* clang-format on */
    {
    }

    static SP shared()
    {
        return std::make_shared<PreambleFragmentValReq>();
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
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid preamble fragment:", jsonVal.loc());
            throw;
        }
    }
};

/*
 * CTF 2 JSON clock offset value requirement.
 */
class ClkOffsetValReq final : public bt2c::JsonObjValReq
{
public:
    explicit ClkOffsetValReq() :
        /* clang-format off */
        bt2c::JsonObjValReq {{
            {strings::seconds, {bt2c::JsonAnyIntValReq::shared()}},
            {strings::cycles, {bt2c::JsonValHasTypeReq::shared(bt2c::ValType::UINT)}},
        }}
    /* clang-format on */
    {
    }

    static SP shared()
    {
        return std::make_shared<ClkOffsetValReq>();
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            bt2c::JsonObjValReq::_validate(jsonVal);
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid clock offset:", jsonVal.loc());
            throw;
        }
    }
};

/*
 * CTF 2 clock class fragment value requirement.
 */
class ClkClsFragmentValReq final : public FragmentValReq
{
public:
    explicit ClkClsFragmentValReq() :
        /* clang-format off */
        FragmentValReq {this->typeStr(), {
            namePropReqEntry(true),
            {strings::freq, {bt2c::JsonUIntValInRangeReq::shared(1, nonstd::nullopt), true}},
            {strings::descr, {bt2c::JsonValHasTypeReq::shared(bt2c::ValType::STR)}},
            {strings::uuid, {UuidValReq::shared()}},
            {strings::originIsUnixEpoch, {bt2c::JsonValHasTypeReq::shared(bt2c::ValType::BOOL)}},
            {strings::offset, {ClkOffsetValReq::shared()}},
            {strings::precision, {bt2c::JsonValHasTypeReq::shared(bt2c::ValType::UINT)}},
        }}
    /* clang-format on */
    {
    }

    static SP shared()
    {
        return std::make_shared<ClkClsFragmentValReq>();
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
                        std::ostringstream ss;

                        ss << "Invalid `" << strings::cycles << "` property of `" << strings::offset
                           << "` property: "
                           << "value " << cycles << " is greater than the value of the "
                           << "`" << strings::freq << "` property (" << freq << ").";
                        throwTextParseError(ss, *jsonCycles);
                    }
                }
            }
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid clock class fragment:", jsonVal.loc());
            throw;
        }
    }
};

/*
 * CTF 2 trace class fragment value requirement.
 */
class TraceClsFragmentValReq final : public FragmentValReq
{
public:
    explicit TraceClsFragmentValReq() :
        /* clang-format off */
        FragmentValReq {this->typeStr(), {
            {strings::uuid, {UuidValReq::shared()}},
            {strings::env, {TraceEnvValReq::shared()}},
            {strings::pktHeaderFc, {
                ScopeFcValReq::shared({
                    strings::dataStreamClsId,
                    strings::dataStreamId,
                    strings::pktMagicNumber,
                }, true)
            }},
        }}
    /* clang-format on */
    {
    }

    static SP shared()
    {
        return std::make_shared<TraceClsFragmentValReq>();
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
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid trace class fragment:", jsonVal.loc());
            throw;
        }
    }
};

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 object namespace
 * object property requirement.
 */
bt2c::JsonObjValReq::PropReqsEntry nsPropReqEntry()
{
    return {strings::ns, {bt2c::JsonValHasTypeReq::shared(bt2c::ValType::STR)}};
}

/*
 * Returns the pair (suitable for insertion into a
 * `bt2c::JsonObjValReq::PropReqs` instance) for the CTF 2 object numeric ID
 * object property requirement.
 */
bt2c::JsonObjValReq::PropReqsEntry idPropReqEntry()
{
    return {strings::id, {bt2c::JsonValHasTypeReq::shared(bt2c::ValType::UINT)}};
}

/*
 * CTF 2 data stream class fragment value requirement.
 */
class DataStreamClsFragmentValReq final : public FragmentValReq
{
public:
    explicit DataStreamClsFragmentValReq() :
        /* clang-format off */
        FragmentValReq {this->typeStr(), {
            namePropReqEntry(false),
            nsPropReqEntry(),
            idPropReqEntry(),
            {strings::defClkClsName, {bt2c::JsonValHasTypeReq::shared(bt2c::ValType::STR)}},
            {strings::pktCtxFc, {ScopeFcValReq::shared({
                strings::defClkTs,
                strings::discEventRecordCounterSnap,
                strings::pktContentLen,
                strings::pktEndDefClkTs,
                strings::pktSeqNum,
                strings::pktTotalLen,
            })}},
            {strings::eventRecordHeaderFc, {ScopeFcValReq::shared({
                strings::defClkTs,
                strings::eventRecordClsId,
            })}},
            {strings::eventRecordCommonCtxFc, {ScopeFcValReq::shared()}},
        }}
    /* clang-format on */
    {
    }

    static SP shared()
    {
        return std::make_shared<DataStreamClsFragmentValReq>();
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
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid data stream class fragment:", jsonVal.loc());
            throw;
        }
    }
};

/*
 * CTF 2 event record class fragment value requirement.
 */
class EventRecordClsFragmentValReq final : public FragmentValReq
{
public:
    explicit EventRecordClsFragmentValReq() :
        /* clang-format off */
        FragmentValReq {this->typeStr(), {
            namePropReqEntry(false),
            nsPropReqEntry(),
            idPropReqEntry(),
            {strings::dataStreamClsId, {bt2c::JsonValHasTypeReq::shared(bt2c::ValType::UINT)}},
            {strings::specCtxFc, {ScopeFcValReq::shared()}},
            {strings::payloadFc, {ScopeFcValReq::shared()}},
        }}
    /* clang-format on */
    {
    }

    static SP shared()
    {
        return std::make_shared<EventRecordClsFragmentValReq>();
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
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid event record class fragment:", jsonVal.loc());
            throw;
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
    explicit Ctf2JsonAnyFragmentValReqImpl() :
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
                    }), true
                }
            }
        }, true}
    /* clang-format on */
    {
        this->_addToFcValReqs(_preambleFragmentValReq);
        this->_addToFcValReqs(_traceClsFragmentValReq);
        this->_addToFcValReqs(_clkClsFragmentValReq);
        this->_addToFcValReqs(_dataStreamClsFragmentValReq);
        this->_addToFcValReqs(_eventRecordClsFragmentValReq);
    }

    static SP shared()
    {
        return std::make_shared<Ctf2JsonAnyFragmentValReqImpl>();
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
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid fragment:", jsonVal.loc());
            throw;
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

Ctf2JsonAnyFragmentValReq::Ctf2JsonAnyFragmentValReq() :
    _mImpl {new internal::Ctf2JsonAnyFragmentValReqImpl}
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
