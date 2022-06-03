/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_VAL_REQ_HPP
#define BABELTRACE_CPP_COMMON_VAL_REQ_HPP

#include <cassert>
#include <string>
#include <memory>
#include <regex>
#include <unordered_map>
#include <set>
#include <limits>
#include <sstream>

#include "optional.hpp"
#include "exc.hpp"
#include "text-loc.hpp"
#include "text-loc-str.hpp"
#include "log-cfg.hpp"
#include "cfg-logging-error-reporting-throw.hpp"

namespace bt2_common {

/*
 * This set of class templates makes it possible to get basic
 * requirement classes to validate JSON-like value objects, that is, a
 * system of null, boolean, unsigned/signed integer, real, string,
 * array, and object value objects.
 *
 * All the class templates accept a `ValT` parameter which is the base
 * type of the objects to validate, as well as `ValOpsT`, a structure
 * which defines specific value operations.
 *
 * The requirements of `ValOptsT` are:
 *
 * static ValType valType(const ValT& val):
 *     Returns the type of `val` as a `ValType` value.
 *
 * static const char *typeDetStr(ValType type):
 *     Returns the determiner (lowercase) to use for the value type
 *     `type`.
 *
 *     This is required to generate an error message.
 *
 * static const char *typeStr(ValType type):
 *     Returns the name (lowercase) of the value type `type`.
 *
 *     This is required to generate an error message.
 *
 * static constexpr const char *objValPropName:
 *     Name (lowercase) of an object value object property.
 *
 * static const TextLoc& valLoc(const ValT& val):
 *     Returns the location of the value `val`.
 *
 *     This is required to build a text parse error (`TextParseError`).
 *
 * static const SomeUIntVal& asUInt(const ValT& val):
 *     Returns `val` as an unsigned integer value object.
 *
 * static const SomeStrVal& asStr(const ValT& val):
 *     Returns `val` as a string value object.
 *
 * static const SomeArrayVal& asArray(const ValT& val):
 *     Returns `val` as an array value object.
 *
 * static const SomeObjVal& asObj(const ValT& val):
 *     Returns `val` as an object value object.
 *
 * template <typename ScalarValT> using ScalarValRawValT = ...:
 *     Raw value type of the scalar value object type `ScalarValT`.
 *
 * static unsigned long long scalarValRawVal(const SomeUIntVal& val):
 *     Returns the raw value of the unsigned value object `val`.
 *
 * static long long scalarValRawVal(const SomeSIntVal& val):
 *     Returns the raw value of the signed value object `val`.
 *
 * static double scalarValRawVal(const SomeRealVal& val):
 *     Returns the raw value of the real value object `val`.
 *
 * static const std::string& scalarValRawVal(const SomeStrVal& val):
 *     Returns the raw value of the string value object `val`.
 *
 * static std::size_t arrayValSize(const SomeArrayVal& val):
 *     Returns the size of the array value object `val`.
 *
 * static const ValT& arrayValElem(const SomeArrayVal& val, std::size_t index):
 *     Returns the element of the array value object `val` at the index
 *     `index`.
 *
 * static const ValT *objValVal(const SomeObjVal& val, const std::string& key):
 *     Returns the value of the object value object `val` having the key
 *     `key`, or `nullptr` if there's none.
 *
 * static SomeIterator objValBegin(const SomeObjVal& val):
 *     Returns an iterator at the beginning of the object value object
 *     `val`.
 *
 * static SomeIterator objValEnd(const SomeObjVal& val):
 *     Returns an iterator at the end of the object value object `val`.
 *
 * static const std::string& objValItKey(const SomeIterator& it):
 *     Returns the key of the object value object iterator `it`.
 *
 * static const ValT& objValItVal(const SomeIterator& it):
 *     Returns the value object of the object value object iterator
 *     `it`.
 */

/*
 * Value requirement logging configuration.
 */
class ValReqLogCfg
{
public:
    /*
     * Builds a value requirement logging configuration.
     *
     * Not explicit to allow passing a generic logging configuration
     * instead of this object as a function parameter.
     */
    ValReqLogCfg(const LogCfg& logCfg,
                 const TextLocStrFmt textLocStrFmt = TextLocStrFmt::LINE_COL_NOS_AND_OFFSET) :
        _mLogCfg {logCfg},
        _mTextLocStrFmt {textLocStrFmt}
    {
    }

    const LogCfg& logCfg() const noexcept
    {
        return _mLogCfg;
    }

    TextLocStrFmt textLocStrFmt() const noexcept
    {
        return _mTextLocStrFmt;
    }

private:
    LogCfg _mLogCfg;
    TextLocStrFmt _mTextLocStrFmt;
};

/*
 * Value requirement abstract base class.
 */
template <typename ValT, typename ValOpsT>
class ValReq
{
public:
    /* Shared pointer to constant value requirement */
    using SP = std::shared_ptr<const ValReq>;

protected:
    /*
     * Builds a value requirement.
     *
     * When the value requirement logs or appends a cause to the error
     * of the current thread, it uses `logCfg` to format the text
     * location part of the message.
     */
    explicit ValReq(const ValReqLogCfg& logCfg) noexcept : _mLogCfg {logCfg}
    {
    }

public:
    /* Deleted copy/move operations to simplify */
    ValReq(const ValReq&) = delete;
    ValReq(ValReq&&) = delete;
    ValReq& operator=(const ValReq&) = delete;
    ValReq& operator=(ValReq&&) = delete;

    virtual ~ValReq() = default;

    /*
     * Validates that `val` satisfies this requirement.
     */
    void validate(const ValT& val) const
    {
        this->_validate(val);
    }

protected:
    std::string _locStr(const TextLoc& loc) const
    {
        return textLocStr(loc, _mLogCfg.textLocStrFmt());
    }

    std::string _locStr(const ValT& val) const
    {
        return ValReq::_locStr(ValOpsT::valLoc(val));
    }

    const LogCfg& _logCfg() const noexcept
    {
        return _mLogCfg.logCfg();
    }

private:
    /*
     * Requirement-specific validation.
     */
    virtual void _validate(const ValT& val) const
    {
    }

    /* Logging configuration */
    ValReqLogCfg _mLogCfg;
};

/*
 * Value type.
 */
enum class ValType
{
    NUL,
    BOOL,
    SINT,
    UINT,
    REAL,
    STR,
    ARRAY,
    OBJ,
};

/*
 * "Value has type" requirement.
 *
 * An instance of this class validates that a value has a given type.
 */
template <typename ValT, typename ValOpsT>
class ValHasTypeReq : public ValReq<ValT, ValOpsT>
{
public:
    /*
     * Builds a "value has type" requirement: _validate() validates that
     * the type of the value is `type`.
     *
     * When the value requirement logs or appends a cause to the error
     * of the current thread, it uses `logCfg` to format the text
     * location part of the message.
     */
    explicit ValHasTypeReq(const ValType type, const ValReqLogCfg& logCfg) noexcept :
        ValReq<ValT, ValOpsT> {logCfg}, _mType {type}
    {
    }

    /*
     * Returns a shared pointer to "value has type" requirement,
     * forwarding the parameters to the constructor.
     */
    static typename ValReq<ValT, ValOpsT>::SP shared(const ValType type, const ValReqLogCfg& logCfg)
    {
        return std::make_shared<ValHasTypeReq>(type, logCfg);
    }

protected:
    void _validate(const ValT& val) const override
    {
        if (ValOpsT::valType(val) != _mType) {
            BT_CLOGE_APPEND_CAUSE_AND_THROW_EX(
                this->_logCfg(), Error, "[%s] Expecting %s %s.", this->_locStr(val).c_str(),
                ValOpsT::typeDetStr(_mType), ValOpsT::typeStr(_mType));
        }
    }

private:
    /* Required value type */
    ValType _mType;
};

/*
 * Any integer value requirement.
 *
 * An instance of this class validates that a value is an integer value
 * (unsigned or signed).
 */
template <typename ValT, typename ValOpsT>
class AnyIntValReq : public ValReq<ValT, ValOpsT>
{
public:
    explicit AnyIntValReq(const ValReqLogCfg& logCfg) noexcept : ValReq<ValT, ValOpsT> {logCfg}
    {
    }

    /*
     * Returns a shared pointer to any integer value requirement,
     * forwarding the parameters to the constructor.
     */
    static typename ValReq<ValT, ValOpsT>::SP shared(const ValReqLogCfg& logCfg)
    {
        return std::make_shared<AnyIntValReq>(logCfg);
    }

protected:
    void _validate(const ValT& val) const override
    {
        if (!val.isUInt() && !val.isSInt()) {
            BT_CLOGE_APPEND_CAUSE_AND_THROW_EX(this->_logCfg(), Error, "[%s] Expecting an integer.",
                                               this->_locStr(val).c_str());
        }
    }
};

/*
 * Unsigned integer (range) value requirement.
 *
 * An instance of this class validates that a value is an unsigned
 * integer value.
 */
template <typename ValT, typename ValOpsT>
class UIntValReq : public ValHasTypeReq<ValT, ValOpsT>
{
public:
    /*
     * Builds an unsigned integer value: _validate() validates that the
     * integer value is an unsigned integer type.
     *
     * When the value requirement logs or appends a cause to the error
     * of the current thread, it uses `logCfg` to format the text
     * location part of the message.
     */
    explicit UIntValReq(const ValReqLogCfg& logCfg) noexcept :
        ValHasTypeReq<ValT, ValOpsT> {ValType::UINT, logCfg}
    {
    }

    /*
     * Returns a shared pointer to unsigned integer value requirement,
     * forwarding the parameters to the constructor.
     */
    static typename ValReq<ValT, ValOpsT>::SP shared(const ValReqLogCfg& logCfg)
    {
        return std::make_shared<UIntValReq>(logCfg);
    }
};

/*
 * Signed integer value (range) requirement.
 *
 * An instance of this class validates that a value is an integer value
 * (unsigned or signed) and that its raw value is between
 * -9,223,372,036,854,775,808 and 9,223,372,036,854,775,807.
 */
template <typename ValT, typename ValOpsT>
class SIntValReq : public AnyIntValReq<ValT, ValOpsT>
{
public:
    explicit SIntValReq(const ValReqLogCfg& logCfg) noexcept : AnyIntValReq<ValT, ValOpsT> {logCfg}
    {
    }

    /*
     * Returns a shared pointer to signed value requirement, forwarding
     * the parameters to the constructor.
     */
    static typename ValReq<ValT, ValOpsT>::SP shared(const ValReqLogCfg& logCfg)
    {
        return std::make_shared<SIntValReq>(logCfg);
    }

protected:
    void _validate(const ValT& val) const override
    {
        /* Validate that it's an integer value */
        AnyIntValReq<ValT, ValOpsT>::_validate(val);

        if (ValOpsT::valType(val) == ValType::SINT) {
            /* Always correct */
            return;
        }

        /* Validate the raw value */
        static constexpr auto llMaxAsUll =
            static_cast<unsigned long long>(std::numeric_limits<long long>::max());

        const auto rawVal = ValOpsT::scalarValRawVal(ValOpsT::asUInt(val));

        if (rawVal > llMaxAsUll) {
            std::ostringstream ss;

            ss << "Expecting a signed integer: " << rawVal << " is greater than " << llMaxAsUll
               << '.';
            BT_CLOGE_APPEND_CAUSE_AND_THROW_EX(this->_logCfg(), Error, "[%s] %s",
                                               this->_locStr(val).c_str(), ss.str().c_str());
        }
    }
};

/*
 * "Integer value in range" requirement template.
 *
 * An instance of this class validates that, given a value V of type
 * `IntValT`:
 *
 * • V has the type enumerator `TypeV`.
 * • The raw value of V is within a given range.
 */
template <typename ValT, typename ValOpsT, typename IntValT, ValType TypeV>
class IntValInRangeReq : public ValHasTypeReq<ValT, ValOpsT>
{
private:
    /* Raw value type */
    using _RawVal = typename ValOpsT::template ScalarValRawValT<IntValT>;

public:
    /*
     * Builds an "integer value in range" requirement: _validate()
     * validates that the raw value of the integer value is:
     *
     * • If `minVal` is set: greater than or equal to `*minVal`.
     * • If `maxVal` is set: less than or equal to `*maxVal`.
     *
     * When the value requirement logs or appends a cause to the error
     * of the current thread, it uses `logCfg` to format the text
     * location part of the message.
     */
    explicit IntValInRangeReq(const nonstd::optional<_RawVal>& minVal,
                              const nonstd::optional<_RawVal>& maxVal,
                              const ValReqLogCfg& logCfg) noexcept :
        ValHasTypeReq<ValT, ValOpsT> {TypeV, logCfg},
        _mMinVal {minVal ? *minVal : std::numeric_limits<_RawVal>::min()},
        _mMaxVal {maxVal ? *maxVal : std::numeric_limits<_RawVal>::max()}
    {
    }

    /*
     * Builds an "integer value in range" requirement: _validate()
     * validates that the raw value of the integer value is exactly
     * `exactVal`.
     *
     * When the value requirement logs or appends a cause to the error
     * of the current thread, it uses `logCfg` to format the text
     * location part of the message.
     */
    explicit IntValInRangeReq(const _RawVal exactVal, const ValReqLogCfg& logCfg) noexcept :
        IntValInRangeReq {exactVal, exactVal, logCfg}
    {
    }

    /*
     * Returns a shared pointer to "integer value in range" requirement,
     * forwarding the parameters to the constructor.
     */
    static typename ValReq<ValT, ValOpsT>::SP shared(const nonstd::optional<_RawVal>& minVal,
                                                     const nonstd::optional<_RawVal>& maxVal,
                                                     const ValReqLogCfg& logCfg)
    {
        return std::make_shared<IntValInRangeReq>(minVal, maxVal, logCfg);
    }

    /*
     * Returns a shared pointer to "integer value in range" requirement,
     * forwarding the parameters to the constructor.
     */
    static typename ValReq<ValT, ValOpsT>::SP shared(const _RawVal exactVal,
                                                     const ValReqLogCfg& logCfg)
    {
        return std::make_shared<IntValInRangeReq>(exactVal, logCfg);
    }

protected:
    void _validate(const ValT& val) const override
    {
        ValHasTypeReq<ValT, ValOpsT>::_validate(val);

        auto& intVal = static_cast<const IntValT&>(val);
        const auto rawVal = ValOpsT::scalarValRawVal(intVal);

        if (rawVal < _mMinVal) {
            std::ostringstream ss;

            ss << "Integer " << rawVal << " is too small: "
               << "expecting at least " << _mMinVal << ".";
            BT_CLOGE_APPEND_CAUSE_AND_THROW_EX(this->_logCfg(), Error, "[%s] %s",
                                               this->_locStr(intVal).c_str(), ss.str().c_str());
        }

        if (rawVal > _mMaxVal) {
            std::ostringstream ss;

            ss << "Integer " << rawVal << " is too large: "
               << "expecting at most " << _mMaxVal << ".";
            BT_CLOGE_APPEND_CAUSE_AND_THROW_EX(this->_logCfg(), Error, "[%s] %s",
                                               this->_locStr(intVal).c_str(), ss.str().c_str());
        }
    }

private:
    /* Minimum raw value */
    _RawVal _mMinVal;

    /* Maximum raw value */
    _RawVal _mMaxVal;
};

namespace internal {

template <typename RawValT>
void writeRawVal(std::ostringstream& ss, const RawValT& rawVal)
{
    ss << rawVal;
}

template <>
inline void writeRawVal<std::string>(std::ostringstream& ss, const std::string& val)
{
    ss << '`' << val << '`';
}

template <>
inline void writeRawVal<bool>(std::ostringstream& ss, const bool& val)
{
    writeRawVal(ss, std::string {val ? "true" : "false"});
}

} /* namespace internal */

/*
 * "Scalar value in set" requirement template.
 *
 * An instance of this class validates that, given a value V of type
 * `ScalarValT`:
 *
 * • V has the type enumerator `TypeV`.
 * • The raw value of V is an element of a given set.
 */
template <typename ValT, typename ValOpsT, typename ScalarValT, ValType TypeV>
class ScalarValInSetReq : public ValHasTypeReq<ValT, ValOpsT>
{
private:
    /* Raw value type */
    using _RawVal = typename ValOpsT::template ScalarValRawValT<ScalarValT>;

public:
    /*
     * Raw value set type.
     *
     * Using `std::set` instead of `std::unordered_set` because
     * _setStr() needs the elements in order.
     */
    using Set = std::set<_RawVal>;

    /*
     * Builds a "scalar value in set" requirement: _validate() validates
     * that the raw value of the scalar value is an element of `set`.
     *
     * When the value requirement logs or appends a cause to the error
     * of the current thread, it uses `logCfg` to format the text
     * location part of the message.
     */
    explicit ScalarValInSetReq(Set set, const ValReqLogCfg& logCfg) :
        ValHasTypeReq<ValT, ValOpsT> {TypeV, logCfg}, _mSet {std::move(set)}
    {
    }

    /*
     * Builds a "scalar value in set" requirement: _validate() validates
     * that the raw value of the scalar value is exactly `rawVal`.
     *
     * When the value requirement logs or appends a cause to the error
     * of the current thread, it uses `logCfg` to format the text
     * location part of the message.
     */
    explicit ScalarValInSetReq(_RawVal rawVal, const ValReqLogCfg& logCfg) :
        ScalarValInSetReq {Set {std::move(rawVal)}, logCfg}
    {
    }

    /*
     * Returns a shared pointer to "scalar value in set" requirement,
     * forwarding the parameters to the constructor.
     */
    static typename ValReq<ValT, ValOpsT>::SP shared(Set set, const ValReqLogCfg& logCfg)
    {
        return std::make_shared<ScalarValInSetReq>(std::move(set), logCfg);
    }

    /*
     * Returns a shared pointer to "scalar value in set" requirement,
     * forwarding the parameters to the constructor.
     */
    static typename ValReq<ValT, ValOpsT>::SP shared(_RawVal rawVal, const ValReqLogCfg& logCfg)
    {
        return std::make_shared<ScalarValInSetReq>(std::move(rawVal), logCfg);
    }

protected:
    void _validate(const ValT& val) const override
    {
        ValHasTypeReq<ValT, ValOpsT>::_validate(val);

        auto& scalarVal = static_cast<const ScalarValT&>(val);
        const auto rawVal = ValOpsT::scalarValRawVal(scalarVal);

        if (_mSet.find(rawVal) == _mSet.end()) {
            std::ostringstream ss;

            ss << "Unexpected value ";
            internal::writeRawVal(ss, rawVal);
            ss << ": expecting " << this->_setStr() << '.';
            BT_CLOGE_APPEND_CAUSE_AND_THROW_EX(this->_logCfg(), Error, "[%s] %s",
                                               this->_locStr(val).c_str(), ss.str().c_str());
        }
    }

private:
    /*
     * Serializes the raw values of `_mSet` and returns the resulting
     * string.
     */
    std::string _setStr() const
    {
        std::ostringstream ss;

        if (_mSet.size() == 1) {
            /* Special case: direct value */
            internal::writeRawVal(ss, *_mSet.begin());
            return ss.str();
        } else if (_mSet.size() == 2) {
            /* Special case: "or" word without any comma */
            internal::writeRawVal(ss, *_mSet.begin());
            ss << " or ";
            internal::writeRawVal(ss, *std::next(_mSet.begin()));
            return ss.str();
        }

        /* Enumeration with at least one comma */
        const auto lastIt = std::prev(_mSet.end());

        for (auto it = _mSet.begin(); it != lastIt; ++it) {
            internal::writeRawVal(ss, *it);
            ss << ", ";
        }

        ss << "or ";
        internal::writeRawVal(ss, *lastIt);
        return ss.str();
    }

    /* Set of expected raw values */
    Set _mSet;
};

/*
 * "String value matches regular expression" requirement.
 *
 * An instance of this class validates that, given a value V:
 *
 * • V is a string value.
 * • The raw value of V matches a given regular expression.
 */
template <typename ValT, typename ValOpsT>
class StrValMatchesRegexReq : public ValHasTypeReq<ValT, ValOpsT>
{
public:
    /*
     * Builds a "string value matches regular expression" requirement:
     * _validate() validates that the raw value of the string value
     * matches the regular expression `regex`.
     *
     * When the value requirement logs or appends a cause to the error
     * of the current thread, it uses `logCfg` to format the text
     * location part of the message.
     */
    explicit StrValMatchesRegexReq(std::regex regex, const ValReqLogCfg& logCfg) :
        ValHasTypeReq<ValT, ValOpsT> {ValType::STR, logCfg}, _mRegex {std::move(regex)}
    {
    }

    /*
     * Builds a "string value matches regular expression" requirement:
     * _validate() validates that the raw value of the string value
     * matches the regular expression `regex` (ECMAScript engine).
     *
     * When the value requirement logs or appends a cause to the error
     * of the current thread, it uses `logCfg` to format the text
     * location part of the message.
     */
    explicit StrValMatchesRegexReq(const char * const regex, const ValReqLogCfg& logCfg) :
        ValHasTypeReq<ValT, ValOpsT> {ValType::STR, logCfg}, _mRegex {regex,
                                                                      std::regex::ECMAScript |
                                                                          std::regex::optimize}
    {
    }

    /*
     * Returns a shared pointer to "string value matches regular
     * expression" requirement, forwarding the parameters to the
     * constructor.
     */
    static typename ValReq<ValT, ValOpsT>::SP shared(std::regex regex, const ValReqLogCfg& logCfg)
    {
        return std::make_shared<StrValMatchesRegexReq>(std::move(regex), logCfg);
    }

    /*
     * Returns a shared pointer to "string value matches regular
     * expression" requirement, forwarding the parameters to the
     * constructor.
     */
    static typename ValReq<ValT, ValOpsT>::SP shared(const char * const regex,
                                                     const ValReqLogCfg& logCfg)
    {
        std::make_shared<StrValMatchesRegexReq>(regex, logCfg);
    }

protected:
    void _validate(const ValT& val) const override
    {
        ValHasTypeReq<ValT, ValOpsT>::_validate(val);

        const auto& rawVal = ValOpsT::scalarValRawVal(ValOpsT::asStr(val));

        if (!std::regex_match(rawVal, _mRegex)) {
            BT_CLOGE_APPEND_CAUSE_AND_THROW_EX(this->_logCfg(), Error, "[%s] Invalid string `%s`.",
                                               this->_locStr(val).c_str(), rawVal.c_str());
        }
    }

private:
    std::regex _mRegex;
};

/*
 * Array value requirement.
 *
 * An instance of this class validates that, given a value V:
 *
 * • V is an array value.
 * • The size of V is within a given range.
 * • All the elements of V satisfy a given value requirement.
 */
template <typename ValT, typename ValOpsT>
class ArrayValReq : public ValHasTypeReq<ValT, ValOpsT>
{
public:
    using SP = typename ValReq<ValT, ValOpsT>::SP;

    /*
     * Builds an array value requirement: _validate() validates that,
     * for a given array value V:
     *
     * • If `minSize` is set: the size of V is greater than or equal to
     *   `*minSize`.
     *
     * • If `maxSize` is set: the size of V is less than or equal to
     *   `*maxSize`.
     *
     * • If `elemValReq` is set: all the elements of V satisfy
     *   `*elemValReq`.
     *
     * When the value requirement logs or appends a cause to the error
     * of the current thread, it uses `logCfg` to format the text
     * location part of the message.
     */
    explicit ArrayValReq(const nonstd::optional<std::size_t>& minSize,
                         const nonstd::optional<std::size_t>& maxSize, SP elemValReq,
                         const ValReqLogCfg& logCfg) :
        ValHasTypeReq<ValT, ValOpsT> {ValType::ARRAY, logCfg},
        _mMinSize {minSize ? *minSize : std::numeric_limits<std::size_t>::min()},
        _mMaxSize {maxSize ? *maxSize : std::numeric_limits<std::size_t>::max()},
        _mElemValReq {std::move(elemValReq)}
    {
    }

    /*
     * Builds an array value requirement: _validate() validates that,
     * for a given array value V:
     *
     * • If `minSize` is set: the size of V is greater than or equal to
     *   `*minSize`.
     *
     * • If `maxSize` is set: the size of V is less than or equal to
     *   `*maxSize`.
     *
     * When the value requirement logs or appends a cause to the error
     * of the current thread, it uses `logCfg` to format the text
     * location part of the message.
     */
    explicit ArrayValReq(const nonstd::optional<std::size_t>& minSize,
                         const nonstd::optional<std::size_t>& maxSize, const ValReqLogCfg& logCfg) :
        ArrayValReq {minSize, maxSize, nullptr, logCfg}
    {
    }

    /*
     * Builds an array value requirement: _validate() validates that,
     * for a given array value V:
     *
     * • The size of V is exactly `exactSize`.
     *
     * • If `elemValReq` is set: all the elements of V satisfy
     *   `*elemValReq`.
     *
     * When the value requirement logs or appends a cause to the error
     * of the current thread, it uses `logCfg` to format the text
     * location part of the message.
     */
    explicit ArrayValReq(const std::size_t exactSize, SP elemValReq, const ValReqLogCfg& logCfg) :
        ArrayValReq {exactSize, exactSize, std::move(elemValReq), logCfg}
    {
    }

    /*
     * Builds an array value requirement: _validate() validates that,
     * for a given array value V:
     *
     * • The size of V is exactly `exactSize`.
     *
     * When the value requirement logs or appends a cause to the error
     * of the current thread, it uses `logCfg` to format the text
     * location part of the message.
     */
    explicit ArrayValReq(const std::size_t exactSize, const ValReqLogCfg& logCfg) :
        ArrayValReq {exactSize, exactSize, nullptr, logCfg}
    {
    }

    /*
     * Builds an array value requirement: _validate() validates that all
     * the elements of a given array value satisfy `*elemValReq`, if
     * set.
     *
     * When the value requirement logs or appends a cause to the error
     * of the current thread, it uses `logCfg` to format the text
     * location part of the message.
     */
    explicit ArrayValReq(SP elemValReq, const ValReqLogCfg& logCfg) :
        ArrayValReq {nonstd::nullopt, nonstd::nullopt, std::move(elemValReq), logCfg}
    {
    }

    /*
     * Builds an array value requirement: _validate() validates that
     * a given value is an array value.
     *
     * When the value requirement logs or appends a cause to the error
     * of the current thread, it uses `logCfg` to format the text
     * location part of the message.
     */
    explicit ArrayValReq(const ValReqLogCfg& logCfg) :
        ArrayValReq {nonstd::nullopt, nonstd::nullopt, logCfg}
    {
    }

    /*
     * Returns a shared pointer to array value requirement, forwarding
     * the parameters to the constructor.
     */
    static SP shared(const nonstd::optional<std::size_t>& minSize,
                     const nonstd::optional<std::size_t>& maxSize, SP elemValReq,
                     const ValReqLogCfg& logCfg)
    {
        return std::make_shared<ArrayValReq>(minSize, maxSize, std::move(elemValReq), logCfg);
    }

    /*
     * Returns a shared pointer to array value requirement, forwarding
     * the parameters to the constructor.
     */
    static SP shared(const nonstd::optional<std::size_t>& minSize,
                     const nonstd::optional<std::size_t>& maxSize, const ValReqLogCfg& logCfg)
    {
        return std::make_shared<ArrayValReq>(minSize, maxSize, logCfg);
    }

    /*
     * Returns a shared pointer to array value requirement, forwarding
     * the parameters to the constructor.
     */
    static SP shared(const std::size_t exactSize, SP elemValReq, const ValReqLogCfg& logCfg)
    {
        return std::make_shared<ArrayValReq>(exactSize, std::move(elemValReq), logCfg);
    }

    /*
     * Returns a shared pointer to array value requirement, forwarding
     * the parameters to the constructor.
     */
    static SP shared(const std::size_t exactSize, const ValReqLogCfg& logCfg)
    {
        return std::make_shared<ArrayValReq>(exactSize, logCfg);
    }

    /*
     * Returns a shared pointer to array value requirement, forwarding
     * the parameters to the constructor.
     */
    static SP shared(SP elemValReq, const ValReqLogCfg& logCfg)
    {
        return std::make_shared<ArrayValReq>(std::move(elemValReq), logCfg);
    }

    /*
     * Returns a shared pointer to array value requirement, forwarding
     * the parameter to the constructor.
     */
    static SP shared(const ValReqLogCfg& logCfg)
    {
        return std::make_shared<ArrayValReq>(logCfg);
    }

protected:
    void _validate(const ValT& val) const override
    {
        ValHasTypeReq<ValT, ValOpsT>::_validate(val);

        auto& arrayVal = ValOpsT::asArray(val);
        const auto size = ValOpsT::arrayValSize(arrayVal);

        if (size < _mMinSize) {
            BT_CLOGE_APPEND_CAUSE_AND_THROW_EX(
                this->_logCfg(), Error,
                "[%s] Size of array (%zu) is too small: expecting at least %zu elements.",
                this->_locStr(val).c_str(), size, _mMinSize);
        }

        if (size > _mMaxSize) {
            BT_CLOGE_APPEND_CAUSE_AND_THROW_EX(
                this->_logCfg(), Error,
                "[%s] Size of array (%zu) is too large: expecting at most %zu elements.",
                this->_locStr(val).c_str(), size, _mMaxSize);
        }

        if (_mElemValReq) {
            for (std::size_t i = 0; i < size; ++i) {
                auto& elemVal = ValOpsT::arrayValElem(arrayVal, i);

                try {
                    _mElemValReq->validate(elemVal);
                } catch (const Error&) {
                    BT_CLOGE_APPEND_CAUSE_AND_RETHROW_EX(this->_logCfg(),
                                                         "[%s] Invalid array element #%zu.",
                                                         this->_locStr(elemVal).c_str(), i + 1);
                }
            }
        }
    }

private:
    std::size_t _mMinSize;
    std::size_t _mMaxSize;
    SP _mElemValReq;
};

/*
 * Object value property requirement.
 *
 * An instance of this class contains the requirements of a single
 * object value property, that is:
 *
 * • Whether or not it's required.
 * • The requirement of the value of the property.
 */
template <typename ValT, typename ValOpsT>
class ObjValPropReq final
{
public:
    /*
     * Builds an object value property requirement, required if
     * `isRequired` is true: if `valReq` is set, then validate()
     * validates that a value satisfies `*valReq`.
     *
     * Not `explicit` to make the construction of `ObjValReq` lighter.
     */
    ObjValPropReq(typename ValReq<ValT, ValOpsT>::SP valReq = nullptr,
                  const bool isRequired = false) :
        _mIsRequired {isRequired},
        _mValReq {std::move(valReq)}
    {
    }

    /* Default copy/move operations */
    ObjValPropReq(const ObjValPropReq&) = default;
    ObjValPropReq(ObjValPropReq&&) = default;
    ObjValPropReq& operator=(const ObjValPropReq&) = default;
    ObjValPropReq& operator=(ObjValPropReq&&) = default;

    /*
     * Whether or not the property is required.
     */
    bool isRequired() const noexcept
    {
        return _mIsRequired;
    }

    /*
     * Validates that `val` satisfies this requirement.
     */
    void validate(const ValT& val) const
    {
        if (_mValReq) {
            _mValReq->validate(val);
        }
    }

private:
    /* Whether or not this property is required */
    bool _mIsRequired = false;

    /* Requirement of the value */
    typename ValReq<ValT, ValOpsT>::SP _mValReq;
};

/*
 * Object value requirement.
 *
 * An instance of this class validates that, given a value V:
 *
 * • V is an object value.
 *
 * • The properties of V satisfy a given set of object value property
 *   requirements.
 */
template <typename ValT, typename ValOpsT>
class ObjValReq : public ValHasTypeReq<ValT, ValOpsT>
{
public:
    /* Map of property name to property requirement */
    using PropReqs = std::unordered_map<std::string, ObjValPropReq<ValT, ValOpsT>>;

    /* Single entry (pair) of `PropReqs` */
    using PropReqsEntry = typename PropReqs::value_type;

public:
    /*
     * Builds an object value requirement: _validate() validates that,
     * for a given object value V:
     *
     * • If `allowUnknownProps` is false, then V has no value of which
     *   the key is not an element of the keys of `propReqs`.
     *
     * • For each property requirement PR having the key K in
     *   `propReqs`: if `PR.isRequired()`, then a value having the key K
     *   exists in V.
     *
     * • For each value VV having the key K in V: VV satisfies the value
     *   requirement, if any, of `propReqs[K]`.
     *
     * When the value requirement logs or appends a cause to the error
     * of the current thread, it uses `logCfg` to format the text
     * location part of the message.
     */
    explicit ObjValReq(PropReqs propReqs, const bool allowUnknownProps,
                       const ValReqLogCfg& logCfg) :
        ValHasTypeReq<ValT, ValOpsT> {ValType::OBJ, logCfg},
        _mPropReqs {std::move(propReqs)}, _mAllowUnknownProps {allowUnknownProps}
    {
    }

    /*
     * Builds an object value requirement: _validate() validates that,
     * for a given object value V:
     *
     * • V has no value of which the key is not an element of the keys
     *   of `propReqs`.
     *
     * • For each property requirement PR having the key K in
     *   `propReqs`: if `PR.isRequired()`, then a value having the key K
     *   exists in V.
     *
     * • For each value VV having the key K in V: VV satisfies the value
     *   requirement, if any, of `propReqs[K]`.
     *
     * When the value requirement logs or appends a cause to the error
     * of the current thread, it uses `logCfg` to format the text
     * location part of the message.
     */
    explicit ObjValReq(PropReqs propReqs, const ValReqLogCfg& logCfg) :
        ObjValReq {std::move(propReqs), false, logCfg}
    {
    }

    /*
     * Returns a shared pointer to object value requirement, forwarding
     * the parameters to the constructor.
     */
    static typename ValReq<ValT, ValOpsT>::SP
    shared(PropReqs propReqs, const bool allowUnknownProps, const ValReqLogCfg& logCfg)
    {
        return std::make_shared<ObjValReq>(std::move(propReqs), allowUnknownProps, logCfg);
    }

    /*
     * Returns a shared pointer to object value requirement, forwarding
     * the parameters to the constructor.
     */
    static typename ValReq<ValT, ValOpsT>::SP shared(PropReqs propReqs, const ValReqLogCfg& logCfg)
    {
        return std::make_shared<ObjValReq>(std::move(propReqs), logCfg);
    }

protected:
    void _validate(const ValT& val) const override
    {
        ValHasTypeReq<ValT, ValOpsT>::_validate(val);

        auto& objVal = ValOpsT::asObj(val);
        const auto objValTypeStr = ValOpsT::typeStr(ValType::OBJ);

        for (auto& keyPropReqPair : _mPropReqs) {
            auto& key = keyPropReqPair.first;

            if (keyPropReqPair.second.isRequired() && !ValOpsT::objValVal(objVal, key)) {
                BT_CLOGE_APPEND_CAUSE_AND_THROW_EX(this->_logCfg(), Error,
                                                   "[%s] Missing mandatory %s %s `%s`.",
                                                   this->_locStr(objVal).c_str(), objValTypeStr,
                                                   ValOpsT::objValPropName, key.c_str());
            }
        }

        for (auto it = ValOpsT::objValBegin(objVal); it != ValOpsT::objValEnd(objVal); ++it) {
            auto& key = ValOpsT::objValItKey(it);
            auto& propVal = ValOpsT::objValItVal(it);
            const auto keyPropReqPairIt = _mPropReqs.find(key);

            if (keyPropReqPairIt == _mPropReqs.end()) {
                /* No property requirement found */
                if (_mAllowUnknownProps) {
                    continue;
                } else {
                    BT_CLOGE_APPEND_CAUSE_AND_THROW_EX(
                        this->_logCfg(), Error, "[%s] Unknown %s %s `%s`.",
                        this->_locStr(propVal).c_str(), objValTypeStr, ValOpsT::objValPropName,
                        key.c_str());
                }
            }

            try {
                keyPropReqPairIt->second.validate(propVal);
            } catch (const Error&) {
                BT_CLOGE_APPEND_CAUSE_AND_RETHROW_EX(this->_logCfg(), "[%s] Invalid %s %s `%s`.",
                                                     this->_locStr(propVal).c_str(), objValTypeStr,
                                                     ValOpsT::objValPropName, key.c_str());
            }
        }
    }

private:
    PropReqs _mPropReqs;
    bool _mAllowUnknownProps;
};

} /* namespace bt2_common */

#endif /* BABELTRACE_CPP_COMMON_VAL_REQ_HPP */
