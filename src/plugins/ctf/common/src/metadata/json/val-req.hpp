/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _CTF_SRC_METADATA_JSON_VAL_REQ_HPP
#define _CTF_SRC_METADATA_JSON_VAL_REQ_HPP

#include <memory>

#include "cpp-common/bt2c/exc.hpp"
#include "cpp-common/bt2c/json-val-req.hpp"
#include "cpp-common/bt2c/json-val.hpp"
#include "cpp-common/bt2c/text-loc-str.hpp"

namespace ctf {
namespace src {

/*
 * CTF 2 JSON integer range value requirement.
 *
 * An instance of this class validates that a given JSON value is
 * a CTF 2 integer range, both contained values satisfying
 * an instance of `JsonIntValReqT`.
 */
template <typename JsonIntValReqT>
class Ctf2JsonIntRangeValReq final : public bt2c::JsonArrayValReq
{
public:
    explicit Ctf2JsonIntRangeValReq(const bt2c::ValReqLogCfg& logCfg) :
        bt2c::JsonArrayValReq {2, JsonIntValReqT::shared(logCfg), logCfg}
    {
    }

    explicit Ctf2JsonIntRangeValReq(const bt2c::Logger& parentLogger,
                                    const bt2c::TextLocStrFmt textLocStrFmt) :
        Ctf2JsonIntRangeValReq {bt2c::ValReqLogCfg {parentLogger, textLocStrFmt}}
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<Ctf2JsonIntRangeValReq>(logCfg);
    }

    static SP shared(const bt2c::Logger& parentLogger, const bt2c::TextLocStrFmt textLocStrFmt)
    {
        return std::make_shared<Ctf2JsonIntRangeValReq>(parentLogger, textLocStrFmt);
    }

private:
    template <typename LowerT, typename UpperT>
    void _throwLowerGtUpper(const LowerT lower, const UpperT upper,
                            const bt2c::JsonVal& jsonVal) const
    {
        BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), bt2c::Error,
                                               "[{}] {} is greater than {}.",
                                               this->_locStr(jsonVal), lower, upper);
    }

    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            bt2c::JsonArrayValReq::_validate(jsonVal);

            /*
             * Here's the truth table:
             *
             * ╔════╦════════════╦════════════╦═══════════════════════════╗
             * ║ ID ║ Lower      ║ Upper      ║ Valid?                    ║
             * ╠════╬════════════╬════════════╬═══════════════════════════╣
             * ║ 1  ║ Unsigned   ║ Unsigned   ║ Lower < upper             ║
             * ║ 2  ║ Signed     ║ Signed     ║ Lower < upper             ║
             * ║ 3  ║ Unsigned   ║ Signed ≥ 0 ║ Lower < upper as unsigned ║
             * ║ 4  ║ Unsigned   ║ Signed < 0 ║ No                        ║
             * ║ 5  ║ Signed ≥ 0 ║ Unsigned   ║ Lower as unsigned < upper ║
             * ║ 6  ║ Signed < 0 ║ Unsigned   ║ Yes                       ║
             * ╚════╩════════════╩════════════╩═══════════════════════════╝
             */
            auto& lowerJsonVal = jsonVal.asArray()[0];
            auto& upperJsonVal = jsonVal.asArray()[1];

            if (lowerJsonVal.isUInt()) {
                const auto uLower = *lowerJsonVal.asUInt();

                if (upperJsonVal.isUInt()) {
                    const auto uUpper = *upperJsonVal.asUInt();

                    if (uUpper < uLower) {
                        /* ID 1 */
                        this->_throwLowerGtUpper(uLower, uUpper, jsonVal);
                    }
                } else {
                    const auto sUpper = *upperJsonVal.asSInt();

                    if (sUpper < 0) {
                        /* ID 4 */
                        this->_throwLowerGtUpper(uLower, sUpper, jsonVal);
                    }

                    if (static_cast<unsigned long long>(sUpper) < uLower) {
                        /* ID 3 */
                        this->_throwLowerGtUpper(uLower, sUpper, jsonVal);
                    }
                }
            } else {
                const auto sLower = *lowerJsonVal.asSInt();

                if (upperJsonVal.isSInt()) {
                    const auto sUpper = *upperJsonVal.asSInt();

                    if (sUpper < sLower) {
                        /* ID 2 */
                        this->_throwLowerGtUpper(sLower, sUpper, jsonVal);
                    }
                } else if (sLower >= 0) {
                    const auto uUpper = *upperJsonVal.asUInt();

                    if (uUpper < static_cast<unsigned long long>(sLower)) {
                        /* ID 5 */
                        this->_throwLowerGtUpper(sLower, uUpper, jsonVal);
                    }
                }
            }
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_RETHROW_SPEC(this->_logger(), "[{}] Invalid integer range.",
                                                     this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 JSON integer range set value requirement.
 *
 * An instance of this class validates that a given JSON value is a
 * CTF 2 integer range set, each element satisfying an instance of
 * `Ctf2JsonIntRangeValReq<JsonIntValReqT>`.
 */
template <typename JsonIntValReqT>
class Ctf2JsonIntRangeSetValReqBase final : public bt2c::JsonArrayValReq
{
public:
    explicit Ctf2JsonIntRangeSetValReqBase(const bt2c::ValReqLogCfg& logCfg) :
        bt2c::JsonArrayValReq {1, bt2s::nullopt,
                               Ctf2JsonIntRangeValReq<JsonIntValReqT>::shared(logCfg), logCfg}
    {
    }

    explicit Ctf2JsonIntRangeSetValReqBase(const bt2c::Logger& parentLogger,
                                           const bt2c::TextLocStrFmt textLocStrFmt) :
        Ctf2JsonIntRangeSetValReqBase {bt2c::ValReqLogCfg {parentLogger, textLocStrFmt}}
    {
    }

    static SP shared(const bt2c::ValReqLogCfg& logCfg)
    {
        return std::make_shared<Ctf2JsonIntRangeSetValReqBase>(logCfg);
    }

    static SP shared(const bt2c::Logger& parentLogger, const bt2c::TextLocStrFmt textLocStrFmt)
    {
        return std::make_shared<Ctf2JsonIntRangeSetValReqBase>(parentLogger, textLocStrFmt);
    }

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override
    {
        try {
            bt2c::JsonArrayValReq::_validate(jsonVal);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_APPEND_CAUSE_AND_RETHROW_SPEC(
                this->_logger(), "[{}] Invalid integer range set.", this->_locStr(jsonVal));
        }
    }
};

/*
 * CTF 2 JSON unsigned integer range set value requirement.
 */
using Ctf2JsonUIntRangeSetValReq = Ctf2JsonIntRangeSetValReqBase<bt2c::JsonUIntValReq>;

/*
 * CTF 2 JSON signed integer range set value requirement.
 */
using Ctf2JsonSIntRangeSetValReq = Ctf2JsonIntRangeSetValReqBase<bt2c::JsonSIntValReq>;

/*
 * CTF 2 JSON integer range set value requirement.
 */
using Ctf2JsonIntRangeSetValReq = Ctf2JsonIntRangeSetValReqBase<bt2c::JsonAnyIntValReq>;

namespace internal {

class Ctf2JsonAnyFragmentValReqImpl;

}

/*
 * CTF 2 JSON (any) fragment value requirement.
 *
 * This value requirement doesn't validate:
 *
 * • The dependencies of the dependent (dynamic-length, optional, and
 *   variant) field classes.
 *
 *   In other words, it validates the form of field locations, but
 *   doesn't use them to find dependencies because there's not enough
 *   context.
 *
 * • Overlaps of integer ranges between variant field class options.
 *
 */
class Ctf2JsonAnyFragmentValReq : public bt2c::JsonValReq
{
public:
    explicit Ctf2JsonAnyFragmentValReq(const bt2c::Logger& parentLogger,
                                       bt2c::TextLocStrFmt textLocStrFmt);
    ~Ctf2JsonAnyFragmentValReq();

private:
    void _validate(const bt2c::JsonVal& jsonVal) const override;

    /* Pointer to implementation */
    std::unique_ptr<const internal::Ctf2JsonAnyFragmentValReqImpl> _mImpl;
};

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_JSON_VAL_REQ_HPP */
