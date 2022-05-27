/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _CTF_SRC_METADATA_JSON_VAL_REQ_HPP
#define _CTF_SRC_METADATA_JSON_VAL_REQ_HPP

#include <unordered_map>
#include <memory>

#include "cpp-common/text-parse-error.hpp"
#include "cpp-common/json-val.hpp"
#include "cpp-common/json-val-req.hpp"

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
class Ctf2JsonIntRangeValReq final : public bt2_common::JsonArrayValReq
{
public:
    explicit Ctf2JsonIntRangeValReq() : bt2_common::JsonArrayValReq {2, JsonIntValReqT::shared()}
    {
    }

    static SP shared()
    {
        return std::make_shared<Ctf2JsonIntRangeValReq>();
    }

private:
    template <typename LowerT, typename UpperT>
    static void _throwLowerGtUpper(const LowerT lower, const UpperT upper,
                                   const bt2_common::TextLoc& loc)
    {
        std::ostringstream ss;

        ss << lower << " is greater than " << upper << '.';
        throw bt2_common::TextParseError {ss.str(), loc};
    }

    void _validate(const bt2_common::JsonVal& jsonVal) const override
    {
        try {
            bt2_common::JsonArrayValReq::_validate(jsonVal);

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
                        this->_throwLowerGtUpper(uLower, uUpper, jsonVal.loc());
                    }
                } else {
                    const auto sUpper = *upperJsonVal.asSInt();

                    if (sUpper < 0) {
                        /* ID 4 */
                        this->_throwLowerGtUpper(uLower, sUpper, jsonVal.loc());
                    }

                    if (static_cast<unsigned long long>(sUpper) < uLower) {
                        /* ID 3 */
                        this->_throwLowerGtUpper(uLower, sUpper, jsonVal.loc());
                    }
                }
            } else {
                const auto sLower = *lowerJsonVal.asSInt();

                if (upperJsonVal.isSInt()) {
                    const auto sUpper = *upperJsonVal.asSInt();

                    if (sUpper < sLower) {
                        /* ID 2 */
                        this->_throwLowerGtUpper(sLower, sUpper, jsonVal.loc());
                    }
                } else if (sLower >= 0) {
                    const auto uUpper = *upperJsonVal.asUInt();

                    if (uUpper < static_cast<unsigned long long>(sLower)) {
                        /* ID 5 */
                        this->_throwLowerGtUpper(sLower, uUpper, jsonVal.loc());
                    }
                }
            }
        } catch (bt2_common::TextParseError& exc) {
            exc.appendErrorMsg("Invalid integer range:", jsonVal.loc());
            throw;
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
class Ctf2JsonIntRangeSetValReqBase final : public bt2_common::JsonArrayValReq
{
public:
    explicit Ctf2JsonIntRangeSetValReqBase() :
        bt2_common::JsonArrayValReq {1, nonstd::nullopt,
                                     Ctf2JsonIntRangeValReq<JsonIntValReqT>::shared()}
    {
    }

    static SP shared()
    {
        return std::make_shared<Ctf2JsonIntRangeSetValReqBase>();
    }

private:
    void _validate(const bt2_common::JsonVal& jsonVal) const override
    {
        try {
            bt2_common::JsonArrayValReq::_validate(jsonVal);
        } catch (bt2_common::TextParseError& exc) {
            exc.appendErrorMsg("Invalid integer range set:", jsonVal.loc());
            throw;
        }
    }
};

/*
 * CTF 2 JSON unsigned integer range set value requirement.
 */
using Ctf2JsonUIntRangeSetValReq = Ctf2JsonIntRangeSetValReqBase<bt2_common::JsonUIntValReq>;

/*
 * CTF 2 JSON signed integer range set value requirement.
 */
using Ctf2JsonSIntRangeSetValReq = Ctf2JsonIntRangeSetValReqBase<bt2_common::JsonSIntValReq>;

/*
 * CTF 2 JSON integer range set value requirement.
 */
using Ctf2JsonIntRangeSetValReq = Ctf2JsonIntRangeSetValReqBase<bt2_common::JsonAnyIntValReq>;

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
class Ctf2JsonAnyFragmentValReq : public bt2_common::JsonValReq
{
public:
    explicit Ctf2JsonAnyFragmentValReq();
    ~Ctf2JsonAnyFragmentValReq();

private:
    void _validate(const bt2_common::JsonVal& jsonVal) const override;

    /* Pointer to implementation */
    std::unique_ptr<const internal::Ctf2JsonAnyFragmentValReqImpl> _mImpl;
};

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_JSON_VAL_REQ_HPP */
