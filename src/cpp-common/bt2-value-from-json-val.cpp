/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include "bt2-value-from-json-val.hpp"

#include "common/assert.h"

namespace bt2_common {

/*
 * Within an instance of this converter, `_mCurBt2Val` is always the
 * last converted value.
 *
 * Therefore, with a visit() method, to convert some JSON value
 * `jsonVal`, make `jsonVal` accept the same visitor, and then use
 * `_mCurBt2Val`.
 *
 * At the end of a visit, use bt2Val() to get the root shared
 * Babeltrace 2 value.
 */
class Bt2ValueFromJsonValConverter final : public JsonValVisitor
{
public:
    /*
     * Initial value of `_mCurBt2Val` is a shared null value because
     * `bt2::Value::Shared` has no default constructor and it's more
     * straightforward that way than having
     * `nonstd::optional<bt2::Value::Shared>`.
     *
     * This initial shared null value is never used.
     */
    explicit Bt2ValueFromJsonValConverter() : _mCurBt2Val {bt2::NullValue {}.shared()}
    {
    }

    void visit(const JsonNullVal& jsonVal) override
    {
        _mCurBt2Val = bt2::NullValue {}.shared();
    }

    void visit(const JsonBoolVal& jsonVal) override
    {
        this->_visitScalarVal(jsonVal);
    }

    void visit(const JsonSIntVal& jsonVal) override
    {
        /* Explicit `long long` to `std::int64_t` */
        this->_visitScalarVal<std::int64_t>(jsonVal);
    }

    void visit(const JsonUIntVal& jsonVal) override
    {
        /* Explicit `unsigned long long` to `std::uint64_t` */
        this->_visitScalarVal<std::uint64_t>(jsonVal);
    }

    void visit(const JsonRealVal& jsonVal) override
    {
        this->_visitScalarVal(jsonVal);
    }

    void visit(const JsonStrVal& jsonVal) override
    {
        this->_visitScalarVal(jsonVal);
    }

    void visit(const JsonArrayVal& jsonVal) override
    {
        /*
         * Create an empty Babeltrace 2 array value, fill it with
         * converted values, and set it as the current value.
         */
        auto bt2ArrayVal = bt2::ArrayValue::create();

        for (auto& jsonValElem : jsonVal) {
            jsonValElem->accept(*this);
            bt2ArrayVal->append(*_mCurBt2Val);
        }

        _mCurBt2Val = bt2ArrayVal;
    }

    void visit(const JsonObjVal& jsonVal) override
    {
        /*
         * Create an empty Babeltrace 2 map value, fill it with
         * converted values, and set it as the current value.
         */
        auto bt2MapVal = bt2::MapValue::create();

        for (auto& keyJsonValPair : jsonVal) {
            keyJsonValPair.second->accept(*this);
            bt2MapVal->insert(keyJsonValPair.first, *_mCurBt2Val);
        }

        _mCurBt2Val = bt2MapVal;
    }

    bt2::Value::Shared bt2Val() noexcept
    {
        return _mCurBt2Val;
    }

private:
    /*
     * Sets `_mCurBt2Val` to a new shared Babeltrace 2 value having the
     * raw value `*jsonVal` of type `ValT`.
     */
    template <typename JsonValT, typename ValT = typename JsonValT::Val>
    void _visitScalarVal(const JsonValT& jsonVal)
    {
        _mCurBt2Val = bt2::createValue(static_cast<ValT>(*jsonVal));
    }

    template <typename ValT, typename JsonValT>
    void _visitScalarVal(const JsonValT& jsonVal)
    {
        this->_visitScalarVal<JsonValT, ValT>(jsonVal);
    }

private:
    bt2::Value::Shared _mCurBt2Val;
};

bt2::Value::Shared bt2ValueFromJsonVal(const JsonVal& jsonVal)
{
    Bt2ValueFromJsonValConverter converter;

    jsonVal.accept(converter);
    return converter.bt2Val();
}

} /* namespace bt2_common */
