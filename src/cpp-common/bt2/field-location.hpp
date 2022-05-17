/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_BT2_FIELD_LOCATION_HPP
#define BABELTRACE_CPP_COMMON_BT2_FIELD_LOCATION_HPP

#include <cstdint>
#include <babeltrace2/babeltrace.h>

#include "common/assert.h"
#include "cpp-common/string_view.hpp"
#include "internal/borrowed-obj.hpp"
#include "internal/shared-obj.hpp"
#include "common-iter.hpp"

namespace bt2 {
namespace internal {

struct FieldLocationRefFuncs final
{
    static void get(const bt_field_location * const libObjPtr)
    {
        bt_field_location_get_ref(libObjPtr);
    }

    static void put(const bt_field_location * const libObjPtr)
    {
        bt_field_location_get_ref(libObjPtr);
    }
};

} /* namespace internal */

class ConstFieldLocation : public internal::BorrowedObj<const bt_field_location>
{
private:
    using typename internal::BorrowedObj<const bt_field_location>::_ThisBorrowedObj;

public:
    using Shared = internal::SharedObj<ConstFieldLocation, const bt_field_location,
                                       internal::FieldLocationRefFuncs>;

    using Iterator = CommonIterator<ConstFieldLocation, bpstd::string_view>;

    enum class Scope
    {
        PACKET_CONTEXT = BT_FIELD_LOCATION_SCOPE_PACKET_CONTEXT,
        EVENT_COMMON_CONTEXT = BT_FIELD_LOCATION_SCOPE_EVENT_COMMON_CONTEXT,
        EVENT_SPECIFIC_CONTEXT = BT_FIELD_LOCATION_SCOPE_EVENT_SPECIFIC_CONTEXT,
        EVENT_PAYLOAD = BT_FIELD_LOCATION_SCOPE_EVENT_PAYLOAD,
    };

    explicit ConstFieldLocation(const bt_field_location * const libObjPtr) noexcept :
        _ThisBorrowedObj {libObjPtr}
    {
    }

    ConstFieldLocation(const ConstFieldLocation& obj) noexcept : _ThisBorrowedObj {obj}
    {
    }

    ConstFieldLocation& operator=(const ConstFieldLocation& obj) noexcept
    {
        _ThisBorrowedObj::operator=(obj);
        return *this;
    }

    Scope rootScope() const noexcept
    {
        return static_cast<Scope>(bt_field_location_get_root_scope(this->libObjPtr()));
    }

    std::uint64_t size() const noexcept
    {
        return bt_field_location_get_item_count(this->libObjPtr());
    }

    bpstd::string_view operator[](const std::uint64_t index) const noexcept
    {
        return bt_field_location_get_item_by_index(this->libObjPtr(), index);
    }

    Iterator begin() const noexcept
    {
        return Iterator {*this, 0};
    }

    Iterator end() const noexcept
    {
        return Iterator {*this, this->size()};
    }

    Shared shared() const noexcept
    {
        return Shared::createWithRef(*this);
    }
};

} /* namespace bt2 */

#endif /* BABELTRACE_CPP_COMMON_BT2_FIELD_LOCATION_HPP */
