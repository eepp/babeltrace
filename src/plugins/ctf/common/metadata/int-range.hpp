/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2022-2024 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef CTF_COMMON_METADATA_INT_RANGE_HPP
#define CTF_COMMON_METADATA_INT_RANGE_HPP

#include "common/assert.h"

namespace ctf {

/*
 * An integer range is a simple pair of lower and upper values of type
 * `ValT`, both included in the range.
 */
template <typename ValT>
class IntRange final
{
public:
    /* Type of the lower and upper values */
    using Val = ValT;

public:
    /*
     * Builds an integer range [`lower`, `upper`].
     *
     * `upper` must be greater than or equal to `lower`.
     */
    explicit IntRange(const ValT lower, const ValT upper) : _mLower {lower}, _mUpper {upper}
    {
        BT_ASSERT_DBG(lower <= upper);
    }

    /*
     * Lower bound of this integer range.
     */
    ValT lower() const noexcept
    {
        return _mLower;
    }

    /*
     * Upper bound of this integer range.
     */
    ValT upper() const noexcept
    {
        return _mUpper;
    }

    /*
     * Returns whether or not this integer range contains the value
     * `val`.
     */
    bool contains(const ValT val) const noexcept
    {
        return val >= _mLower && val <= _mUpper;
    }

    /*
     * Returns whether or not the integer range `range` intersects with
     * this integer range, that is, `range` and this integer range share
     * at least one integer value.
     */
    bool intersects(const IntRange& other) const noexcept
    {
        return _mLower <= other.upper() && other.lower() <= _mUpper;
    }

    bool operator==(const IntRange& other) const noexcept
    {
        return other.lower() == _mLower && other.upper() == _mUpper;
    }

    bool operator!=(const IntRange& other) const noexcept
    {
        return !(*this == other);
    }

    bool operator<(const IntRange& other) const noexcept
    {
        if (_mLower < other._mLower) {
            return true;
        }

        if (other._mLower < _mLower) {
            return false;
        }

        if (_mUpper < other._mUpper) {
            return true;
        }

        return false;
    }

private:
    ValT _mLower;
    ValT _mUpper;
};

/* Convenient aliases */
using UIntRange = IntRange<unsigned long long>;
using SIntRange = IntRange<long long>;

} /* namespace ctf */

#endif /* CTF_COMMON_METADATA_INT_RANGE_HPP */
