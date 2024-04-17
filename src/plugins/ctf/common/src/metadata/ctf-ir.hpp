/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2022 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef _CTF_SRC_METADATA_CTF_IR_HPP
#define _CTF_SRC_METADATA_CTF_IR_HPP

#include <cstdlib>
#include <unordered_set>
#include <vector>

#include "cpp-common/bt2/trace-ir.hpp"
#include "cpp-common/bt2c/observable.hpp"

#include "../../metadata/ctf-ir.hpp"

namespace ctf {
namespace src {

/*
 * This is the CTF IR API specific to source component classes.
 *
 * This API defines a few internal user mixins for our needs to reuse
 * the common `ctf::ir` API.
 */

/*
 * A field class deep type is a superset of `ctf::ir::FcType` which
 * contains additional, static information about the field class.
 *
 * For fixed-length and variable-length field classes, this deep type
 * incorporates important decoding information, for example:
 *
 * • Byte order.
 * • Length, if it's a "standard" fixed-length bit array.
 * • Integer signedness.
 * • Whether or not the field has a role.
 * • Whether or not the value of field has to be saved.
 *
 * The purpose of the deep type of a field class is having a single
 * `switch` statement in the field reading method of some data stream
 * decoder to select its next state and make it easier/possible for the
 * compiler to optimize as most common decisions are encoded in there.
 *
 * For example, if it's known that the next field to read is a
 * little-endian, byte-aligned 32-bit unsigned integer field of which
 * the data stream decoder needs to save the value, then its deep type
 * is `FcDeepType::FIXED_LEN_UINT_BA_32_LE_SAVE_VAL`, which means the
 * decoder will jump to a specific, corresponding reading method
 * directly. The latter method can do exactly what's needed to perform
 * such a field reading operation efficiently (using
 * bt2c::readFixedLenIntLe()) and save its value unconditionally.
 *
 * The enumerators below use the following common parts:
 *
 * `BE`:
 *     Big-endian.
 *
 * `LE`:
 *     Little-endian.
 *
 * `BA`:
 *     Byte-aligned (alignment of at least 8 bits).
 *
 * `8`, `16`, `32`, `64`:
 *     Fixed 8-bit, 16-bit, 32-bit, or 64-bit length.
 *
 * `SAVE_VAL`:
 *     Save the value of the boolean/integer field.
 *
 * `WITH_ROLE`:
 *     Unsigned integer field with at least one role.
 *
 * `WITH_METADATA_STREAM_UUID_ROLE`:
 *     Static-length array/BLOB field with the "metadata stream UUID"
 *     role.
 */
enum FcDeepType
{
    FIXED_LEN_BIT_ARRAY_BE,
    FIXED_LEN_BIT_ARRAY_LE,
    FIXED_LEN_BIT_ARRAY_BA_8,
    FIXED_LEN_BIT_ARRAY_BA_16_LE,
    FIXED_LEN_BIT_ARRAY_BA_16_BE,
    FIXED_LEN_BIT_ARRAY_BA_32_LE,
    FIXED_LEN_BIT_ARRAY_BA_32_BE,
    FIXED_LEN_BIT_ARRAY_BA_64_LE,
    FIXED_LEN_BIT_ARRAY_BA_64_BE,
    FIXED_LEN_BOOL_BE,
    FIXED_LEN_BOOL_LE,
    FIXED_LEN_BOOL_BA_8,
    FIXED_LEN_BOOL_BA_16_LE,
    FIXED_LEN_BOOL_BA_16_BE,
    FIXED_LEN_BOOL_BA_32_LE,
    FIXED_LEN_BOOL_BA_32_BE,
    FIXED_LEN_BOOL_BA_64_LE,
    FIXED_LEN_BOOL_BA_64_BE,
    FIXED_LEN_BOOL_BE_SAVE_VAL,
    FIXED_LEN_BOOL_LE_SAVE_VAL,
    FIXED_LEN_BOOL_BA_8_SAVE_VAL,
    FIXED_LEN_BOOL_BA_16_LE_SAVE_VAL,
    FIXED_LEN_BOOL_BA_16_BE_SAVE_VAL,
    FIXED_LEN_BOOL_BA_32_LE_SAVE_VAL,
    FIXED_LEN_BOOL_BA_32_BE_SAVE_VAL,
    FIXED_LEN_BOOL_BA_64_LE_SAVE_VAL,
    FIXED_LEN_BOOL_BA_64_BE_SAVE_VAL,
    FIXED_LEN_FLOAT_32_BE,
    FIXED_LEN_FLOAT_32_LE,
    FIXED_LEN_FLOAT_64_BE,
    FIXED_LEN_FLOAT_64_LE,
    FIXED_LEN_FLOAT_BA_32_LE,
    FIXED_LEN_FLOAT_BA_32_BE,
    FIXED_LEN_FLOAT_BA_64_LE,
    FIXED_LEN_FLOAT_BA_64_BE,
    FIXED_LEN_UINT_BE,
    FIXED_LEN_UINT_LE,
    FIXED_LEN_UINT_BA_8,
    FIXED_LEN_UINT_BA_16_LE,
    FIXED_LEN_UINT_BA_16_BE,
    FIXED_LEN_UINT_BA_32_LE,
    FIXED_LEN_UINT_BA_32_BE,
    FIXED_LEN_UINT_BA_64_LE,
    FIXED_LEN_UINT_BA_64_BE,
    FIXED_LEN_UINT_BE_WITH_ROLE,
    FIXED_LEN_UINT_LE_WITH_ROLE,
    FIXED_LEN_UINT_BA_8_WITH_ROLE,
    FIXED_LEN_UINT_BA_16_LE_WITH_ROLE,
    FIXED_LEN_UINT_BA_16_BE_WITH_ROLE,
    FIXED_LEN_UINT_BA_32_LE_WITH_ROLE,
    FIXED_LEN_UINT_BA_32_BE_WITH_ROLE,
    FIXED_LEN_UINT_BA_64_LE_WITH_ROLE,
    FIXED_LEN_UINT_BA_64_BE_WITH_ROLE,
    FIXED_LEN_UINT_BE_SAVE_VAL,
    FIXED_LEN_UINT_LE_SAVE_VAL,
    FIXED_LEN_UINT_BA_8_SAVE_VAL,
    FIXED_LEN_UINT_BA_16_LE_SAVE_VAL,
    FIXED_LEN_UINT_BA_16_BE_SAVE_VAL,
    FIXED_LEN_UINT_BA_32_LE_SAVE_VAL,
    FIXED_LEN_UINT_BA_32_BE_SAVE_VAL,
    FIXED_LEN_UINT_BA_64_LE_SAVE_VAL,
    FIXED_LEN_UINT_BA_64_BE_SAVE_VAL,
    FIXED_LEN_UINT_BE_WITH_ROLE_SAVE_VAL,
    FIXED_LEN_UINT_LE_WITH_ROLE_SAVE_VAL,
    FIXED_LEN_UINT_BA_8_WITH_ROLE_SAVE_VAL,
    FIXED_LEN_UINT_BA_16_LE_WITH_ROLE_SAVE_VAL,
    FIXED_LEN_UINT_BA_16_BE_WITH_ROLE_SAVE_VAL,
    FIXED_LEN_UINT_BA_32_LE_WITH_ROLE_SAVE_VAL,
    FIXED_LEN_UINT_BA_32_BE_WITH_ROLE_SAVE_VAL,
    FIXED_LEN_UINT_BA_64_LE_WITH_ROLE_SAVE_VAL,
    FIXED_LEN_UINT_BA_64_BE_WITH_ROLE_SAVE_VAL,
    FIXED_LEN_SINT_BE,
    FIXED_LEN_SINT_LE,
    FIXED_LEN_SINT_BA_8,
    FIXED_LEN_SINT_BA_16_LE,
    FIXED_LEN_SINT_BA_16_BE,
    FIXED_LEN_SINT_BA_32_LE,
    FIXED_LEN_SINT_BA_32_BE,
    FIXED_LEN_SINT_BA_64_LE,
    FIXED_LEN_SINT_BA_64_BE,
    FIXED_LEN_SINT_BE_SAVE_VAL,
    FIXED_LEN_SINT_LE_SAVE_VAL,
    FIXED_LEN_SINT_BA_8_SAVE_VAL,
    FIXED_LEN_SINT_BA_16_LE_SAVE_VAL,
    FIXED_LEN_SINT_BA_16_BE_SAVE_VAL,
    FIXED_LEN_SINT_BA_32_LE_SAVE_VAL,
    FIXED_LEN_SINT_BA_32_BE_SAVE_VAL,
    FIXED_LEN_SINT_BA_64_LE_SAVE_VAL,
    FIXED_LEN_SINT_BA_64_BE_SAVE_VAL,
    FIXED_LEN_UENUM_BE,
    FIXED_LEN_UENUM_LE,
    FIXED_LEN_UENUM_BA_8,
    FIXED_LEN_UENUM_BA_16_LE,
    FIXED_LEN_UENUM_BA_16_BE,
    FIXED_LEN_UENUM_BA_32_LE,
    FIXED_LEN_UENUM_BA_32_BE,
    FIXED_LEN_UENUM_BA_64_LE,
    FIXED_LEN_UENUM_BA_64_BE,
    FIXED_LEN_UENUM_BE_WITH_ROLE,
    FIXED_LEN_UENUM_LE_WITH_ROLE,
    FIXED_LEN_UENUM_BA_8_WITH_ROLE,
    FIXED_LEN_UENUM_BA_16_LE_WITH_ROLE,
    FIXED_LEN_UENUM_BA_16_BE_WITH_ROLE,
    FIXED_LEN_UENUM_BA_32_LE_WITH_ROLE,
    FIXED_LEN_UENUM_BA_32_BE_WITH_ROLE,
    FIXED_LEN_UENUM_BA_64_LE_WITH_ROLE,
    FIXED_LEN_UENUM_BA_64_BE_WITH_ROLE,
    FIXED_LEN_UENUM_BE_SAVE_VAL,
    FIXED_LEN_UENUM_LE_SAVE_VAL,
    FIXED_LEN_UENUM_BA_8_SAVE_VAL,
    FIXED_LEN_UENUM_BA_16_LE_SAVE_VAL,
    FIXED_LEN_UENUM_BA_16_BE_SAVE_VAL,
    FIXED_LEN_UENUM_BA_32_LE_SAVE_VAL,
    FIXED_LEN_UENUM_BA_32_BE_SAVE_VAL,
    FIXED_LEN_UENUM_BA_64_LE_SAVE_VAL,
    FIXED_LEN_UENUM_BA_64_BE_SAVE_VAL,
    FIXED_LEN_UENUM_BE_WITH_ROLE_SAVE_VAL,
    FIXED_LEN_UENUM_LE_WITH_ROLE_SAVE_VAL,
    FIXED_LEN_UENUM_BA_8_WITH_ROLE_SAVE_VAL,
    FIXED_LEN_UENUM_BA_16_LE_WITH_ROLE_SAVE_VAL,
    FIXED_LEN_UENUM_BA_16_BE_WITH_ROLE_SAVE_VAL,
    FIXED_LEN_UENUM_BA_32_LE_WITH_ROLE_SAVE_VAL,
    FIXED_LEN_UENUM_BA_32_BE_WITH_ROLE_SAVE_VAL,
    FIXED_LEN_UENUM_BA_64_LE_WITH_ROLE_SAVE_VAL,
    FIXED_LEN_UENUM_BA_64_BE_WITH_ROLE_SAVE_VAL,
    FIXED_LEN_SENUM_BE,
    FIXED_LEN_SENUM_LE,
    FIXED_LEN_SENUM_BA_8,
    FIXED_LEN_SENUM_BA_16_LE,
    FIXED_LEN_SENUM_BA_16_BE,
    FIXED_LEN_SENUM_BA_32_LE,
    FIXED_LEN_SENUM_BA_32_BE,
    FIXED_LEN_SENUM_BA_64_LE,
    FIXED_LEN_SENUM_BA_64_BE,
    FIXED_LEN_SENUM_BE_SAVE_VAL,
    FIXED_LEN_SENUM_LE_SAVE_VAL,
    FIXED_LEN_SENUM_BA_8_SAVE_VAL,
    FIXED_LEN_SENUM_BA_16_LE_SAVE_VAL,
    FIXED_LEN_SENUM_BA_16_BE_SAVE_VAL,
    FIXED_LEN_SENUM_BA_32_LE_SAVE_VAL,
    FIXED_LEN_SENUM_BA_32_BE_SAVE_VAL,
    FIXED_LEN_SENUM_BA_64_LE_SAVE_VAL,
    FIXED_LEN_SENUM_BA_64_BE_SAVE_VAL,
    VAR_LEN_UINT,
    VAR_LEN_UINT_WITH_ROLE,
    VAR_LEN_UINT_SAVE_VAL,
    VAR_LEN_UINT_WITH_ROLE_SAVE_VAL,
    VAR_LEN_SINT,
    VAR_LEN_SINT_SAVE_VAL,
    VAR_LEN_UENUM,
    VAR_LEN_UENUM_WITH_ROLE,
    VAR_LEN_UENUM_SAVE_VAL,
    VAR_LEN_UENUM_WITH_ROLE_SAVE_VAL,
    VAR_LEN_SENUM,
    VAR_LEN_SENUM_SAVE_VAL,
    NULL_TERMINATED_STR,
    STATIC_LEN_STR,
    DYN_LEN_STR,
    STATIC_LEN_BLOB,
    STATIC_LEN_BLOB_WITH_METADATA_STREAM_UUID_ROLE,
    DYN_LEN_BLOB,
    STATIC_LEN_ARRAY,
    STATIC_LEN_ARRAY_WITH_METADATA_STREAM_UUID_ROLE,
    DYN_LEN_ARRAY,
    STRUCT,
    OPTIONAL_WITH_BOOL_SEL,
    OPTIONAL_WITH_UINT_SEL,
    OPTIONAL_WITH_SINT_SEL,
    VARIANT_WITH_UINT_SEL,
    VARIANT_WITH_SINT_SEL,
};

/*
 * Vector of value saving indexes.
 *
 * The strategy to decode dynamic-length, optional, and variant fields
 * (called dependend fields) is for the data stream decoder to save the
 * values of dependencies (boolean or integer fields) so that it can use
 * them afterwards to decode dependent fields.
 *
 * A field class FC of which the deep type contains `SAVE_VAL` contains
 * value saving indexes I (valSavingIndexes() method).
 * valSavingIndexes() possibly returns more than one index because many
 * dependent fields may depend on the same boolean/integer field
 *
 * When decoding an instance of FC, the decoder saves its value to some
 * vector V at the indexes I. When decoding a dependend field, its class
 * contains an index to retrieve a saved value (its length or selector)
 * from V.
 */
using ValSavingIndexes = std::vector<std::size_t>;

namespace internal {

struct CtfIrMixins;

}

/*
 * Set of field class pointers.
 */
using FcSet = std::unordered_set<ir::Fc<internal::CtfIrMixins> *>;

namespace internal {

/*
 * Clock class user mixin.
 */
class ClkClsMixin
{
public:
    explicit ClkClsMixin() noexcept = default;

    /*
     * Sets the equivalent libbabeltrace2 class to `cls` (shared).
     */
    void sharedLibCls(bt2::ClockClass::Shared cls) noexcept;

private:
    /* Equivalent libbabeltrace2 class (shared) */
    bt2::ClockClass::Shared _mSharedLibCls;
};

class FixedLenBoolFcMixin;
class FixedLenIntFcMixin;
class VarLenIntFcMixin;

/*
 * Field class user mixin.
 */
class FcMixin
{
    friend class FixedLenBoolFcMixin;
    friend class FixedLenIntFcMixin;
    friend class VarLenIntFcMixin;

public:
    explicit FcMixin() noexcept = default;

    explicit FcMixin(const FcDeepType deepType) noexcept : _mDeepType {deepType}
    {
    }

    /*
     * Deep type of this field class.
     */
    FcDeepType deepType() const noexcept
    {
        return _mDeepType;
    }

private:
    /* Deep type of this field class */
    FcDeepType _mDeepType;
};

/*
 * Internal mixin for a value saving field class.
 *
 * See the comment of `ValSavingIndexes` to learn more.
 */
class ValSavingFcMixin
{
protected:
    explicit ValSavingFcMixin() noexcept = default;

public:
    const ValSavingIndexes& valSavingIndexes() const noexcept
    {
        return _mValSavingIndexes;
    }

protected:
    /*
     * Adds the value saving index `index` to this field class having
     * the deep type `deepType`.
     */
    void _addValSavingIndex(std::size_t index, FcDeepType& deepType) noexcept;

private:
    /* Value saving indexes */
    ValSavingIndexes _mValSavingIndexes;
};

/*
 * Fixed-length boolean field class user mixin.
 */
class FixedLenBoolFcMixin : public ValSavingFcMixin
{
public:
    explicit FixedLenBoolFcMixin() noexcept = default;

    /*
     * Adds the value saving index `index` to this field class.
     *
     * IMPORTANT: Only call this method if you can guarantee that you
     * you won't clone `*this` (through Fc::clone()).
     */
    void addValSavingIndex(std::size_t index) noexcept;

    using ValSavingFcMixin::valSavingIndexes;
};

/*
 * Fixed-length integer field class user mixin.
 */
class FixedLenIntFcMixin : public ValSavingFcMixin
{
public:
    explicit FixedLenIntFcMixin() noexcept = default;

    /*
     * Adds the value saving index `index` to this field class.
     *
     * IMPORTANT: Only call this method if you can guarantee that you
     * you won't clone `*this` (through Fc::clone()).
     */
    void addValSavingIndex(std::size_t index) noexcept;

    using ValSavingFcMixin::valSavingIndexes;
};

/*
 * Variable-length integer field class user mixin.
 */
class VarLenIntFcMixin : public ValSavingFcMixin
{
public:
    explicit VarLenIntFcMixin() noexcept = default;

    /*
     * Adds the value saving index `index` to this field class.
     *
     * IMPORTANT: Only call this method if you can guarantee that you
     * you won't clone `*this` (through Fc::clone()).
     */
    void addValSavingIndex(std::size_t index) noexcept;

    using ValSavingFcMixin::valSavingIndexes;
};

/*
 * Internal mixin for a dependent (dynamic-length, optional, or variant)
 * field class.
 *
 * See the comment of `ValSavingIndexes` to learn more.
 */
class DependentFcMixin
{
public:
    explicit DependentFcMixin() noexcept = default;

    /*
     * Index of the saved dependency value of this field class.
     */
    const bt2s::optional<std::size_t>& savedDepValIndex() const noexcept
    {
        return _mSavedDepValIndex;
    }

    /*
     * Sets the index of the saved dependency value of this field class
     * to `savedDepValIndex`.
     *
     * IMPORTANT: Only call this method if you can guarantee that you
     * you won't clone `*this` (through Fc::clone()).
     */
    void savedDepValIndex(const std::size_t savedDepValIndex) noexcept
    {
        _mSavedDepValIndex = savedDepValIndex;
    }

    /*
     * Dependencies of this field class.
     */
    const FcSet& deps() noexcept
    {
        return _mDeps;
    }

    /*
     * Sets the dependencies of this field class to `deps`.
     *
     * IMPORTANT: Only call this method if you can guarantee that you
     * you won't clone `*this` (through Fc::clone()).
     */
    void deps(FcSet deps)
    {
        _mDeps = std::move(deps);
    }

private:
    /* Index of the saved dependency value of this field class */
    bt2s::optional<std::size_t> _mSavedDepValIndex;

    /* Dependencies of this field class */
    FcSet _mDeps;
};

/*
 * Event record class user mixin.
 *
 * If libCls() has a value, then consider that all the dependent field
 * classes of the event record class have a saved value index.
 */
class EventRecordClsMixin
{
public:
    explicit EventRecordClsMixin() noexcept = default;
};

/*
 * Data stream class user mixin.
 *
 * If libCls() has a value, then consider that all the dependent field
 * classes of the data stream class have a saved value index.
 */
class DataStreamClsMixin
{
public:
    explicit DataStreamClsMixin() noexcept = default;
};

/*
 * Trace class user mixin.
 *
 * If libCls() has a value, then consider that all the dependent field
 * classes of the trace class have a saved value index.
 */
class TraceClsMixin
{
public:
    using SavedValCountUpdatedObservable = bt2c::Observable<std::size_t>;

public:
    explicit TraceClsMixin() noexcept = default;

    /*
     * Sets the equivalent libbabeltrace2 class to `cls` (shared).
     */
    void sharedLibCls(bt2::TraceClass::Shared cls) noexcept;

    /*
     * Maximum number of saved values for an instance of this trace
     * class.
     *
     * See the comment of `ValSavingIndexes` to learn more.
     */
    std::size_t savedValCount() const noexcept
    {
        return _mSavedValCount;
    }

    /*
     * Sets the maximum number of saved values for an instance of this
     * trace class to `savedValCount`.
     *
     * See the comment of `ValSavingIndexes` to learn more.
     */
    void savedValCount(const std::size_t savedValCount) noexcept
    {
        _mSavedValCount = savedValCount;
        _mSavedValCountUpdatedObservable.notify(_mSavedValCount);
    }

    /*
     * Observable notified when the number of saved values required by this
     * trace class changes.
     */
    SavedValCountUpdatedObservable& savedValCountUpdatedObservable() const
    {
        return _mSavedValCountUpdatedObservable;
    }

private:
    /* Equivalent libbabeltrace2 class (shared) */
    bt2::TraceClass::Shared _mSharedLibCls;

    /*
     * Maximum number of saved values for an instance of this trace
     * class.
     *
     * See the comment of `ValSavingIndexes` to learn more.
     */
    std::size_t _mSavedValCount = 0;

    /*
     * Observable notified when the number of saved values required by this
     * trace class changes.
     */
    mutable SavedValCountUpdatedObservable _mSavedValCountUpdatedObservable;
};

/*
 * User mixin container.
 */
struct CtfIrMixins final : public ir::DefUserMixins
{
    using ClkCls = ClkClsMixin;
    using Fc = FcMixin;
    using FixedLenBoolFc = FixedLenBoolFcMixin;
    using FixedLenIntFc = FixedLenIntFcMixin;
    using VarLenIntFc = VarLenIntFcMixin;
    using DynLenStrFc = DependentFcMixin;
    using DynLenBlobFc = DependentFcMixin;
    using DynLenArrayFc = DependentFcMixin;
    using VariantFc = DependentFcMixin;
    using OptionalFc = DependentFcMixin;
    using EventRecordCls = EventRecordClsMixin;
    using DataStreamCls = DataStreamClsMixin;
    using TraceCls = TraceClsMixin;
};

} /* namespace internal */

/* Aliases of the `ctf::src` CTF IR API */
using Fc = ir::Fc<internal::CtfIrMixins>;
using FixedLenBitArrayFc = ir::FixedLenBitArrayFc<internal::CtfIrMixins>;
using FixedLenBoolFc = ir::FixedLenBoolFc<internal::CtfIrMixins>;
using FixedLenFloatFc = ir::FixedLenFloatFc<internal::CtfIrMixins>;
using FixedLenIntFc = ir::FixedLenIntFc<internal::CtfIrMixins>;
using FixedLenUIntFc = ir::FixedLenUIntFc<internal::CtfIrMixins>;
using FixedLenSIntFc = ir::FixedLenSIntFc<internal::CtfIrMixins>;
using FixedLenSEnumFc = ir::FixedLenSEnumFc<internal::CtfIrMixins>;
using FixedLenUEnumFc = ir::FixedLenUEnumFc<internal::CtfIrMixins>;
using VarLenIntFc = ir::VarLenIntFc<internal::CtfIrMixins>;
using VarLenSIntFc = ir::VarLenSIntFc<internal::CtfIrMixins>;
using VarLenUIntFc = ir::VarLenUIntFc<internal::CtfIrMixins>;
using VarLenSEnumFc = ir::VarLenSEnumFc<internal::CtfIrMixins>;
using VarLenUEnumFc = ir::VarLenUEnumFc<internal::CtfIrMixins>;
using NullTerminatedStrFc = ir::NullTerminatedStrFc<internal::CtfIrMixins>;
using NonNullTerminatedStrFc = ir::NonNullTerminatedStrFc<internal::CtfIrMixins>;
using StaticLenStrFc = ir::StaticLenStrFc<internal::CtfIrMixins>;
using DynLenStrFc = ir::DynLenStrFc<internal::CtfIrMixins>;
using BlobFc = ir::BlobFc<internal::CtfIrMixins>;
using StaticLenBlobFc = ir::StaticLenBlobFc<internal::CtfIrMixins>;
using DynLenBlobFc = ir::DynLenBlobFc<internal::CtfIrMixins>;
using ArrayFc = ir::ArrayFc<internal::CtfIrMixins>;
using StaticLenArrayFc = ir::StaticLenArrayFc<internal::CtfIrMixins>;
using DynLenArrayFc = ir::DynLenArrayFc<internal::CtfIrMixins>;
using StructFc = ir::StructFc<internal::CtfIrMixins>;
using OptionalFc = ir::OptionalFc<internal::CtfIrMixins>;
using OptionalWithBoolSelFc = ir::OptionalWithBoolSelFc<internal::CtfIrMixins>;
using OptionalWithUIntSelFc = ir::OptionalWithUIntSelFc<internal::CtfIrMixins>;
using OptionalWithSIntSelFc = ir::OptionalWithSIntSelFc<internal::CtfIrMixins>;
using VariantWithUIntSelFc = ir::VariantWithUIntSelFc<internal::CtfIrMixins>;
using VariantWithSIntSelFc = ir::VariantWithSIntSelFc<internal::CtfIrMixins>;
using FieldLoc = ir::FieldLoc<internal::CtfIrMixins>;
using StructFieldMemberCls = ir::StructFieldMemberCls<internal::CtfIrMixins>;
using ClkCls = ir::ClkCls<internal::CtfIrMixins>;
using EventRecordCls = ir::EventRecordCls<internal::CtfIrMixins>;
using DataStreamCls = ir::DataStreamCls<internal::CtfIrMixins>;
using TraceCls = ir::TraceCls<internal::CtfIrMixins>;
using FcVisitor = ir::FcVisitor<internal::CtfIrMixins>;
using ConstFcVisitor = ir::ConstFcVisitor<internal::CtfIrMixins>;

/*
 * Creates and returns a field location having the scope `scope` and the
 * path items `items`.
 */
FieldLoc createFieldLoc(ir::FieldLocScope scope, FieldLoc::Items items);

/*
 * Creates and returns a class of fixed-length bit array fields having
 * the alignment `align` bits, the length `len`, the byte order
 * `byteOrder`, and the user attributes `userAttrs`.
 */
std::unique_ptr<FixedLenBitArrayFc>
createFixedLenBitArrayFc(unsigned int align, bt2c::DataLen len, ir::ByteOrder byteOrder,
                         ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class of fixed-length boolean fields having the
 * alignment `align` bits, the length `len`, the byte order `byteOrder`,
 * and the user attributes `userAttrs`.
 */
std::unique_ptr<FixedLenBoolFc>
createFixedLenBoolFc(unsigned int align, bt2c::DataLen len, ir::ByteOrder byteOrder,
                     ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class of fixed-length floating point number
 * fields having the alignment `align` bits, the length `len`, the byte
 * order `byteOrder`, and the user attributes `userAttrs`.
 */
std::unique_ptr<FixedLenFloatFc>
createFixedLenFloatFc(unsigned int align, bt2c::DataLen len, ir::ByteOrder byteOrder,
                      ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class of fixed-length unsigned integer fields
 * having the alignment `align` bits, the length `len`, the byte order
 * `byteOrder`, the preferred display base `prefDispBase`, the roles
 * `roles`, and the user attributes `userAttrs`.
 */
std::unique_ptr<FixedLenUIntFc>
createFixedLenUIntFc(unsigned int align, bt2c::DataLen len, ir::ByteOrder byteOrder,
                     ir::DispBase prefDispBase = ir::DispBase::DEC, ir::UIntFieldRoles roles = {},
                     ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class of fixed-length signed integer fields
 * having the alignment `align` bits, the length `len`, the byte order
 * `byteOrder`, the preferred display base `prefDispBase`, and the user
 * attributes `userAttrs`.
 */
std::unique_ptr<FixedLenSIntFc>
createFixedLenSIntFc(unsigned int align, bt2c::DataLen len, ir::ByteOrder byteOrder,
                     ir::DispBase prefDispBase = ir::DispBase::DEC,
                     ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class of fixed-length unsigned enumeration
 * fields having the alignment `align` bits, the length `len`, the byte
 * order `byteOrder`, the mappings `mappings`, the preferred display
 * base `prefDispBase`, the roles `roles`, and the user attributes
 * `userAttrs`.
 */
std::unique_ptr<FixedLenUEnumFc>
createFixedLenUEnumFc(unsigned int align, bt2c::DataLen len, ir::ByteOrder byteOrder,
                      FixedLenUEnumFc::Mappings mappings,
                      ir::DispBase prefDispBase = ir::DispBase::DEC, ir::UIntFieldRoles roles = {},
                      ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class of fixed-length signed enumeration fields
 * having the alignment `align` bits, the length `len`, the byte order
 * `byteOrder`, the mappings `mappings`, the preferred display base
 * `prefDispBase`, and the user attributes `userAttrs`.
 */
std::unique_ptr<FixedLenSEnumFc>
createFixedLenSEnumFc(unsigned int align, bt2c::DataLen len, ir::ByteOrder byteOrder,
                      FixedLenSEnumFc::Mappings mappings,
                      ir::DispBase prefDispBase = ir::DispBase::DEC,
                      ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class of variable-length unsigned integer
 * fields having the preferred display base `prefDispBase`, the roles
 * `roles`, and the user attributes `userAttrs`.
 */
std::unique_ptr<VarLenUIntFc> createVarLenUIntFc(ir::DispBase prefDispBase = ir::DispBase::DEC,
                                                 ir::UIntFieldRoles roles = {},
                                                 ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class of variable-length signed integer fields
 * having the preferred display base `prefDispBase` and the user
 * attributes `userAttrs`.
 */
std::unique_ptr<VarLenSIntFc> createVarLenSIntFc(ir::DispBase prefDispBase = ir::DispBase::DEC,
                                                 ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class of variable-length unsigned enumeration
 * fields having the mapping `mapping`, the preferred display base
 * `prefDispBase`, the roles `roles`, and the user attributes
 * `userAttrs`.
 */
std::unique_ptr<VarLenUEnumFc>
createVarLenUEnumFc(FixedLenUEnumFc::Mappings mappings,
                    ir::DispBase prefDispBase = ir::DispBase::DEC, ir::UIntFieldRoles roles = {},
                    ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class of variable-length signed enumeration
 * fields having the mapping `mapping`, the preferred display base
 * `prefDispBase`, and the user attributes `userAttrs`.
 */
std::unique_ptr<VarLenSEnumFc>
createVarLenSEnumFc(FixedLenSEnumFc::Mappings mappings,
                    ir::DispBase prefDispBase = ir::DispBase::DEC,
                    ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class of null-terminated fields having the user
 * attributes `userAttrs`.
 */
std::unique_ptr<NullTerminatedStrFc>
createNullTerminatedStrFc(ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class of static-length array fields having the
 * length `len`, the element field class `elemFc`, the minimum alignment
 * `minAlign` bits, the user attributes `userAttrs`, and the "metadata
 * stream UUID" role if `hasMetadataStreamUuidRole` is true.
 */
std::unique_ptr<StaticLenArrayFc>
createStaticLenArrayFc(std::size_t len, Fc::UP elemFc, unsigned int minAlign = 1,
                       ir::OptUserAttrs userAttrs = ir::OptUserAttrs {},
                       bool hasMetadataStreamUuidRole = false);

/*
 * Creates and returns a class of dynamic-length array fields having the
 * length field location `lenFieldLoc`, the element field class
 * `elemFc`, the minimum alignment `minAlign` bits, and the user
 * attributes `userAttrs`.
 */
std::unique_ptr<DynLenArrayFc>
createDynLenArrayFc(FieldLoc lenFieldLoc, Fc::UP elemFc, unsigned int minAlign = 1,
                    ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class of static-length string fields having the
 * length `len` bytes and the user attributes `userAttrs`.
 */
std::unique_ptr<StaticLenStrFc>
createStaticLenStrFc(std::size_t len, ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class of dynamic-length string fields having
 * the length field location `lenFieldLoc` and the user attributes
 * `userAttrs`.
 */
std::unique_ptr<DynLenStrFc> createDynLenStrFc(FieldLoc lenFieldLoc,
                                               ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class of static-length BLOB fields having the
 * length `len` bytes, the media type `mediaType`, the "metadata stream
 * UUID" role if `hasMetadataStreamUuidRole` is true, and the user
 * attributes `userAttrs`.
 */
std::unique_ptr<StaticLenBlobFc>
createStaticLenBlobFc(std::size_t len, std::string mediaType = StaticLenBlobFc::defaultMediaType,
                      bool hasMetadataStreamUuidRole = false,
                      ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class of dynamic-length BLOB fields having the
 * length field location `lenFieldLoc`, the media type `mediaType`, and
 * the user attributes `userAttrs`.
 */
std::unique_ptr<DynLenBlobFc>
createDynLenBlobFc(FieldLoc lenFieldLoc, std::string mediaType = DynLenBlobFc::defaultMediaType,
                   ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class of structure field members having the
 * name `name`, the field class `fc`, and the user attributes
 * `userAttrs`.
 */
StructFieldMemberCls createStructFieldMemberCls(std::string name, Fc::UP fc,
                                                ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class of structure fields having members of
 * classes `memberClasses`, the minimum alignment `minAlign` bits, and
 * the user attributes `userAttrs`.
 */
std::unique_ptr<StructFc> createStructFc(StructFc::MemberClasses&& memberClasses = {},
                                         unsigned int minAlign = 1,
                                         ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class of optional fields having a boolean
 * selector, the optional field class `fc`, the selector field location
 * `selFieldLoc`, and the user attributes `userAttrs`.
 */
std::unique_ptr<OptionalWithBoolSelFc>
createOptionalFc(Fc::UP fc, FieldLoc selFieldLoc, ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class of optional fields having an unsigned
 * integer selector, the optional field class `fc`, the selector field
 * location `selFieldLoc`, the integer selector field ranges
 * `selFieldRanges`, and the user attributes `userAttrs`.
 */
std::unique_ptr<OptionalWithUIntSelFc>
createOptionalFc(Fc::UP fc, FieldLoc selFieldLoc, UIntRangeSet selFieldRanges,
                 ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class of optional fields having a signed
 * integer selector, the optional field class `fc`, the selector field
 * location `selFieldLoc`, the integer selector field ranges
 * `selFieldRanges`, and the user attributes `userAttrs`.
 */
std::unique_ptr<OptionalWithSIntSelFc>
createOptionalFc(Fc::UP fc, FieldLoc selFieldLoc, SIntRangeSet selFieldRanges,
                 ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns an option, for the class of a variant field
 * having an unsigned integer selector, having the field class `fc`, the
 * selector field ranges `selFieldRanges`, the name `name`, and the user
 * attributes `userAttrs`.
 */
VariantWithUIntSelFc::Opt createVariantFcOpt(Fc::UP fc, UIntRangeSet selFieldRanges,
                                             bt2s::optional<std::string> name,
                                             ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns an option, for the class of a variant field
 * having a signed integer selector, having the field class `fc`, the
 * selector field ranges `selFieldRanges`, the name `name`, and the user
 * attributes `userAttrs`.
 */
VariantWithSIntSelFc::Opt createVariantFcOpt(Fc::UP fc, SIntRangeSet selFieldRanges,
                                             bt2s::optional<std::string> name,
                                             ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class of variant fields having an unsigned
 * integer selector, the options `opts`, the selector field location
 * `selFieldLoc`, and the user attributes `userAttrs`.
 */
std::unique_ptr<VariantWithUIntSelFc>
createVariantFc(VariantWithUIntSelFc::Opts&& opts, FieldLoc selFieldLoc,
                ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class of variant fields having a signed integer
 * selector, the options `opts`, the selector field location
 * `selFieldLoc`, and the user attributes `userAttrs`.
 */
std::unique_ptr<VariantWithSIntSelFc>
createVariantFc(VariantWithSIntSelFc::Opts&& opts, FieldLoc selFieldLoc,
                ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class of a clocks havin the name `name`, the
 * frequency `freq` Hz, the offset from origin `offset`, its origin
 * being the Unix epoch if `originIsUnixEpoch` is true, the description
 * `descr`, the precision `precision` cycles, the UUID `uuid`, and the
 * user attributes `userAttrs`.
 */
ClkCls::SP createClkCls(std::string name, unsigned long long freq,
                        const ir::ClkOffset& offset = ir::ClkOffset {},
                        bool originIsUnixEpoch = true,
                        bt2s::optional<std::string> descr = bt2s::nullopt,
                        unsigned long long precision = 0,
                        bt2s::optional<bt2c::Uuid> uuid = bt2s::nullopt,
                        ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class, having the ID `id`, of event records
 * having the namespace `ns`, the name `name`, the specific context
 * field class `specCtxFc`, the payload field class `payloadFc`, and the
 * user attributes `userAttrs`.
 */
std::unique_ptr<EventRecordCls>
createEventRecordCls(unsigned long long id, bt2s::optional<std::string> ns = bt2s::nullopt,
                     bt2s::optional<std::string> name = bt2s::nullopt, Fc::UP specCtxFc = nullptr,
                     Fc::UP payloadFc = nullptr, ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class, having the ID `id`, of data streams
 * having the namespace `ns`, the name `name`, the packet context field
 * class `pktCtxFc`, the event record header field class
 * `eventRecordHeaderFc`, the common event record context field class
 * `eventRecordCommonCtxFc`, the default clock class `defClkCls`, and
 * the user attributes `userAttrs`.
 */
std::unique_ptr<DataStreamCls>
createDataStreamCls(unsigned long long id, bt2s::optional<std::string> ns = bt2s::nullopt,
                    bt2s::optional<std::string> name = bt2s::nullopt, Fc::UP pktCtxFc = nullptr,
                    Fc::UP eventRecordHeaderFc = nullptr, Fc::UP eventRecordCommonCtxFc = nullptr,
                    ClkCls::SP defClkCls = nullptr,
                    ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

/*
 * Creates and returns a class of traces having the UUID `uuid`, the
 * environment `env`, the packet header field class `pktHeaderFc`, and
 * the user attributes `userAttrs`.
 */
std::unique_ptr<TraceCls>
createTraceCls(bt2s::optional<bt2c::Uuid> uuid = bt2s::nullopt,
               bt2::ConstMapValue::Shared env = bt2::ConstMapValue::Shared {},
               Fc::UP pktHeaderFc = nullptr, ir::OptUserAttrs userAttrs = ir::OptUserAttrs {});

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_CTF_IR_HPP */
