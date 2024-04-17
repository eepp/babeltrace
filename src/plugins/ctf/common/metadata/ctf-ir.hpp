/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2022 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef _CTF_CTF_IR_HPP
#define _CTF_CTF_IR_HPP

#include <algorithm>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "common/assert.h"
#include "cpp-common/bt2/clock-class.hpp"
#include "cpp-common/bt2/field-class.hpp"
#include "cpp-common/bt2/trace-ir.hpp"
#include "cpp-common/bt2c/data-len.hpp"
#include "cpp-common/bt2c/uuid.hpp"
#include "cpp-common/bt2s/make-unique.hpp"

#include "int-range-set.hpp"

namespace ctf {
namespace ir {

/*
 * This is the common CTF IR API, that is, the intermediate
 * representation of CTF metadata objects for the whole `ctf` plugin.
 *
 * Class hierarchy
 * ═══════════════
 * The class hierarchy (omitting template parameters) is as such:
 *
 *    TraceCls
 *    DataStreamCls
 *    EventRecordCls
 *    ClkCls
 *    FieldLoc
 *    StructFieldMemberCls
 *    VariantFcOpt
 *    Fc
 *      FixedLengthBitArrayFc
 *        FixedLengthBoolFc
 *        FixedLengthFloatFc
 *        FixedLengthIntFc
 *          FixedLengthUIntFc
 *            FixedLengthUEnumFc
 *          FixedLengthSIntFc
 *            FixedLengthSEnumFc
 *      VarLengthIntFc
 *        VarLengthUIntFc
 *          VarLengthUEnumFc
 *        VarLengthSIntFc
 *          FixedLengthSEnumFc
 *      NullTerminatedStrFc
 *      NonNullTerminatedStrFc
 *        StaticLenStrFc
 *        DynLenStrFc
 *      BlobFc
 *        StaticLenBlobFc
 *        DynLenBlobFc
 *      ArrayFc
 *        StaticLenArrayFc
 *        DynLenArrayFc
 *      StructFc
 *      OptionalFc
 *        OptionalWithBoolSelFc
 *        OptionalWithIntSelFc
 *          OptionalWithUIntSelFc
 *          OptionalWithSIntSelFc
 *      VariantFc
 *        VariantWithUIntSelFc
 *        VariantWithSIntSelFc
 *
 * The `FcVisitor` and `ConstFcVisitor` base classes are available to
 * visit field classes through the virtual Fc::accept() methods.
 *
 * Each class template has the `UserMixinsT` template parameter.
 *
 * User mixins
 * ═══════════
 * `UserMixinsT` is expected to be a user mixin container, a type which
 * defines the following nested types (user mixins):
 *
 * • `FieldLoc`
 * • `Fc`
 * • `FixedLenBitArrayFc`
 * • `FixedLenBoolFc`
 * • `FixedLenIntFc`
 * • `FixedLenUIntFc`
 * • `VarLenIntFc`
 * • `VarLenUIntFc`
 * • `StaticLenStrFc`
 * • `DynLenStrFc`
 * • `StaticLenBlobFc`
 * • `DynLenBlobFc`
 * • `StaticLenArrayFc`
 * • `DynLenArrayFc`
 * • `StructFieldMemberCls`
 * • `StructFc`
 * • `OptionalFc`
 * • `OptionalWithBoolSelFc`
 * • `OptionalWithUIntSelFc`
 * • `OptionalWithSIntSelFc`
 * • `VariantFcOpt`
 * • `VariantWithUIntSelFc`
 * • `VariantWithSIntSelFc`
 * • `ClkCls`
 * • `EventRecordCls`
 * • `DataStreamCls`
 * • `TraceCls`
 *
 * Most class templates inherit a given user mixin. For example,
 * `FixedLenBoolFc` inherits `UserMixinsT::FixedLenBoolFc`. This makes
 * it possible for the user to inject data and methods into the class
 * while keeping the hierarchy and common features.
 *
 * A class template which inherits a user mixin M has a constructor
 * which accepts an instance of M by value to initialize this part of
 * the object.
 *
 * If a class template C which inherits a user mixin also inherits
 * another class template inheriting another user mixin, then the
 * constructor of C accepts both mixins. For example,
 * FixedLenUEnumFc::FixedLenUEnumFc() accepts four mixins: field class,
 * fixed-length bit array field class, fixed-length integer field class,
 * and fixed-length unsigned integer field class.
 *
 * A mixin must be copy-constructible to make the Fc::clone() method
 * work.
 *
 * The API offers `DefUserMixins` which defines empty user mixins to act
 * as a base user mixin container structure.
 *
 * Usage
 * ═════
 * This is how you would use this API:
 *
 * • Define your own user mixin container structure which inherits
 *   `DefUserMixins`, defining the user mixins you need to add data and
 *   methods to specific common classes.
 *
 * • Define aliases for each `ctf::ir` class template you need, using
 *   your user mixin container structure as the `UserMixinsT` template
 *   parameter.
 *
 * • Create convenient object creation functions to construct specific
 *   CTF IR objects from parameters, hiding the internal user mixin
 *   details.
 */

template <typename UserMixinsT>
class FixedLenBitArrayFc;

template <typename UserMixinsT>
class FixedLenBoolFc;

template <typename UserMixinsT>
class FixedLenFloatFc;

template <typename UserMixinsT>
class FixedLenIntFc;

template <typename UserMixinsT>
class FixedLenUIntFc;

template <typename UserMixinsT>
class FixedLenSIntFc;

template <typename UserMixinsT>
class FixedLenSEnumFc;

template <typename UserMixinsT>
class FixedLenUEnumFc;

template <typename UserMixinsT>
class VarLenIntFc;

template <typename UserMixinsT>
class VarLenSIntFc;

template <typename UserMixinsT>
class VarLenUIntFc;

template <typename UserMixinsT>
class VarLenSEnumFc;

template <typename UserMixinsT>
class VarLenUEnumFc;

template <typename UserMixinsT>
class NullTerminatedStrFc;

template <typename UserMixinsT>
class NonNullTerminatedStrFc;

template <typename UserMixinsT>
class StaticLenStrFc;

template <typename UserMixinsT>
class DynLenStrFc;

template <typename UserMixinsT>
class BlobFc;

template <typename UserMixinsT>
class StaticLenBlobFc;

template <typename UserMixinsT>
class DynLenBlobFc;

template <typename UserMixinsT>
class ArrayFc;

template <typename UserMixinsT>
class StaticLenArrayFc;

template <typename UserMixinsT>
class DynLenArrayFc;

template <typename UserMixinsT>
class StructFc;

template <typename UserMixinsT>
class OptionalFc;

template <typename UserMixinsT>
class OptionalWithBoolSelFc;

template <typename UserMixinsT>
class OptionalWithUIntSelFc;

template <typename UserMixinsT>
class OptionalWithSIntSelFc;

template <typename UserMixinsT>
class VariantWithUIntSelFc;

template <typename UserMixinsT>
class VariantWithSIntSelFc;

/*
 * Visitor of `Fc<UserMixinsT>`.
 *
 * See `ConstFcVisitor` which visits `const Fc<UserMixinsT>`.
 */
template <typename UserMixinsT>
class FcVisitor
{
protected:
    explicit FcVisitor() = default;

public:
    virtual ~FcVisitor() = default;

    virtual void visit(FixedLenBitArrayFc<UserMixinsT>&)
    {
    }

    virtual void visit(FixedLenBoolFc<UserMixinsT>&)
    {
    }

    virtual void visit(FixedLenFloatFc<UserMixinsT>&)
    {
    }

    virtual void visit(FixedLenUIntFc<UserMixinsT>&)
    {
    }

    virtual void visit(FixedLenSIntFc<UserMixinsT>&)
    {
    }

    virtual void visit(FixedLenSEnumFc<UserMixinsT>&)
    {
    }

    virtual void visit(FixedLenUEnumFc<UserMixinsT>&)
    {
    }

    virtual void visit(VarLenSIntFc<UserMixinsT>&)
    {
    }

    virtual void visit(VarLenUIntFc<UserMixinsT>&)
    {
    }

    virtual void visit(VarLenSEnumFc<UserMixinsT>&)
    {
    }

    virtual void visit(VarLenUEnumFc<UserMixinsT>&)
    {
    }

    virtual void visit(NullTerminatedStrFc<UserMixinsT>&)
    {
    }

    virtual void visit(StaticLenStrFc<UserMixinsT>&)
    {
    }

    virtual void visit(DynLenStrFc<UserMixinsT>&)
    {
    }

    virtual void visit(StaticLenBlobFc<UserMixinsT>&)
    {
    }

    virtual void visit(DynLenBlobFc<UserMixinsT>&)
    {
    }

    virtual void visit(StaticLenArrayFc<UserMixinsT>&)
    {
    }

    virtual void visit(DynLenArrayFc<UserMixinsT>&)
    {
    }

    virtual void visit(StructFc<UserMixinsT>&)
    {
    }

    virtual void visit(OptionalWithBoolSelFc<UserMixinsT>&)
    {
    }

    virtual void visit(OptionalWithUIntSelFc<UserMixinsT>&)
    {
    }

    virtual void visit(OptionalWithSIntSelFc<UserMixinsT>&)
    {
    }

    virtual void visit(VariantWithUIntSelFc<UserMixinsT>&)
    {
    }

    virtual void visit(VariantWithSIntSelFc<UserMixinsT>&)
    {
    }
};

/*
 * Visitor of `const Fc<UserMixinsT>`.
 *
 * See `FcVisitor` which visits `Fc<UserMixinsT>`.
 */
template <typename UserMixinsT>
class ConstFcVisitor
{
protected:
    explicit ConstFcVisitor() = default;

public:
    virtual ~ConstFcVisitor() = default;

    virtual void visit(const FixedLenBitArrayFc<UserMixinsT>&)
    {
    }

    virtual void visit(const FixedLenBoolFc<UserMixinsT>&)
    {
    }

    virtual void visit(const FixedLenFloatFc<UserMixinsT>&)
    {
    }

    virtual void visit(const FixedLenUIntFc<UserMixinsT>&)
    {
    }

    virtual void visit(const FixedLenSIntFc<UserMixinsT>&)
    {
    }

    virtual void visit(const FixedLenSEnumFc<UserMixinsT>&)
    {
    }

    virtual void visit(const FixedLenUEnumFc<UserMixinsT>&)
    {
    }

    virtual void visit(const VarLenSIntFc<UserMixinsT>&)
    {
    }

    virtual void visit(const VarLenUIntFc<UserMixinsT>&)
    {
    }

    virtual void visit(const VarLenSEnumFc<UserMixinsT>&)
    {
    }

    virtual void visit(const VarLenUEnumFc<UserMixinsT>&)
    {
    }

    virtual void visit(const NullTerminatedStrFc<UserMixinsT>&)
    {
    }

    virtual void visit(const StaticLenStrFc<UserMixinsT>&)
    {
    }

    virtual void visit(const DynLenStrFc<UserMixinsT>&)
    {
    }

    virtual void visit(const StaticLenBlobFc<UserMixinsT>&)
    {
    }

    virtual void visit(const DynLenBlobFc<UserMixinsT>&)
    {
    }

    virtual void visit(const StaticLenArrayFc<UserMixinsT>&)
    {
    }

    virtual void visit(const DynLenArrayFc<UserMixinsT>&)
    {
    }

    virtual void visit(const StructFc<UserMixinsT>&)
    {
    }

    virtual void visit(const OptionalWithBoolSelFc<UserMixinsT>&)
    {
    }

    virtual void visit(const OptionalWithUIntSelFc<UserMixinsT>&)
    {
    }

    virtual void visit(const OptionalWithSIntSelFc<UserMixinsT>&)
    {
    }

    virtual void visit(const VariantWithUIntSelFc<UserMixinsT>&)
    {
    }

    virtual void visit(const VariantWithSIntSelFc<UserMixinsT>&)
    {
    }
};

/* clang-format off */

/*
 * To make the Fc<UserMixinsT>::isXyz() methods more efficient, `FcType`
 * enumerators (below) are bitwise compositions of `FcTypeTraits` values
 * (traits/features). The isXyz() methods only check if specific bits of
 * the field class type are set.
 */
struct FcTypeTraits
{
    enum {
        FIXED_OR_STATIC_LEN = 1 << 0,
        VAR_OR_DYN_LEN      = 1 << 1,
        BIT_ARRAY           = 1 << 2,
        BOOL                = 1 << 3,
        INT                 = 1 << 4,
        UINT                = (1 << 5) | INT,
        SINT                = (1 << 6) | INT,
        ENUM                = (1 << 7) | INT,
        FLOAT               = 1 << 8,
        NULL_TERMINATED     = 1 << 9,
        NON_NULL_TERMINATED = 1 << 10,
        BLOB                = 1 << 11,
        ARRAY               = 1 << 12,
        STRUCT              = 1 << 13,
        BOOL_SEL            = 1 << 14,
        INT_SEL             = 1 << 15,
        UINT_SEL            = (1 << 16) | INT_SEL,
        SINT_SEL            = (1 << 17) | INT_SEL,
        OPTION              = 1 << 18,
        VARIANT             = 1 << 19
    };
};

/*
 * Field class type.
 */
enum class FcType
{
    FIXED_LEN_BIT_ARRAY     = FcTypeTraits::FIXED_OR_STATIC_LEN | FcTypeTraits::BIT_ARRAY,
    FIXED_LEN_BOOL          = FcTypeTraits::FIXED_OR_STATIC_LEN | FcTypeTraits::BIT_ARRAY | FcTypeTraits::BOOL,
    FIXED_LEN_UINT          = FcTypeTraits::FIXED_OR_STATIC_LEN | FcTypeTraits::BIT_ARRAY | FcTypeTraits::UINT,
    FIXED_LEN_SINT          = FcTypeTraits::FIXED_OR_STATIC_LEN | FcTypeTraits::BIT_ARRAY | FcTypeTraits::SINT,
    FIXED_LEN_UENUM         = FcTypeTraits::FIXED_OR_STATIC_LEN | FcTypeTraits::BIT_ARRAY | FcTypeTraits::ENUM | FcTypeTraits::UINT,
    FIXED_LEN_SENUM         = FcTypeTraits::FIXED_OR_STATIC_LEN | FcTypeTraits::BIT_ARRAY | FcTypeTraits::ENUM | FcTypeTraits::SINT,
    FIXED_LEN_FLOAT         = FcTypeTraits::FIXED_OR_STATIC_LEN | FcTypeTraits::BIT_ARRAY | FcTypeTraits::FLOAT,
    VAR_LEN_UINT            = FcTypeTraits::VAR_OR_DYN_LEN | FcTypeTraits::UINT,
    VAR_LEN_SINT            = FcTypeTraits::VAR_OR_DYN_LEN | FcTypeTraits::SINT,
    VAR_LEN_UENUM           = FcTypeTraits::VAR_OR_DYN_LEN | FcTypeTraits::ENUM | FcTypeTraits::UINT,
    VAR_LEN_SENUM           = FcTypeTraits::VAR_OR_DYN_LEN | FcTypeTraits::ENUM | FcTypeTraits::SINT,
    NULL_TERMINATED_STR     = FcTypeTraits::NULL_TERMINATED,
    STATIC_LEN_STR          = FcTypeTraits::FIXED_OR_STATIC_LEN | FcTypeTraits::NON_NULL_TERMINATED,
    DYN_LEN_STR             = FcTypeTraits::VAR_OR_DYN_LEN | FcTypeTraits::NON_NULL_TERMINATED,
    STATIC_LEN_BLOB         = FcTypeTraits::FIXED_OR_STATIC_LEN | FcTypeTraits::BLOB,
    DYN_LEN_BLOB            = FcTypeTraits::VAR_OR_DYN_LEN | FcTypeTraits::BLOB,
    STATIC_LEN_ARRAY        = FcTypeTraits::FIXED_OR_STATIC_LEN | FcTypeTraits::ARRAY,
    DYN_LEN_ARRAY           = FcTypeTraits::VAR_OR_DYN_LEN | FcTypeTraits::ARRAY,
    STRUCT                  = FcTypeTraits::STRUCT,
    OPTIONAL_WITH_BOOL_SEL  = FcTypeTraits::OPTION | FcTypeTraits::BOOL_SEL,
    OPTIONAL_WITH_UINT_SEL  = FcTypeTraits::OPTION | FcTypeTraits::UINT_SEL,
    OPTIONAL_WITH_SINT_SEL  = FcTypeTraits::OPTION | FcTypeTraits::SINT_SEL,
    VARIANT_WITH_UINT_SEL   = FcTypeTraits::VARIANT | FcTypeTraits::UINT_SEL,
    VARIANT_WITH_SINT_SEL   = FcTypeTraits::VARIANT | FcTypeTraits::SINT_SEL,
};
/* clang-format on */

/*
 * Optional user attributes.
 */
using OptUserAttrs = bt2::ConstMapValue::Shared;

namespace internal {

/*
 * Internal mixin for classes with an optional equivalent libbabeltrace2
 * class.
 */
template <typename ClsT>
class WithLibCls
{
public:
    /*
     * Equivalent libbabeltrace2 class (borrowed).
     */
    const bt2::OptionalBorrowedObject<ClsT>& libCls() const noexcept
    {
        return _mLibCls;
    }

    /*
     * Equivalent libbabeltrace2 class (borrowed).
     */
    bt2::OptionalBorrowedObject<ClsT>& libCls() noexcept
    {
        return _mLibCls;
    }

    /*
     * Sets the equivalent libbabeltrace2 class to `libCls` (borrowed).
     */
    void libCls(const ClsT libCls) noexcept
    {
        _mLibCls = libCls;
    }

private:
    /* Equivalent libbabeltrace2 class (borrowed) */
    bt2::OptionalBorrowedObject<ClsT> _mLibCls;
};

/*
 * Internal mixin for classes with user attributes.
 */
class WithUserAttrsMixin
{
protected:
    explicit WithUserAttrsMixin(OptUserAttrs userAttrs) : _mUserAttrs {std::move(userAttrs)}
    {
    }

public:
    /*
     * User attributes of this object.
     */
    const OptUserAttrs& userAttrs() const noexcept
    {
        return _mUserAttrs;
    }

private:
    /* User attributes of this object */
    OptUserAttrs _mUserAttrs;
};

} /* namespace internal */

/*
 * Field class base.
 *
 * Specific properties:
 *
 * • Alignment of field class instances.
 * • User attributes.
 */
template <typename UserMixinsT>
class Fc :
    public internal::WithUserAttrsMixin,
    public internal::WithLibCls<bt2::FieldClass>,
    public UserMixinsT::Fc
{
public:
    using Type = FcType;
    using UP = std::unique_ptr<Fc>;

protected:
    explicit Fc(const FcType type, typename UserMixinsT::Fc mixin, const unsigned int align,
                OptUserAttrs&& userAttrs) :
        internal::WithUserAttrsMixin {std::move(userAttrs)},
        UserMixinsT::Fc {std::move(mixin)}, _mType {type}, _mAlign {align}
    {
    }

public:
    /* Disable copy/move operations to make this API simpler */
    Fc(const Fc&) = delete;
    Fc(Fc&&) = delete;
    Fc& operator=(const Fc&) = delete;
    Fc& operator=(Fc&&) = delete;

    virtual ~Fc() = default;

    Type type() const noexcept
    {
        return _mType;
    }

    /*
     * Alignment (bits) of instances of this field class.
     */
    unsigned int align() const noexcept
    {
        return _mAlign;
    }

    /*
     * Clones this field class and returns the clone.
     */
    virtual UP clone() const = 0;

    /*
     * Accepts a visitor to visit this field class.
     */
    virtual void accept(FcVisitor<UserMixinsT>&) = 0;

    /*
     * Accepts a visitor to visit this constant field class.
     */
    virtual void accept(ConstFcVisitor<UserMixinsT>&) const = 0;

    /* Casting methods below */
    FixedLenBitArrayFc<UserMixinsT>& asFixedLenBitArray() noexcept;
    const FixedLenBitArrayFc<UserMixinsT>& asFixedLenBitArray() const noexcept;
    FixedLenBoolFc<UserMixinsT>& asFixedLenBool() noexcept;
    const FixedLenBoolFc<UserMixinsT>& asFixedLenBool() const noexcept;
    FixedLenFloatFc<UserMixinsT>& asFixedLenFloat() noexcept;
    const FixedLenFloatFc<UserMixinsT>& asFixedLenFloat() const noexcept;
    FixedLenIntFc<UserMixinsT>& asFixedLenInt() noexcept;
    const FixedLenIntFc<UserMixinsT>& asFixedLenInt() const noexcept;
    FixedLenSIntFc<UserMixinsT>& asFixedLenSInt() noexcept;
    const FixedLenSIntFc<UserMixinsT>& asFixedLenSInt() const noexcept;
    FixedLenUIntFc<UserMixinsT>& asFixedLenUInt() noexcept;
    const FixedLenUIntFc<UserMixinsT>& asFixedLenUInt() const noexcept;
    FixedLenSEnumFc<UserMixinsT>& asFixedLenSEnum() noexcept;
    const FixedLenSEnumFc<UserMixinsT>& asFixedLenSEnum() const noexcept;
    FixedLenUEnumFc<UserMixinsT>& asFixedLenUEnum() noexcept;
    const FixedLenUEnumFc<UserMixinsT>& asFixedLenUEnum() const noexcept;
    VarLenIntFc<UserMixinsT>& asVarLenInt() noexcept;
    const VarLenIntFc<UserMixinsT>& asVarLenInt() const noexcept;
    VarLenUIntFc<UserMixinsT>& asVarLenUInt() noexcept;
    const VarLenUIntFc<UserMixinsT>& asVarLenUInt() const noexcept;
    VarLenSIntFc<UserMixinsT>& asVarLenSInt() noexcept;
    const VarLenSIntFc<UserMixinsT>& asVarLenSInt() const noexcept;
    VarLenUEnumFc<UserMixinsT>& asVarLenUEnum() noexcept;
    const VarLenUEnumFc<UserMixinsT>& asVarLenUEnum() const noexcept;
    VarLenSEnumFc<UserMixinsT>& asVarLenSEnum() noexcept;
    const VarLenSEnumFc<UserMixinsT>& asVarLenSEnum() const noexcept;
    NullTerminatedStrFc<UserMixinsT>& asNullTerminatedStr() noexcept;
    const NullTerminatedStrFc<UserMixinsT>& asNullTerminatedStr() const noexcept;
    NonNullTerminatedStrFc<UserMixinsT>& asNonNullTerminatedStr() noexcept;
    const NonNullTerminatedStrFc<UserMixinsT>& asNonNullTerminatedStr() const noexcept;
    StaticLenStrFc<UserMixinsT>& asStaticLenStr() noexcept;
    const StaticLenStrFc<UserMixinsT>& asStaticLenStr() const noexcept;
    DynLenStrFc<UserMixinsT>& asDynLenStr() noexcept;
    const DynLenStrFc<UserMixinsT>& asDynLenStr() const noexcept;
    BlobFc<UserMixinsT>& asBlob() noexcept;
    const BlobFc<UserMixinsT>& asBlob() const noexcept;
    StaticLenBlobFc<UserMixinsT>& asStaticLenBlob() noexcept;
    const StaticLenBlobFc<UserMixinsT>& asStaticLenBlob() const noexcept;
    DynLenBlobFc<UserMixinsT>& asDynLenBlob() noexcept;
    const DynLenBlobFc<UserMixinsT>& asDynLenBlob() const noexcept;
    ArrayFc<UserMixinsT>& asArray() noexcept;
    const ArrayFc<UserMixinsT>& asArray() const noexcept;
    StaticLenArrayFc<UserMixinsT>& asStaticLenArray() noexcept;
    const StaticLenArrayFc<UserMixinsT>& asStaticLenArray() const noexcept;
    DynLenArrayFc<UserMixinsT>& asDynLenArray() noexcept;
    const DynLenArrayFc<UserMixinsT>& asDynLenArray() const noexcept;
    StructFc<UserMixinsT>& asStruct() noexcept;
    const StructFc<UserMixinsT>& asStruct() const noexcept;
    OptionalFc<UserMixinsT>& asOptional() noexcept;
    const OptionalFc<UserMixinsT>& asOptional() const noexcept;
    OptionalWithBoolSelFc<UserMixinsT>& asOptionalWithBoolSel() noexcept;
    const OptionalWithBoolSelFc<UserMixinsT>& asOptionalWithBoolSel() const noexcept;
    OptionalWithUIntSelFc<UserMixinsT>& asOptionalWithUIntSel() noexcept;
    const OptionalWithUIntSelFc<UserMixinsT>& asOptionalWithUIntSel() const noexcept;
    OptionalWithSIntSelFc<UserMixinsT>& asOptionalWithSIntSel() noexcept;
    const OptionalWithSIntSelFc<UserMixinsT>& asOptionalWithSIntSel() const noexcept;
    VariantWithUIntSelFc<UserMixinsT>& asVariantWithUIntSel() noexcept;
    const VariantWithUIntSelFc<UserMixinsT>& asVariantWithUIntSel() const noexcept;
    VariantWithSIntSelFc<UserMixinsT>& asVariantWithSIntSel() noexcept;
    const VariantWithSIntSelFc<UserMixinsT>& asVariantWithSIntSel() const noexcept;

    bool isFixedLenBitArray() const noexcept
    {
        return this->_hasTypeTrait(FcTypeTraits::FIXED_OR_STATIC_LEN | FcTypeTraits::BIT_ARRAY);
    }

    bool isFixedLenBool() const noexcept
    {
        return this->_mType == Type::FIXED_LEN_BOOL;
    }

    bool isFixedLenFloat() const noexcept
    {
        return this->_mType == Type::FIXED_LEN_FLOAT;
    }

    bool isInt() const noexcept
    {
        return this->_hasTypeTrait(FcTypeTraits::INT);
    }

    bool isUInt() const noexcept
    {
        return this->_hasTypeTrait(FcTypeTraits::UINT);
    }

    bool isSInt() const noexcept
    {
        return this->_hasTypeTrait(FcTypeTraits::SINT);
    }

    bool isFixedLenInt() const noexcept
    {
        return this->_hasTypeTrait(FcTypeTraits::FIXED_OR_STATIC_LEN | FcTypeTraits::INT);
    }

    bool isFixedLenUInt() const noexcept
    {
        return this->_hasTypeTrait(FcTypeTraits::FIXED_OR_STATIC_LEN | FcTypeTraits::UINT);
    }

    bool isFixedLenSInt() const noexcept
    {
        return this->_hasTypeTrait(FcTypeTraits::FIXED_OR_STATIC_LEN | FcTypeTraits::SINT);
    }

    bool isEnum() const noexcept
    {
        return this->_hasTypeTrait(FcTypeTraits::ENUM);
    }

    bool isFixedLenEnum() const noexcept
    {
        return this->_hasTypeTrait(FcTypeTraits::FIXED_OR_STATIC_LEN | FcTypeTraits::ENUM);
    }

    bool isFixedLenUEnum() const noexcept
    {
        return _mType == Type::FIXED_LEN_UENUM;
    }

    bool isFixedLenSEnum() const noexcept
    {
        return _mType == Type::FIXED_LEN_SENUM;
    }

    bool isVarLenInt() const noexcept
    {
        return this->_hasTypeTrait(FcTypeTraits::VAR_OR_DYN_LEN | FcTypeTraits::INT);
    }

    bool isVarLenUInt() const noexcept
    {
        return this->_hasTypeTrait(FcTypeTraits::VAR_OR_DYN_LEN | FcTypeTraits::UINT);
    }

    bool isVarLenSInt() const noexcept
    {
        return this->_hasTypeTrait(FcTypeTraits::VAR_OR_DYN_LEN | FcTypeTraits::SINT);
    }

    bool isVarLenEnum() const noexcept
    {
        return this->_hasTypeTrait(FcTypeTraits::VAR_OR_DYN_LEN | FcTypeTraits::ENUM);
    }

    bool isVarLenUEnum() const noexcept
    {
        return _mType == Type::VAR_LEN_UENUM;
    }

    bool isVarLenSEnum() const noexcept
    {
        return _mType == Type::VAR_LEN_SENUM;
    }

    bool isNullTerminatedStr() const noexcept
    {
        return _mType == Type::NULL_TERMINATED_STR;
    }

    bool isNonNullTerminatedStr() const noexcept
    {
        return this->_hasTypeTrait(FcTypeTraits::NON_NULL_TERMINATED);
    }

    bool isStaticLenStr() const noexcept
    {
        return _mType == Type::STATIC_LEN_STR;
    }

    bool isDynLenStr() const noexcept
    {
        return _mType == Type::DYN_LEN_STR;
    }

    bool isBlob() const noexcept
    {
        return this->_hasTypeTrait(FcTypeTraits::BLOB);
    }

    bool isStaticLenBlob() const noexcept
    {
        return _mType == Type::STATIC_LEN_BLOB;
    }

    bool isDynLenBlob() const noexcept
    {
        return _mType == Type::DYN_LEN_BLOB;
    }

    bool isArray() const noexcept
    {
        return this->_hasTypeTrait(FcTypeTraits::ARRAY);
    }

    bool isStaticLenArray() const noexcept
    {
        return _mType == Type::STATIC_LEN_ARRAY;
    }

    bool isDynLenArray() const noexcept
    {
        return _mType == Type::DYN_LEN_ARRAY;
    }

    bool isStruct() const noexcept
    {
        return _mType == Type::STRUCT;
    }

    bool isOptional() const noexcept
    {
        return this->_hasTypeTrait(FcTypeTraits::OPTION);
    }

    bool isOptionalWithBoolSel() const noexcept
    {
        return _mType == Type::OPTIONAL_WITH_BOOL_SEL;
    }

    bool isOptionalWithIntSel() const noexcept
    {
        return this->_hasTypeTrait(FcTypeTraits::OPTION | FcTypeTraits::INT_SEL);
    }

    bool isOptionalWithUIntSel() const noexcept
    {
        return _mType == Type::OPTIONAL_WITH_UINT_SEL;
    }

    bool isOptionalWithSIntSel() const noexcept
    {
        return _mType == Type::OPTIONAL_WITH_SINT_SEL;
    }

    bool isVariant() const noexcept
    {
        return this->_hasTypeTrait(FcTypeTraits::VARIANT);
    }

    bool isVariantWithUIntSel() const noexcept
    {
        return _mType == Type::VARIANT_WITH_UINT_SEL;
    }

    bool isVariantWithSIntSel() const noexcept
    {
        return _mType == Type::VARIANT_WITH_SINT_SEL;
    }

private:
    /*
     * Returns whether or not this field class has the type trait
     * `typeTrait` (one or more bitwise-OR combined `FcTypeTraits`
     * enumerators).
     */
    bool _hasTypeTrait(const int typeTrait) const noexcept
    {
        return (static_cast<int>(_mType) & typeTrait) == typeTrait;
    }

    /* Type of this field class */
    Type _mType;

    /* Alignment (bits) of instances of this field class */
    unsigned int _mAlign;
};

/*
 * Byte order.
 */
enum class ByteOrder
{
    /* Big-endian */
    BIG,

    /* Little-endian */
    LITTLE,
};

/*
 * Fixed-length bit array field class.
 *
 * Specific properties over `Fc<UserMixinsT>`:
 *
 * • Length of instances
 * • Byte order of instances
 */
template <typename UserMixinsT>
class FixedLenBitArrayFc : public Fc<UserMixinsT>, public UserMixinsT::FixedLenBitArrayFc
{
protected:
    explicit FixedLenBitArrayFc(const FcType type, typename UserMixinsT::Fc fcMixin,
                                typename UserMixinsT::FixedLenBitArrayFc mixin,
                                const unsigned int align, const bt2c::DataLen len,
                                const ByteOrder byteOrder, OptUserAttrs&& userAttrs) :
        Fc<UserMixinsT> {type, std::move(fcMixin), align, std::move(userAttrs)},
        UserMixinsT::FixedLenBitArrayFc {std::move(mixin)}, _mLen {len}, _mByteOrder {byteOrder}
    {
        using namespace bt2c::literals::datalen;

        BT_ASSERT(len > 0_bits && len <= 64_bits);
        BT_ASSERT(align > 0);
    }

public:
    explicit FixedLenBitArrayFc(typename UserMixinsT::Fc fcMixin,
                                typename UserMixinsT::FixedLenBitArrayFc mixin,
                                const unsigned int align, const bt2c::DataLen len,
                                const ByteOrder byteOrder,
                                OptUserAttrs userAttrs = OptUserAttrs {}) :
        FixedLenBitArrayFc {FcType::FIXED_LEN_BIT_ARRAY,
                            std::move(fcMixin),
                            std::move(mixin),
                            align,
                            len,
                            byteOrder,
                            std::move(userAttrs)}
    {
    }

    /*
     * Length of instances of this field class.
     */
    bt2c::DataLen len() const noexcept
    {
        return _mLen;
    }

    /*
     * Byte order of instances of this field class.
     */
    ByteOrder byteOrder() const noexcept
    {
        return _mByteOrder;
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<FixedLenBitArrayFc>(*this, *this, this->align(), _mLen,
                                                     _mByteOrder, this->userAttrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }

private:
    /* Length of instances of this field class */
    bt2c::DataLen _mLen;

    /* Byte order of instances of this field class */
    ByteOrder _mByteOrder;
};

/*
 * Fixed-length boolean field class.
 */
template <typename UserMixinsT>
class FixedLenBoolFc : public FixedLenBitArrayFc<UserMixinsT>, public UserMixinsT::FixedLenBoolFc
{
public:
    explicit FixedLenBoolFc(typename UserMixinsT::Fc fcMixin,
                            typename UserMixinsT::FixedLenBitArrayFc fixedLenBitArrayFcMixin,
                            typename UserMixinsT::FixedLenBoolFc mixin, const unsigned int align,
                            const bt2c::DataLen len, const ByteOrder byteOrder,
                            OptUserAttrs userAttrs = OptUserAttrs {}) :
        FixedLenBitArrayFc<UserMixinsT> {FcType::FIXED_LEN_BOOL,
                                         std::move(fcMixin),
                                         std::move(fixedLenBitArrayFcMixin),
                                         align,
                                         len,
                                         byteOrder,
                                         std::move(userAttrs)},
        UserMixinsT::FixedLenBoolFc {std::move(mixin)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<FixedLenBoolFc>(*this, *this, *this, this->align(), this->len(),
                                                 this->byteOrder(), this->userAttrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Fixed-length floating-point number field class.
 */
template <typename UserMixinsT>
class FixedLenFloatFc : public FixedLenBitArrayFc<UserMixinsT>
{
public:
    explicit FixedLenFloatFc(typename UserMixinsT::Fc fcMixin,
                             typename UserMixinsT::FixedLenBitArrayFc fixedLenBitArrayFcMixin,
                             const unsigned int align, const bt2c::DataLen len,
                             const ByteOrder byteOrder, OptUserAttrs userAttrs = OptUserAttrs {}) :
        FixedLenBitArrayFc<UserMixinsT> {FcType::FIXED_LEN_FLOAT,
                                         std::move(fcMixin),
                                         std::move(fixedLenBitArrayFcMixin),
                                         align,
                                         len,
                                         byteOrder,
                                         std::move(userAttrs)}
    {
        using namespace bt2c::literals::datalen;

        BT_ASSERT(len == 32_bits || len == 64_bits);
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<FixedLenFloatFc>(*this, *this, this->align(), this->len(),
                                                  this->byteOrder(), this->userAttrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Display base.
 */
enum class DispBase
{
    /* Binary */
    BIN = 2,

    /* Octal */
    OCT = 8,

    /* Decimal */
    DEC = 10,

    /* Hexadecimal */
    HEX = 16,
};

namespace internal {

/*
 * Internal mixin for integer field class classes.
 */
class IntFcMixin
{
public:
    explicit IntFcMixin(const DispBase prefDispBase) : _mPrefDispBase {prefDispBase}
    {
    }

    /*
     * Preferred display base of instances of this field class.
     */
    DispBase prefDispBase() const noexcept
    {
        return _mPrefDispBase;
    }

private:
    /* Preferred display base of instances of this field class */
    DispBase _mPrefDispBase;
};

} /* namespace internal */

/*
 * Fixed-length integer field class base.
 *
 * The only specific property over `FixedLenBitArrayFc<UserMixinsT>` is
 * the preferred display base of field class instances.
 */
template <typename UserMixinsT>
class FixedLenIntFc :
    public FixedLenBitArrayFc<UserMixinsT>,
    public internal::IntFcMixin,
    public UserMixinsT::FixedLenIntFc
{
protected:
    explicit FixedLenIntFc(const FcType type, typename UserMixinsT::Fc fcMixin,
                           typename UserMixinsT::FixedLenBitArrayFc fixedLenBitArrayFcMixin,
                           typename UserMixinsT::FixedLenIntFc mixin, const unsigned int align,
                           const bt2c::DataLen len, const ByteOrder byteOrder,
                           const DispBase prefDispBase, OptUserAttrs&& userAttrs) :
        FixedLenBitArrayFc<UserMixinsT> {
            type,      std::move(fcMixin),  std::move(fixedLenBitArrayFcMixin), align, len,
            byteOrder, std::move(userAttrs)},
        internal::IntFcMixin {prefDispBase}, UserMixinsT::FixedLenIntFc {std::move(mixin)}
    {
    }
};

/* clang-format off */

/*
 * Unsigned integer field role.
 */
enum class UIntFieldRole
{
    /* Packet magic number */
    PKT_MAGIC_NUMBER                    = 1 << 1,

    /* Data stream class ID */
    DATA_STREAM_CLS_ID                  = 1 << 2,

    /* Data stream ID */
    DATA_STREAM_ID                      = 1 << 3,

    /* Total length of packet */
    PKT_TOTAL_LEN                       = 1 << 4,

    /* Content length of packet */
    PKT_CONTENT_LEN                     = 1 << 5,

    /* Default clock timestamp */
    DEF_CLK_TS                          = 1 << 6,

    /* Default clock timestamp at end of packet */
    PKT_END_DEF_CLK_TS                  = 1 << 7,

    /* Discarded event record counter snapshot */
    DISC_EVENT_RECORD_COUNTER_SNAP      = 1 << 8,

    /* Packet sequence number */
    PKT_SEQ_NUM                         = 1 << 9,

    /* Event record class ID */
    EVENT_RECORD_CLS_ID                 = 1 << 10,
};
/* clang-format on */

/*
 * Set of unsigned integer field roles.
 */
using UIntFieldRoles = std::set<UIntFieldRole>;

namespace internal {

/*
 * Internal mixin for unsigned integer field class classes.
 */
class UIntFcMixin
{
private:
    using _Roles = std::vector<UIntFieldRole>;

public:
    explicit UIntFcMixin(const UIntFieldRoles& roles)
    {
        std::copy(roles.begin(), roles.end(), std::back_inserter(_mRoles));
    }

    /*
     * Roles of instances of this field class.
     */
    const _Roles& roles() const noexcept
    {
        return _mRoles;
    }

    /*
     * Roles of instances of this field class.
     */
    _Roles& roles() noexcept
    {
        return _mRoles;
    }

    /*
     * Returns whether or not the instances of this field class have the
     * role `role`.
     */
    bool hasRole(const UIntFieldRole role) const noexcept
    {
        return std::find(_mRoles.begin(), _mRoles.end(), role) != _mRoles.end();
    }

protected:
    UIntFieldRoles _rolesAsSet() const
    {
        UIntFieldRoles roles;

        std::copy(_mRoles.begin(), _mRoles.end(), std::inserter(roles, roles.end()));
        return roles;
    }

private:
    _Roles _mRoles;
};

} /* namespace internal */

/*
 * Fixed-length unsigned integer field class.
 *
 * The only specific property over `FixedLenIntFc<UserMixinsT>` is the
 * roles of field class instances.
 */
template <typename UserMixinsT>
class FixedLenUIntFc :
    public FixedLenIntFc<UserMixinsT>,
    public internal::UIntFcMixin,
    public UserMixinsT::FixedLenUIntFc
{
protected:
    explicit FixedLenUIntFc(const FcType type, typename UserMixinsT::Fc fcMixin,
                            typename UserMixinsT::FixedLenBitArrayFc fixedLenBitArrayFcMixin,
                            typename UserMixinsT::FixedLenIntFc fixedLenIntFcMixin,
                            typename UserMixinsT::FixedLenUIntFc mixin, const unsigned int align,
                            const bt2c::DataLen len, const ByteOrder byteOrder,
                            const DispBase prefDispBase, UIntFieldRoles&& roles,
                            OptUserAttrs&& userAttrs) :
        FixedLenIntFc<UserMixinsT> {type,
                                    std::move(fcMixin),
                                    std::move(fixedLenBitArrayFcMixin),
                                    std::move(fixedLenIntFcMixin),
                                    align,
                                    len,
                                    byteOrder,
                                    prefDispBase,
                                    std::move(userAttrs)},
        internal::UIntFcMixin {roles}, UserMixinsT::FixedLenUIntFc {std::move(mixin)}
    {
    }

public:
    explicit FixedLenUIntFc(typename UserMixinsT::Fc fcMixin,
                            typename UserMixinsT::FixedLenBitArrayFc fixedLenBitArrayFcMixin,
                            typename UserMixinsT::FixedLenIntFc fixedLenIntFcMixin,
                            typename UserMixinsT::FixedLenUIntFc mixin, const unsigned int align,
                            const bt2c::DataLen len, const ByteOrder byteOrder,
                            const DispBase prefDispBase = DispBase::DEC, UIntFieldRoles roles = {},
                            OptUserAttrs userAttrs = OptUserAttrs {}) :
        FixedLenUIntFc {FcType::FIXED_LEN_UINT,
                        std::move(fcMixin),
                        std::move(fixedLenBitArrayFcMixin),
                        std::move(fixedLenIntFcMixin),
                        std::move(mixin),
                        align,
                        len,
                        byteOrder,
                        prefDispBase,
                        std::move(roles),
                        std::move(userAttrs)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<FixedLenUIntFc>(
            *this, *this, *this, *this, this->align(), this->len(), this->byteOrder(),
            this->prefDispBase(), this->_rolesAsSet(), this->userAttrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Fixed-length signed integer field class.
 */
template <typename UserMixinsT>
class FixedLenSIntFc : public FixedLenIntFc<UserMixinsT>
{
protected:
    explicit FixedLenSIntFc(const FcType type, typename UserMixinsT::Fc fcMixin,
                            typename UserMixinsT::FixedLenBitArrayFc fixedLenBitArrayFcMixin,
                            typename UserMixinsT::FixedLenIntFc fixedLenIntFcMixin,
                            const unsigned int align, const bt2c::DataLen len,
                            const ByteOrder byteOrder, const DispBase prefDispBase,
                            OptUserAttrs&& userAttrs) :
        FixedLenIntFc<UserMixinsT> {type,
                                    std::move(fcMixin),
                                    std::move(fixedLenBitArrayFcMixin),
                                    std::move(fixedLenIntFcMixin),
                                    align,
                                    len,
                                    byteOrder,
                                    prefDispBase,
                                    std::move(userAttrs)}
    {
    }

public:
    explicit FixedLenSIntFc(typename UserMixinsT::Fc fcMixin,
                            typename UserMixinsT::FixedLenBitArrayFc fixedLenBitArrayFcMixin,
                            typename UserMixinsT::FixedLenIntFc fixedLenIntFcMixin,
                            const unsigned int align, const bt2c::DataLen len,
                            const ByteOrder byteOrder, const DispBase prefDispBase = DispBase::DEC,
                            OptUserAttrs userAttrs = OptUserAttrs {}) :
        FixedLenSIntFc {FcType::FIXED_LEN_SINT,
                        std::move(fcMixin),
                        std::move(fixedLenBitArrayFcMixin),
                        std::move(fixedLenIntFcMixin),
                        align,
                        len,
                        byteOrder,
                        prefDispBase,
                        std::move(userAttrs)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<FixedLenSIntFc>(*this, *this, *this, this->align(), this->len(),
                                                 this->byteOrder(), this->prefDispBase(),
                                                 this->userAttrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

namespace internal {

/*
 * Internal mixin for enumeration field class classes having
 * `IntRangeSetT` as their integer range set type.
 */
template <typename IntRangeSetT>
class EnumFcMixin
{
public:
    using Mappings = std::unordered_map<std::string, IntRangeSetT>;
    using Val = typename IntRangeSetT::Val;

protected:
    explicit EnumFcMixin(Mappings&& mappings) : _mMappings {std::move(mappings)}
    {
        BT_ASSERT(!_mMappings.empty());
    }

public:
    /*
     * Mappings of this enumeration field class.
     */
    const Mappings& mappings() const noexcept
    {
        return _mMappings;
    }

private:
    Mappings _mMappings;
};

} /* namespace internal */

/*
 * Fixed-length unsigned enumeration field class.
 *
 * The only specific property over `FixedLenUIntFc<UserMixinsT>` is the
 * mappings of the field class.
 */
template <typename UserMixinsT>
class FixedLenUEnumFc :
    public FixedLenUIntFc<UserMixinsT>,
    public internal::EnumFcMixin<UIntRangeSet>
{
public:
    explicit FixedLenUEnumFc(typename UserMixinsT::Fc fcMixin,
                             typename UserMixinsT::FixedLenBitArrayFc fixedLenBitArrayFcMixin,
                             typename UserMixinsT::FixedLenIntFc fixedLenIntFcMixin,
                             typename UserMixinsT::FixedLenUIntFc fixedLenUIntFcMixin,
                             const unsigned int align, const bt2c::DataLen len,
                             const ByteOrder byteOrder, Mappings mappings,
                             const DispBase prefDispBase = DispBase::DEC, UIntFieldRoles roles = {},
                             OptUserAttrs userAttrs = OptUserAttrs {}) :
        FixedLenUIntFc<UserMixinsT> {FcType::FIXED_LEN_UENUM,
                                     std::move(fcMixin),
                                     std::move(fixedLenBitArrayFcMixin),
                                     std::move(fixedLenIntFcMixin),
                                     std::move(fixedLenUIntFcMixin),
                                     align,
                                     len,
                                     byteOrder,
                                     prefDispBase,
                                     std::move(roles),
                                     std::move(userAttrs)},
        internal::EnumFcMixin<UIntRangeSet> {std::move(mappings)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<FixedLenUEnumFc>(
            *this, *this, *this, *this, this->align(), this->len(), this->byteOrder(),
            this->mappings(), this->prefDispBase(), this->_rolesAsSet(), this->userAttrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Fixed-length signed enumeration field class.
 *
 * The only specific property over `FixedLenSIntFc<UserMixinsT>` is the
 * mappings of the field class.
 */
template <typename UserMixinsT>
class FixedLenSEnumFc :
    public FixedLenSIntFc<UserMixinsT>,
    public internal::EnumFcMixin<SIntRangeSet>
{
public:
    explicit FixedLenSEnumFc(typename UserMixinsT::Fc fcMixin,
                             typename UserMixinsT::FixedLenBitArrayFc fixedLenBitArrayFcMixin,
                             typename UserMixinsT::FixedLenIntFc fixedLenIntFcMixin,
                             const unsigned int align, const bt2c::DataLen len,
                             const ByteOrder byteOrder, Mappings mappings,
                             const DispBase prefDispBase = DispBase::DEC,
                             OptUserAttrs userAttrs = OptUserAttrs {}) :
        FixedLenSIntFc<UserMixinsT> {FcType::FIXED_LEN_SENUM,
                                     std::move(fcMixin),
                                     std::move(fixedLenBitArrayFcMixin),
                                     std::move(fixedLenIntFcMixin),
                                     align,
                                     len,
                                     byteOrder,
                                     prefDispBase,
                                     std::move(userAttrs)},
        internal::EnumFcMixin<SIntRangeSet> {std::move(mappings)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<FixedLenSEnumFc>(*this, *this, *this, this->align(), this->len(),
                                                  this->byteOrder(), this->mappings(),
                                                  this->prefDispBase(), this->userAttrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Variable-length integer field class base.
 *
 * The only specific property over `Fc<UserMixinsT>` is the preferred
 * display base of field class instances.
 */
template <typename UserMixinsT>
class VarLenIntFc :
    public Fc<UserMixinsT>,
    public internal::IntFcMixin,
    public UserMixinsT::VarLenIntFc
{
protected:
    explicit VarLenIntFc(const FcType type, typename UserMixinsT::Fc fcMixin,
                         typename UserMixinsT::VarLenIntFc mixin, const DispBase prefDispBase,
                         OptUserAttrs&& userAttrs) :
        Fc<UserMixinsT> {type, std::move(fcMixin), 8, std::move(userAttrs)},
        internal::IntFcMixin {prefDispBase}, UserMixinsT::VarLenIntFc {std::move(mixin)}
    {
    }
};

/*
 * Variable-length unsigned integer field class.
 *
 * The only specific property over `VarLenIntFc<UserMixinsT>` is the
 * roles of field class instances.
 */
template <typename UserMixinsT>
class VarLenUIntFc :
    public VarLenIntFc<UserMixinsT>,
    public internal::UIntFcMixin,
    public UserMixinsT::VarLenUIntFc
{
protected:
    explicit VarLenUIntFc(const FcType type, typename UserMixinsT::Fc fcMixin,
                          typename UserMixinsT::VarLenIntFc fixedLenIntFcMixin,
                          typename UserMixinsT::VarLenUIntFc mixin, const DispBase prefDispBase,
                          UIntFieldRoles&& roles, OptUserAttrs&& userAttrs) :
        VarLenIntFc<UserMixinsT> {type, std::move(fcMixin), std::move(fixedLenIntFcMixin),
                                  prefDispBase, std::move(userAttrs)},
        internal::UIntFcMixin {roles}, UserMixinsT::VarLenUIntFc {std::move(mixin)}
    {
    }

public:
    explicit VarLenUIntFc(typename UserMixinsT::Fc fcMixin,
                          typename UserMixinsT::VarLenIntFc fixedLenIntFcMixin,
                          typename UserMixinsT::VarLenUIntFc mixin,
                          const DispBase prefDispBase = DispBase::DEC, UIntFieldRoles roles = {},
                          OptUserAttrs userAttrs = OptUserAttrs {}) :
        VarLenUIntFc {FcType::VAR_LEN_UINT, std::move(fcMixin), std::move(fixedLenIntFcMixin),
                      std::move(mixin),     prefDispBase,       std::move(roles),
                      std::move(userAttrs)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<VarLenUIntFc>(*this, *this, *this, this->prefDispBase(),
                                               this->_rolesAsSet(), this->userAttrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Variable-length signed integer field class.
 */
template <typename UserMixinsT>
class VarLenSIntFc : public VarLenIntFc<UserMixinsT>
{
protected:
    explicit VarLenSIntFc(const FcType type, typename UserMixinsT::Fc fcMixin,
                          typename UserMixinsT::VarLenIntFc fixedLenIntFcMixin,
                          const DispBase prefDispBase, OptUserAttrs&& userAttrs) :
        VarLenIntFc<UserMixinsT> {type, std::move(fcMixin), std::move(fixedLenIntFcMixin),
                                  prefDispBase, std::move(userAttrs)}
    {
    }

public:
    explicit VarLenSIntFc(typename UserMixinsT::Fc fcMixin,
                          typename UserMixinsT::VarLenIntFc fixedLenIntFcMixin,
                          const DispBase prefDispBase = DispBase::DEC,
                          OptUserAttrs userAttrs = OptUserAttrs {}) :
        VarLenSIntFc {FcType::VAR_LEN_SINT, std::move(fcMixin), std::move(fixedLenIntFcMixin),
                      prefDispBase, std::move(userAttrs)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<VarLenSIntFc>(*this, *this, this->prefDispBase(),
                                               this->userAttrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Variable-length unsigned enumeration field class base.
 *
 * The only specific property over `VarLenUIntFc<UserMixinsT>` is the
 * mappings of the field class.
 */
template <typename UserMixinsT>
class VarLenUEnumFc : public VarLenUIntFc<UserMixinsT>, public internal::EnumFcMixin<UIntRangeSet>
{
public:
    explicit VarLenUEnumFc(typename UserMixinsT::Fc fcMixin,
                           typename UserMixinsT::VarLenIntFc varLenIntFcMixin,
                           typename UserMixinsT::VarLenUIntFc varLenUIntFcMixin, Mappings mappings,
                           const DispBase prefDispBase = DispBase::DEC, UIntFieldRoles roles = {},
                           OptUserAttrs userAttrs = OptUserAttrs {}) :
        VarLenUIntFc<UserMixinsT> {
            FcType::VAR_LEN_UENUM,        std::move(fcMixin), std::move(varLenIntFcMixin),
            std::move(varLenUIntFcMixin), prefDispBase,       std::move(roles),
            std::move(userAttrs)},
        internal::EnumFcMixin<UIntRangeSet> {std::move(mappings)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<VarLenUEnumFc>(*this, *this, *this, this->mappings(),
                                                this->prefDispBase(), this->_rolesAsSet(),
                                                this->userAttrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Variable-length signed enumeration field class base.
 *
 * The only specific property over `VarLenSIntFc<UserMixinsT>` is the
 * mappings of the field class.
 */
template <typename UserMixinsT>
class VarLenSEnumFc : public VarLenSIntFc<UserMixinsT>, public internal::EnumFcMixin<SIntRangeSet>
{
public:
    explicit VarLenSEnumFc(typename UserMixinsT::Fc fcMixin,
                           typename UserMixinsT::VarLenIntFc varLenIntFcMixin, Mappings mappings,
                           const DispBase prefDispBase = DispBase::DEC,
                           OptUserAttrs userAttrs = OptUserAttrs {}) :
        VarLenSIntFc<UserMixinsT> {FcType::VAR_LEN_SENUM, std::move(fcMixin),
                                   std::move(varLenIntFcMixin), prefDispBase, std::move(userAttrs)},
        internal::EnumFcMixin<SIntRangeSet> {std::move(mappings)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<VarLenSEnumFc>(*this, *this, this->mappings(),
                                                this->prefDispBase(), this->userAttrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Null-terminated string field class.
 */
template <typename UserMixinsT>
class NullTerminatedStrFc : public Fc<UserMixinsT>
{
public:
    explicit NullTerminatedStrFc(typename UserMixinsT::Fc fcMixin,
                                 OptUserAttrs userAttrs = OptUserAttrs {}) :
        Fc<UserMixinsT> {FcType::NULL_TERMINATED_STR, std::move(fcMixin), 8, std::move(userAttrs)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<NullTerminatedStrFc>(*this, this->userAttrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Field location scope.
 */
enum class FieldLocScope
{
    /* Packet header */
    PKT_HEADER,

    /* Packet context */
    PKT_CTX,

    /* Event record header */
    EVENT_RECORD_HEADER,

    /* Common event record context */
    EVENT_RECORD_COMMON_CTX,

    /* Specific event record context */
    EVENT_RECORD_SPEC_CTX,

    /* Event record payload */
    EVENT_RECORD_PAYLOAD,
};

/*
 * Field location.
 */
template <typename UserMixinsT>
class FieldLoc : public UserMixinsT::FieldLoc
{
public:
    using Items = std::vector<std::string>;

    explicit FieldLoc(typename UserMixinsT::FieldLoc mixin, const FieldLocScope scope,
                      Items items) :
        UserMixinsT::FieldLoc {std::move(mixin)},
        _mScope {scope}, _mItems {std::move(items)}
    {
    }

    /* Use default copy/move operations */
    FieldLoc(const FieldLoc&) = default;
    FieldLoc& operator=(const FieldLoc&) = default;
    FieldLoc(FieldLoc&&) = default;
    FieldLoc& operator=(FieldLoc&&) = default;

    /*
     * Scope of this field location.
     */
    FieldLocScope scope() const noexcept
    {
        return _mScope;
    }

    /*
     * Path item of this field location.
     */
    const Items& items() const noexcept
    {
        return _mItems;
    }

    Items::const_reference operator[](const Items::size_type index) const noexcept
    {
        return _mItems[index];
    }

    Items::size_type size() const noexcept
    {
        return _mItems.size();
    }

    Items::const_iterator begin() const noexcept
    {
        return _mItems.begin();
    }

    Items::const_iterator end() const noexcept
    {
        return _mItems.end();
    }

private:
    /* Scope of this field location */
    FieldLocScope _mScope;

    /* Path items of this field location */
    Items _mItems;
};

namespace internal {

/*
 * Internal mixin for static-length field class classes.
 */
class StaticLenFcMixin
{
public:
    explicit StaticLenFcMixin(const std::size_t len) : _mLen {len}
    {
    }

    /*
     * Length (bytes or elements) of instances of this field class.
     */
    std::size_t len() const noexcept
    {
        return _mLen;
    }

private:
    /* Length of instances of this field class */
    std::size_t _mLen;
};

/*
 * Internal mixin for dynamic-length field class classes.
 */
template <typename UserMixinsT>
class DynLenFcMixin
{
public:
    explicit DynLenFcMixin(FieldLoc<UserMixinsT> lenFieldLoc) :
        _mLenFieldLoc {std::move(lenFieldLoc)}
    {
    }

    /*
     * Length field location of instances of this field class.
     */
    const FieldLoc<UserMixinsT>& lenFieldLoc() const noexcept
    {
        return _mLenFieldLoc;
    }

private:
    /* Length field location of instances of this field class */
    FieldLoc<UserMixinsT> _mLenFieldLoc;
};

} /* namespace internal */

/*
 * Non-null-terminated string field class base.
 */
template <typename UserMixinsT>
class NonNullTerminatedStrFc : public Fc<UserMixinsT>
{
protected:
    explicit NonNullTerminatedStrFc(const FcType type, typename UserMixinsT::Fc fcMixin,
                                    OptUserAttrs&& userAttrs) :
        Fc<UserMixinsT> {type, std::move(fcMixin), 8, std::move(userAttrs)}
    {
    }
};

/*
 * Static-length string field class.
 *
 * The only specific property over `NonNullTerminatedStrFc<UserMixinsT>`
 * is the length (number of bytes) of field class instances.
 */
template <typename UserMixinsT>
class StaticLenStrFc :
    public NonNullTerminatedStrFc<UserMixinsT>,
    public internal::StaticLenFcMixin,
    public UserMixinsT::StaticLenStrFc
{
public:
    explicit StaticLenStrFc(typename UserMixinsT::Fc fcMixin,
                            typename UserMixinsT::StaticLenStrFc mixin, const std::size_t len,
                            OptUserAttrs userAttrs = OptUserAttrs {}) :
        NonNullTerminatedStrFc<UserMixinsT> {FcType::STATIC_LEN_STR, std::move(fcMixin),
                                             std::move(userAttrs)},
        internal::StaticLenFcMixin {len}, UserMixinsT::StaticLenStrFc {std::move(mixin)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<StaticLenStrFc>(*this, *this, this->len(), this->userAttrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Dynamic-length string field class.
 *
 * The only specific property over `NonNullTerminatedStrFc<UserMixinsT>`
 * is the length field location of field class instances.
 */
template <typename UserMixinsT>
class DynLenStrFc :
    public NonNullTerminatedStrFc<UserMixinsT>,
    public internal::DynLenFcMixin<UserMixinsT>,
    public UserMixinsT::DynLenStrFc
{
public:
    explicit DynLenStrFc(typename UserMixinsT::Fc fcMixin, typename UserMixinsT::DynLenStrFc mixin,
                         FieldLoc<UserMixinsT> lenFieldLoc,
                         OptUserAttrs userAttrs = OptUserAttrs {}) :
        NonNullTerminatedStrFc<UserMixinsT> {FcType::DYN_LEN_STR, std::move(fcMixin),
                                             std::move(userAttrs)},
        internal::DynLenFcMixin<UserMixinsT> {std::move(lenFieldLoc)}, UserMixinsT::DynLenStrFc {
                                                                           std::move(mixin)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<DynLenStrFc>(*this, *this, this->lenFieldLoc(), this->userAttrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * BLOB field class base.
 *
 * The only specific property over `Fc<UserMixinsT>` is the media type
 * of field class instances.
 */
template <typename UserMixinsT>
class BlobFc : public Fc<UserMixinsT>
{
protected:
    explicit BlobFc(const FcType type, typename UserMixinsT::Fc fcMixin, std::string&& mediaType,
                    OptUserAttrs&& userAttrs) :
        Fc<UserMixinsT> {type, std::move(fcMixin), 8, std::move(userAttrs)},
        _mMediaType {std::move(mediaType)}
    {
    }

public:
    /*
     * Default BLOB field class media type.
     */
    constexpr static const char *defaultMediaType = "application/octet-stream";

    /*
     * Media type of instances of this field class.
     */
    const std::string& mediaType() const noexcept
    {
        return _mMediaType;
    }

private:
    /* Media type of instances of this field class */
    std::string _mMediaType;
};

/*
 * Static-length BLOB field class.
 *
 * Specific properties over `BlobFc<UserMixinsT>`:
 *
 * • Length (number of bytes) of field class instances.
 *
 * • Whether or not field class instances have the "metadata stream
 *   UUID" role.
 */
template <typename UserMixinsT>
class StaticLenBlobFc :
    public BlobFc<UserMixinsT>,
    public internal::StaticLenFcMixin,
    public UserMixinsT::StaticLenBlobFc
{
public:
    explicit StaticLenBlobFc(typename UserMixinsT::Fc fcMixin,
                             typename UserMixinsT::StaticLenBlobFc mixin, const std::size_t len,
                             std::string mediaType = StaticLenBlobFc::defaultMediaType,
                             const bool hasMetadataStreamUuidRole = false,
                             OptUserAttrs userAttrs = OptUserAttrs {}) :
        BlobFc<UserMixinsT> {FcType::STATIC_LEN_BLOB, std::move(fcMixin), std::move(mediaType),
                             std::move(userAttrs)},
        internal::StaticLenFcMixin {len}, UserMixinsT::StaticLenBlobFc {std::move(mixin)},
        _mHasMetadataStreamUuidRole {hasMetadataStreamUuidRole}
    {
    }

    bool hasMetadataStreamUuidRole() const noexcept
    {
        return _mHasMetadataStreamUuidRole;
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<StaticLenBlobFc>(*this, *this, this->len(), this->mediaType(),
                                                  _mHasMetadataStreamUuidRole, this->userAttrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }

private:
    bool _mHasMetadataStreamUuidRole;
};

/*
 * Dynamic-length BLOB field class.
 *
 * The only specific property over `BlobFc<UserMixinsT>` is the length
 * field location of field class instances.
 */
template <typename UserMixinsT>
class DynLenBlobFc :
    public BlobFc<UserMixinsT>,
    public internal::DynLenFcMixin<UserMixinsT>,
    public UserMixinsT::DynLenBlobFc
{
public:
    explicit DynLenBlobFc(typename UserMixinsT::Fc fcMixin,
                          typename UserMixinsT::DynLenBlobFc mixin,
                          FieldLoc<UserMixinsT> lenFieldLoc,
                          std::string mediaType = DynLenBlobFc::defaultMediaType,
                          OptUserAttrs userAttrs = OptUserAttrs {}) :
        BlobFc<UserMixinsT> {FcType::DYN_LEN_BLOB, std::move(fcMixin), std::move(mediaType),
                             std::move(userAttrs)},
        internal::DynLenFcMixin<UserMixinsT> {std::move(lenFieldLoc)}, UserMixinsT::DynLenBlobFc {
                                                                           std::move(mixin)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<DynLenBlobFc>(*this, *this, this->lenFieldLoc(), this->mediaType(),
                                               this->userAttrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Array field class base.
 *
 * Specific properties over `Fc<UserMixinsT>`:
 *
 * • Class of element fields.
 * • Minimum alignment of field class instances.
 */
template <typename UserMixinsT>
class ArrayFc : public Fc<UserMixinsT>
{
protected:
    explicit ArrayFc(const FcType type, typename UserMixinsT::Fc fcMixin,
                     typename Fc<UserMixinsT>::UP&& elemFc, const unsigned int minAlign,
                     OptUserAttrs&& userAttrs) :
        Fc<UserMixinsT> {type, std::move(fcMixin), ArrayFc::_effectiveAlign(*elemFc, minAlign),
                         std::move(userAttrs)},
        _mElemFc {std::move(elemFc)}, _mMinAlign {minAlign}
    {
        BT_ASSERT(_mElemFc);
    }

public:
    /*
     * Class of the element fields of instances of this field class.
     */
    const Fc<UserMixinsT>& elemFc() const noexcept
    {
        return *_mElemFc;
    }

    /*
     * Class of the element fields of instances of this field class.
     */
    Fc<UserMixinsT>& elemFc() noexcept
    {
        return *_mElemFc;
    }

    /*
     * Minimum alignment (bits) of instances of this field class.
     */
    unsigned int minAlign() const noexcept
    {
        return _mMinAlign;
    }

private:
    /*
     * Returns the effective alignment of an array field of which:
     *
     * • The minimum alignment is `minAlign` bits.
     * • The elements are instances of `elemFc`.
     */
    static unsigned int _effectiveAlign(const Fc<UserMixinsT>& elemFc,
                                        const unsigned int minAlign) noexcept
    {
        return std::max(elemFc.align(), minAlign);
    }

    /* Class of the element fields of instances of this field class */
    typename Fc<UserMixinsT>::UP _mElemFc;

    /* Minimum alignment (bits) of instances of this field class */
    unsigned int _mMinAlign;
};

/*
 * Static-length array field class.
 *
 * The only specific property over `ArrayFc<UserMixinsT>` is the length
 * (number of elements) of field class instances.
 */
template <typename UserMixinsT>
class StaticLenArrayFc :
    public ArrayFc<UserMixinsT>,
    public internal::StaticLenFcMixin,
    public UserMixinsT::StaticLenArrayFc
{
public:
    explicit StaticLenArrayFc(typename UserMixinsT::Fc fcMixin,
                              typename UserMixinsT::StaticLenArrayFc mixin, const std::size_t len,
                              typename Fc<UserMixinsT>::UP elemFc, const unsigned int minAlign = 1,
                              OptUserAttrs userAttrs = OptUserAttrs {}) :
        ArrayFc<UserMixinsT> {FcType::STATIC_LEN_ARRAY, std::move(fcMixin), std::move(elemFc),
                              minAlign, std::move(userAttrs)},
        internal::StaticLenFcMixin {len}, UserMixinsT::StaticLenArrayFc {std::move(mixin)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<StaticLenArrayFc>(
            *this, *this, this->len(), this->elemFc().clone(), this->minAlign(), this->userAttrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Dynamic-length array field class.
 *
 * The only specific property over `ArrayFc<UserMixinsT>` is the length
 * field location of field class instances.
 */
template <typename UserMixinsT>
class DynLenArrayFc :
    public ArrayFc<UserMixinsT>,
    public internal::DynLenFcMixin<UserMixinsT>,
    public UserMixinsT::DynLenArrayFc
{
public:
    explicit DynLenArrayFc(typename UserMixinsT::Fc fcMixin,
                           typename UserMixinsT::DynLenArrayFc mixin,
                           FieldLoc<UserMixinsT> lenFieldLoc, typename Fc<UserMixinsT>::UP elemFc,
                           const unsigned int minAlign = 1,
                           OptUserAttrs userAttrs = OptUserAttrs {}) :
        ArrayFc<UserMixinsT> {FcType::DYN_LEN_ARRAY, std::move(fcMixin), std::move(elemFc),
                              minAlign, std::move(userAttrs)},
        internal::DynLenFcMixin<UserMixinsT> {std::move(lenFieldLoc)}, UserMixinsT::DynLenArrayFc {
                                                                           std::move(mixin)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<DynLenArrayFc>(*this, *this, this->lenFieldLoc(),
                                                this->elemFc().clone(), this->minAlign(),
                                                this->userAttrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Structure field member class.
 */
template <typename UserMixinsT>
class StructFieldMemberCls :
    public internal::WithUserAttrsMixin,
    public UserMixinsT::StructFieldMemberCls
{
public:
    explicit StructFieldMemberCls(typename UserMixinsT::StructFieldMemberCls mixin,
                                  std::string name, typename Fc<UserMixinsT>::UP fc,
                                  OptUserAttrs userAttrs = OptUserAttrs {}) :
        internal::WithUserAttrsMixin {std::move(userAttrs)},
        UserMixinsT::StructFieldMemberCls {std::move(mixin)}, _mName {std::move(name)},
        _mFc {std::move(fc)}
    {
        BT_ASSERT(_mFc);
    }

    /*
     * Builds a member class from `other`, cloning its field class.
     */
    StructFieldMemberCls(const StructFieldMemberCls& other) :
        internal::WithUserAttrsMixin {other.userAttrs()},
        UserMixinsT::StructFieldMemberCls {other}, _mName {other.name()}, _mFc {other.fc().clone()}
    {
    }

    /*
     * Name of this member class.
     */
    const std::string& name() const noexcept
    {
        return _mName;
    }

    /*
     * Field class of this member class.
     */
    const Fc<UserMixinsT>& fc() const noexcept
    {
        return *_mFc;
    }

    /*
     * Field class of this member class.
     */
    Fc<UserMixinsT>& fc() noexcept
    {
        return *_mFc;
    }

private:
    std::string _mName;
    typename Fc<UserMixinsT>::UP _mFc;
};

/*
 * Structure field class.
 *
 * Specific properties over `Fc<UserMixinsT>`:
 *
 * • Minimum alignment of field class instances.
 * • Classes of members of field class instances.
 */
template <typename UserMixinsT>
class StructFc : public Fc<UserMixinsT>, public UserMixinsT::StructFc
{
public:
    using MemberClasses = std::vector<StructFieldMemberCls<UserMixinsT>>;

    explicit StructFc(typename UserMixinsT::Fc fcMixin, typename UserMixinsT::StructFc mixin,
                      MemberClasses memberClasses = {}, const unsigned int minAlign = 1,
                      OptUserAttrs userAttrs = OptUserAttrs {}) :
        Fc<UserMixinsT> {FcType::STRUCT, std::move(fcMixin),
                         StructFc::_effectiveAlign(memberClasses, minAlign), std::move(userAttrs)},
        UserMixinsT::StructFc {std::move(mixin)}, _mMemberClasses {std::move(memberClasses)},
        _mMinAlign {minAlign}
    {
    }

    /*
     * Classes of members of instances of this field class.
     */
    const MemberClasses& memberClasses() const noexcept
    {
        return _mMemberClasses;
    }

    typename MemberClasses::const_reference
    operator[](const typename MemberClasses::size_type index) const noexcept
    {
        return _mMemberClasses[index];
    }

    typename MemberClasses::reference
    operator[](const typename MemberClasses::size_type index) noexcept
    {
        return _mMemberClasses[index];
    }

    const typename MemberClasses::value_type *operator[](const std::string& name) const noexcept
    {
        return this->_memberClsByName<const typename MemberClasses::value_type>(*this, name);
    }

    typename MemberClasses::value_type *operator[](const std::string& name) noexcept
    {
        return this->_memberClsByName<typename MemberClasses::value_type>(*this, name);
    }

    typename MemberClasses::size_type size() const noexcept
    {
        return _mMemberClasses.size();
    }

    bool isEmpty() const noexcept
    {
        return _mMemberClasses.empty();
    }

    typename MemberClasses::const_iterator begin() const noexcept
    {
        return _mMemberClasses.begin();
    }

    typename MemberClasses::iterator begin() noexcept
    {
        return _mMemberClasses.begin();
    }

    typename MemberClasses::const_iterator end() const noexcept
    {
        return _mMemberClasses.end();
    }

    typename MemberClasses::iterator end() noexcept
    {
        return _mMemberClasses.end();
    }

    typename MemberClasses::const_reverse_iterator rbegin() const noexcept
    {
        return _mMemberClasses.rbegin();
    }

    typename MemberClasses::reverse_iterator rbegin() noexcept
    {
        return _mMemberClasses.rbegin();
    }

    typename MemberClasses::const_reverse_iterator rend() const noexcept
    {
        return _mMemberClasses.rend();
    }

    typename MemberClasses::reverse_iterator rend() noexcept
    {
        return _mMemberClasses.rend();
    }

    /*
     * Minimum alignment (bits) of instances of this field class.
     */
    unsigned int minAlign() const noexcept
    {
        return _mMinAlign;
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<StructFc>(*this, *this, _mMemberClasses, _mMinAlign,
                                           this->userAttrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }

private:
    /*
     * Returns the effective alignment of a structure field of which:
     *
     * • The minimum alignment is `minAlign` bits.
     * • The members are instances of `memberClasses`.
     */
    static unsigned int _effectiveAlign(const MemberClasses& memberClasses,
                                        const unsigned int minAlign) noexcept
    {
        auto align = minAlign;

        for (auto& memberCls : memberClasses) {
            align = std::max(align, memberCls.fc().align());
        }

        return align;
    }

    template <typename ValT, typename StructFcT>
    static ValT *_memberClsByName(StructFcT& structFc, const std::string& name) noexcept
    {
        for (auto& memberCls : structFc._mMemberClasses) {
            if (memberCls.name() == name) {
                return &memberCls;
            }
        }

        return nullptr;
    }

    /* Classes of members of instances of this field class */
    MemberClasses _mMemberClasses;

    /* Minimum alignment (bits) of instances of this field class */
    unsigned int _mMinAlign;
};

/*
 * Optional field class base.
 *
 * Specific properties over `Fc<UserMixinsT>`:
 *
 * • Selector field location of field class instances.
 * • Optional field of field class instances.
 */
template <typename UserMixinsT>
class OptionalFc : public Fc<UserMixinsT>, public UserMixinsT::OptionalFc
{
protected:
    explicit OptionalFc(const FcType type, typename UserMixinsT::Fc fcMixin,
                        typename UserMixinsT::OptionalFc mixin, typename Fc<UserMixinsT>::UP&& fc,
                        FieldLoc<UserMixinsT>&& selFieldLoc, OptUserAttrs&& userAttrs) :
        Fc<UserMixinsT> {type, std::move(fcMixin), 1, std::move(userAttrs)},
        UserMixinsT::OptionalFc {std::move(mixin)},
        _mSelFieldLoc {std::move(selFieldLoc)}, _mFc {std::move(fc)}
    {
    }

public:
    /*
     * Selector field location of instances of this field class.
     */
    const FieldLoc<UserMixinsT>& selFieldLoc() const noexcept
    {
        return _mSelFieldLoc;
    }

    /*
     * Class of the optional field of instances of this field class.
     */
    const Fc<UserMixinsT>& fc() const noexcept
    {
        return *_mFc;
    }

    /*
     * Class of the optional field of instances of this field class.
     */
    Fc<UserMixinsT>& fc() noexcept
    {
        return *_mFc;
    }

private:
    /* Selector field location of instances of this field class */
    FieldLoc<UserMixinsT> _mSelFieldLoc;

    /* Class of the optional field of instances of this field class */
    typename Fc<UserMixinsT>::UP _mFc;
};

/*
 * Class of optional fields with a boolean selector.
 */
template <typename UserMixinsT>
class OptionalWithBoolSelFc :
    public OptionalFc<UserMixinsT>,
    public UserMixinsT::OptionalWithBoolSelFc
{
public:
    /* Selector value type */
    using SelVal = bool;

    explicit OptionalWithBoolSelFc(typename UserMixinsT::Fc fcMixin,
                                   typename UserMixinsT::OptionalFc optionalFcMixin,
                                   typename UserMixinsT::OptionalWithBoolSelFc mixin,
                                   typename Fc<UserMixinsT>::UP fc,
                                   FieldLoc<UserMixinsT> selFieldLoc,
                                   OptUserAttrs userAttrs = OptUserAttrs {}) :
        OptionalFc<UserMixinsT> {FcType::OPTIONAL_WITH_BOOL_SEL, std::move(fcMixin),
                                 std::move(optionalFcMixin),     std::move(fc),
                                 std::move(selFieldLoc),         std::move(userAttrs)},
        UserMixinsT::OptionalWithBoolSelFc {std::move(mixin)}
    {
    }

    /*
     * Returns whether or not an instance of this field class is
     * enabled by the selector value `selVal`.
     */
    bool isEnabledBySelVal(const bool selVal) const noexcept
    {
        return selVal;
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<OptionalWithBoolSelFc>(*this, *this, *this, this->fc().clone(),
                                                        this->selFieldLoc(), this->userAttrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Base class of optional fields with an integer selector.
 *
 * `IntRangeSetT` is the integer selector range set type.
 *
 * The only specific property over `OptionalFc<UserMixinsT>` is the
 * selector field ranges which enable an instance of the field class.
 */
template <typename UserMixinsT, typename IntRangeSetT>
class OptionalWithIntSelFc :
    public OptionalFc<UserMixinsT>,
    public UserMixinsT::OptionalWithIntSelFc
{
public:
    /* Integer selector range set type */
    using SelFieldRanges = IntRangeSetT;

    /* Selector value type */
    using SelVal = typename IntRangeSetT::Val;

protected:
    explicit OptionalWithIntSelFc(const FcType type, typename UserMixinsT::Fc fcMixin,
                                  typename UserMixinsT::OptionalFc optionalFcMixin,
                                  typename UserMixinsT::OptionalWithIntSelFc mixin,
                                  typename Fc<UserMixinsT>::UP&& fc,
                                  FieldLoc<UserMixinsT>&& selFieldLoc,
                                  IntRangeSetT&& selFieldRanges, OptUserAttrs&& userAttrs) :
        OptionalFc<UserMixinsT> {type,          std::move(fcMixin),     std::move(optionalFcMixin),
                                 std::move(fc), std::move(selFieldLoc), std::move(userAttrs)},
        UserMixinsT::OptionalWithIntSelFc {std::move(mixin)}, _mSelFieldRanges {
                                                                  std::move(selFieldRanges)}
    {
    }

public:
    /*
     * Integer selector field ranges which enable an instance of this
     * field class.
     */
    const IntRangeSetT& selFieldRanges() const noexcept
    {
        return _mSelFieldRanges;
    }

    /*
     * Returns whether or not an instance of this field class is
     * enabled by the selector value `selVal`.
     */
    bool isEnabledBySelVal(const SelVal selVal) const noexcept
    {
        return _mSelFieldRanges.contains(selVal);
    }

private:
    /* Integer selector field ranges */
    IntRangeSetT _mSelFieldRanges;
};

/*
 * Class of optional fields with an unsigned integer selector.
 */
template <typename UserMixinsT>
class OptionalWithUIntSelFc :
    public OptionalWithIntSelFc<UserMixinsT, UIntRangeSet>,
    public UserMixinsT::OptionalWithUIntSelFc
{
public:
    explicit OptionalWithUIntSelFc(
        typename UserMixinsT::Fc fcMixin, typename UserMixinsT::OptionalFc optionalFcMixin,
        typename UserMixinsT::OptionalWithIntSelFc optionalWithIntSelFcMixin,
        typename UserMixinsT::OptionalWithUIntSelFc mixin, typename Fc<UserMixinsT>::UP fc,
        FieldLoc<UserMixinsT> selFieldLoc, UIntRangeSet selFieldRanges,
        OptUserAttrs userAttrs = OptUserAttrs {}) :
        OptionalWithIntSelFc<UserMixinsT, UIntRangeSet> {FcType::OPTIONAL_WITH_UINT_SEL,
                                                         std::move(fcMixin),
                                                         std::move(optionalFcMixin),
                                                         std::move(optionalWithIntSelFcMixin),
                                                         std::move(fc),
                                                         std::move(selFieldLoc),
                                                         std::move(selFieldRanges),
                                                         std::move(userAttrs)},
        UserMixinsT::OptionalWithUIntSelFc {std::move(mixin)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<OptionalWithUIntSelFc>(*this, *this, *this, *this,
                                                        this->fc().clone(), this->selFieldLoc(),
                                                        this->selFieldRanges(), this->userAttrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Class of optional fields with a signed integer selector.
 */
template <typename UserMixinsT>
class OptionalWithSIntSelFc :
    public OptionalWithIntSelFc<UserMixinsT, SIntRangeSet>,
    public UserMixinsT::OptionalWithSIntSelFc
{
public:
    explicit OptionalWithSIntSelFc(
        typename UserMixinsT::Fc fcMixin, typename UserMixinsT::OptionalFc optionalFcMixin,
        typename UserMixinsT::OptionalWithIntSelFc optionalWithIntSelFcMixin,
        typename UserMixinsT::OptionalWithSIntSelFc mixin, typename Fc<UserMixinsT>::UP fc,
        FieldLoc<UserMixinsT> selFieldLoc, SIntRangeSet selFieldRanges,
        OptUserAttrs userAttrs = OptUserAttrs {}) :
        OptionalWithIntSelFc<UserMixinsT, SIntRangeSet> {FcType::OPTIONAL_WITH_SINT_SEL,
                                                         std::move(fcMixin),
                                                         std::move(optionalFcMixin),
                                                         std::move(optionalWithIntSelFcMixin),
                                                         std::move(fc),
                                                         std::move(selFieldLoc),
                                                         std::move(selFieldRanges),
                                                         std::move(userAttrs)},
        UserMixinsT::OptionalWithSIntSelFc {std::move(mixin)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<OptionalWithSIntSelFc>(*this, *this, *this, *this,
                                                        this->fc().clone(), this->selFieldLoc(),
                                                        this->selFieldRanges(), this->userAttrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Variant field class option.
 *
 * `IntRangeSetT` is the integer selector range set type.
 */
template <typename UserMixinsT, typename IntRangeSetT>
class VariantFcOpt : public internal::WithUserAttrsMixin, public UserMixinsT::VariantFcOpt
{
public:
    /* Integer selector range set type */
    using SelFieldRanges = IntRangeSetT;

    /* Selector value type */
    using SelVal = typename IntRangeSetT::Val;

    explicit VariantFcOpt(typename UserMixinsT::VariantFcOpt mixin, typename Fc<UserMixinsT>::UP fc,
                          IntRangeSetT selFieldRanges, bt2s::optional<std::string> name,
                          OptUserAttrs userAttrs = OptUserAttrs {}) :
        internal::WithUserAttrsMixin {std::move(userAttrs)},
        UserMixinsT::VariantFcOpt {std::move(mixin)}, _mName {std::move(name)},
        _mFc {std::move(fc)}, _mSelFieldRanges {std::move(selFieldRanges)}
    {
        BT_ASSERT(_mFc);
    }

    /*
     * Builds a variant field class option from `other`, cloning its
     * field class.
     */
    VariantFcOpt(const VariantFcOpt& other) :
        internal::WithUserAttrsMixin {other.userAttrs()}, UserMixinsT::VariantFcOpt {other},
        _mName {other.name()}, _mFc {other.fc().clone()}, _mSelFieldRanges {other.selFieldRanges()}
    {
    }

    /*
     * Name of this variant field class option.
     */
    const bt2s::optional<std::string>& name() const noexcept
    {
        return _mName;
    }

    /*
     * Field class of this variant field class option.
     */
    const Fc<UserMixinsT>& fc() const noexcept
    {
        return *_mFc;
    }

    /*
     * Name of this variant field class option.
     */
    Fc<UserMixinsT>& fc() noexcept
    {
        return *_mFc;
    }

    /*
     * Integer selector field ranges which select this variant field
     * class option.
     */
    const IntRangeSetT& selFieldRanges() const noexcept
    {
        return _mSelFieldRanges;
    }

private:
    bt2s::optional<std::string> _mName;
    typename Fc<UserMixinsT>::UP _mFc;
    IntRangeSetT _mSelFieldRanges;
};

/*
 * Variant field class base.
 *
 * `IntRangeSetT` is the integer selector range set type.
 *
 * Specific properties over `Fc<UserMixinsT>`:
 *
 * • Selector field location of field class instances.
 * • Options of the field class.
 */
template <typename UserMixinsT, typename IntRangeSetT>
class VariantFc : public Fc<UserMixinsT>, public UserMixinsT::VariantFc
{
public:
    /* Option type */
    using Opt = VariantFcOpt<UserMixinsT, IntRangeSetT>;

    /* Type of options */
    using Opts = std::vector<Opt>;

    /* Integer selector range set type */
    using SelFieldRanges = typename Opt::SelFieldRanges;

    /* Selector value type */
    using SelVal = typename Opt::SelVal;

protected:
    explicit VariantFc(const FcType type, typename UserMixinsT::Fc fcMixin,
                       typename UserMixinsT::VariantFc mixin, Opts&& opts,
                       FieldLoc<UserMixinsT>&& selFieldLoc, OptUserAttrs&& userAttrs) :
        Fc<UserMixinsT> {type, std::move(fcMixin), 1, std::move(userAttrs)},
        UserMixinsT::VariantFc {std::move(mixin)}, _mOpts {std::move(opts)},
        _mSelFieldLoc {std::move(selFieldLoc)}
    {
    }

public:
    /*
     * Selector field location of instances of this field class.
     */
    const FieldLoc<UserMixinsT>& selFieldLoc() const noexcept
    {
        return _mSelFieldLoc;
    }

    /*
     * Options of this field class.
     */
    const Opts& opts() const noexcept
    {
        return _mOpts;
    }

    /*
     * Options of this field class.
     */
    Opts& opts() noexcept
    {
        return _mOpts;
    }

    typename Opts::const_reference operator[](const typename Opts::size_type index) const noexcept
    {
        return _mOpts[index];
    }

    typename Opts::reference operator[](const typename Opts::size_type index) noexcept
    {
        return _mOpts[index];
    }

    const typename Opts::value_type *operator[](const std::string& name) const noexcept
    {
        return this->_optByName<const typename Opts::value_type>(*this, name);
    }

    typename Opts::value_type *operator[](const std::string& name) noexcept
    {
        return this->_optByName<typename Opts::value_type>(*this, name);
    }

    typename Opts::size_type size() const noexcept
    {
        return _mOpts.size();
    }

    typename Opts::const_iterator begin() const noexcept
    {
        return _mOpts.begin();
    }

    typename Opts::iterator begin() noexcept
    {
        return _mOpts.begin();
    }

    typename Opts::const_iterator end() const noexcept
    {
        return _mOpts.end();
    }

    typename Opts::iterator end() noexcept
    {
        return _mOpts.end();
    }

    /*
     * Returns the option of this field class which the selector value
     * `selVal` selects, or `nullptr` if none.
     */
    typename Opts::const_iterator findOptBySelVal(const SelVal selVal) const noexcept
    {
        return std::find_if(_mOpts.begin(), _mOpts.end(), [selVal](const Opt& opt) {
            return opt.selFieldRanges().contains(selVal);
        });
    }

private:
    template <typename ValT, typename VarFcT>
    static ValT *_optByName(VarFcT& varFc, const std::string& name) noexcept
    {
        for (auto& opt : varFc._mOpts) {
            if (opt.name() && *opt.name() == name) {
                return &opt;
            }
        }

        return nullptr;
    }

    /* Options of this field class */
    Opts _mOpts;

    /* Selector field location of instances of this field class */
    FieldLoc<UserMixinsT> _mSelFieldLoc;
};

/*
 * Class of variant fields with an unsigned integer selector.
 */
template <typename UserMixinsT>
class VariantWithUIntSelFc :
    public VariantFc<UserMixinsT, UIntRangeSet>,
    public UserMixinsT::VariantWithUIntSelFc
{
public:
    explicit VariantWithUIntSelFc(typename UserMixinsT::Fc fcMixin,
                                  typename UserMixinsT::VariantFc variantFcMixin,
                                  typename UserMixinsT::VariantWithUIntSelFc mixin,
                                  typename VariantFc<UserMixinsT, UIntRangeSet>::Opts opts,
                                  FieldLoc<UserMixinsT> selFieldLoc,
                                  OptUserAttrs userAttrs = OptUserAttrs {}) :
        VariantFc<UserMixinsT, UIntRangeSet> {FcType::VARIANT_WITH_UINT_SEL, std::move(fcMixin),
                                              std::move(variantFcMixin),     std::move(opts),
                                              std::move(selFieldLoc),        std::move(userAttrs)},
        UserMixinsT::VariantWithUIntSelFc {std::move(mixin)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<VariantWithUIntSelFc>(*this, *this, *this, this->opts(),
                                                       this->selFieldLoc(), this->userAttrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Class of variant fields with a signed integer selector.
 */
template <typename UserMixinsT>
class VariantWithSIntSelFc :
    public VariantFc<UserMixinsT, SIntRangeSet>,
    public UserMixinsT::VariantWithSIntSelFc
{
public:
    explicit VariantWithSIntSelFc(typename UserMixinsT::Fc fcMixin,
                                  typename UserMixinsT::VariantFc variantFcMixin,
                                  typename UserMixinsT::VariantWithSIntSelFc mixin,
                                  typename VariantFc<UserMixinsT, SIntRangeSet>::Opts opts,
                                  FieldLoc<UserMixinsT> selFieldLoc,
                                  OptUserAttrs userAttrs = OptUserAttrs {}) :
        VariantFc<UserMixinsT, SIntRangeSet> {FcType::VARIANT_WITH_SINT_SEL, std::move(fcMixin),
                                              std::move(variantFcMixin),     std::move(opts),
                                              std::move(selFieldLoc),        std::move(userAttrs)},
        UserMixinsT::VariantWithSIntSelFc {std::move(mixin)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<VariantWithSIntSelFc>(*this, *this, *this, this->opts(),
                                                       this->selFieldLoc(), this->userAttrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

template <typename UserMixinsT>
FixedLenBitArrayFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenBitArray() noexcept
{
    BT_ASSERT_DBG(this->isFixedLenBitArray());
    return static_cast<FixedLenBitArrayFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const FixedLenBitArrayFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenBitArray() const noexcept
{
    BT_ASSERT_DBG(this->isFixedLenBitArray());
    return static_cast<const FixedLenBitArrayFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
FixedLenBoolFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenBool() noexcept
{
    BT_ASSERT_DBG(this->isFixedLenBool());
    return static_cast<FixedLenBoolFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const FixedLenBoolFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenBool() const noexcept
{
    BT_ASSERT_DBG(this->isFixedLenBool());
    return static_cast<const FixedLenBoolFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
FixedLenFloatFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenFloat() noexcept
{
    BT_ASSERT_DBG(this->isFixedLenFloat());
    return static_cast<FixedLenFloatFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const FixedLenFloatFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenFloat() const noexcept
{
    BT_ASSERT_DBG(this->isFixedLenFloat());
    return static_cast<const FixedLenFloatFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
FixedLenIntFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenInt() noexcept
{
    BT_ASSERT_DBG(this->isFixedLenInt());
    return static_cast<FixedLenIntFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const FixedLenIntFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenInt() const noexcept
{
    BT_ASSERT_DBG(this->isFixedLenInt());
    return static_cast<const FixedLenIntFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
FixedLenSIntFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenSInt() noexcept
{
    BT_ASSERT_DBG(this->isFixedLenSInt());
    return static_cast<FixedLenSIntFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const FixedLenSIntFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenSInt() const noexcept
{
    BT_ASSERT_DBG(this->isFixedLenSInt());
    return static_cast<const FixedLenSIntFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
FixedLenUIntFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenUInt() noexcept
{
    BT_ASSERT_DBG(this->isFixedLenUInt());
    return static_cast<FixedLenUIntFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const FixedLenUIntFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenUInt() const noexcept
{
    BT_ASSERT_DBG(this->isFixedLenUInt());
    return static_cast<const FixedLenUIntFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
FixedLenSEnumFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenSEnum() noexcept
{
    BT_ASSERT_DBG(this->isFixedLenSEnum());
    return static_cast<FixedLenSEnumFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const FixedLenSEnumFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenSEnum() const noexcept
{
    BT_ASSERT_DBG(this->isFixedLenSEnum());
    return static_cast<const FixedLenSEnumFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
FixedLenUEnumFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenUEnum() noexcept
{
    BT_ASSERT_DBG(this->isFixedLenUEnum());
    return static_cast<FixedLenUEnumFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const FixedLenUEnumFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenUEnum() const noexcept
{
    BT_ASSERT_DBG(this->isFixedLenUEnum());
    return static_cast<const FixedLenUEnumFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
VarLenIntFc<UserMixinsT>& Fc<UserMixinsT>::asVarLenInt() noexcept
{
    BT_ASSERT_DBG(this->isVarLenInt());
    return static_cast<VarLenIntFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const VarLenIntFc<UserMixinsT>& Fc<UserMixinsT>::asVarLenInt() const noexcept
{
    BT_ASSERT_DBG(this->isVarLenInt());
    return static_cast<const VarLenIntFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
VarLenSIntFc<UserMixinsT>& Fc<UserMixinsT>::asVarLenSInt() noexcept
{
    BT_ASSERT_DBG(this->isVarLenSInt());
    return static_cast<VarLenSIntFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const VarLenSIntFc<UserMixinsT>& Fc<UserMixinsT>::asVarLenSInt() const noexcept
{
    BT_ASSERT_DBG(this->isVarLenSInt());
    return static_cast<const VarLenSIntFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
VarLenUIntFc<UserMixinsT>& Fc<UserMixinsT>::asVarLenUInt() noexcept
{
    BT_ASSERT_DBG(this->isVarLenUInt());
    return static_cast<VarLenUIntFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const VarLenUIntFc<UserMixinsT>& Fc<UserMixinsT>::asVarLenUInt() const noexcept
{
    BT_ASSERT_DBG(this->isVarLenUInt());
    return static_cast<const VarLenUIntFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
VarLenSEnumFc<UserMixinsT>& Fc<UserMixinsT>::asVarLenSEnum() noexcept
{
    BT_ASSERT_DBG(this->isVarLenSEnum());
    return static_cast<VarLenSEnumFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const VarLenSEnumFc<UserMixinsT>& Fc<UserMixinsT>::asVarLenSEnum() const noexcept
{
    BT_ASSERT_DBG(this->isVarLenSEnum());
    return static_cast<const VarLenSEnumFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
VarLenUEnumFc<UserMixinsT>& Fc<UserMixinsT>::asVarLenUEnum() noexcept
{
    BT_ASSERT_DBG(this->isVarLenUEnum());
    return static_cast<VarLenUEnumFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const VarLenUEnumFc<UserMixinsT>& Fc<UserMixinsT>::asVarLenUEnum() const noexcept
{
    BT_ASSERT_DBG(this->isVarLenUEnum());
    return static_cast<const VarLenUEnumFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
NullTerminatedStrFc<UserMixinsT>& Fc<UserMixinsT>::asNullTerminatedStr() noexcept
{
    BT_ASSERT_DBG(this->isNullTerminatedStr());
    return static_cast<NullTerminatedStrFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const NullTerminatedStrFc<UserMixinsT>& Fc<UserMixinsT>::asNullTerminatedStr() const noexcept
{
    BT_ASSERT_DBG(this->isNullTerminatedStr());
    return static_cast<const NullTerminatedStrFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
NonNullTerminatedStrFc<UserMixinsT>& Fc<UserMixinsT>::asNonNullTerminatedStr() noexcept
{
    BT_ASSERT_DBG(this->isNonNullTerminatedStr());
    return static_cast<NonNullTerminatedStrFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const NonNullTerminatedStrFc<UserMixinsT>& Fc<UserMixinsT>::asNonNullTerminatedStr() const noexcept
{
    BT_ASSERT_DBG(this->isNonNullTerminatedStr());
    return static_cast<const NonNullTerminatedStrFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
StaticLenStrFc<UserMixinsT>& Fc<UserMixinsT>::asStaticLenStr() noexcept
{
    BT_ASSERT_DBG(this->isStaticLenStr());
    return static_cast<StaticLenStrFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const StaticLenStrFc<UserMixinsT>& Fc<UserMixinsT>::asStaticLenStr() const noexcept
{
    BT_ASSERT_DBG(this->isStaticLenStr());
    return static_cast<const StaticLenStrFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
DynLenStrFc<UserMixinsT>& Fc<UserMixinsT>::asDynLenStr() noexcept
{
    BT_ASSERT_DBG(this->isDynLenStr());
    return static_cast<DynLenStrFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const DynLenStrFc<UserMixinsT>& Fc<UserMixinsT>::asDynLenStr() const noexcept
{
    BT_ASSERT_DBG(this->isDynLenStr());
    return static_cast<const DynLenStrFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
BlobFc<UserMixinsT>& Fc<UserMixinsT>::asBlob() noexcept
{
    BT_ASSERT_DBG(this->isBlob());
    return static_cast<BlobFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const BlobFc<UserMixinsT>& Fc<UserMixinsT>::asBlob() const noexcept
{
    BT_ASSERT_DBG(this->isBlob());
    return static_cast<const BlobFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
StaticLenBlobFc<UserMixinsT>& Fc<UserMixinsT>::asStaticLenBlob() noexcept
{
    BT_ASSERT_DBG(this->isStaticLenBlob());
    return static_cast<StaticLenBlobFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const StaticLenBlobFc<UserMixinsT>& Fc<UserMixinsT>::asStaticLenBlob() const noexcept
{
    BT_ASSERT_DBG(this->isStaticLenBlob());
    return static_cast<const StaticLenBlobFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
DynLenBlobFc<UserMixinsT>& Fc<UserMixinsT>::asDynLenBlob() noexcept
{
    BT_ASSERT_DBG(this->isDynLenBlob());
    return static_cast<DynLenBlobFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const DynLenBlobFc<UserMixinsT>& Fc<UserMixinsT>::asDynLenBlob() const noexcept
{
    BT_ASSERT_DBG(this->isDynLenBlob());
    return static_cast<const DynLenBlobFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
ArrayFc<UserMixinsT>& Fc<UserMixinsT>::asArray() noexcept
{
    BT_ASSERT_DBG(this->isArray());
    return static_cast<ArrayFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const ArrayFc<UserMixinsT>& Fc<UserMixinsT>::asArray() const noexcept
{
    BT_ASSERT_DBG(this->isArray());
    return static_cast<const ArrayFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
StaticLenArrayFc<UserMixinsT>& Fc<UserMixinsT>::asStaticLenArray() noexcept
{
    BT_ASSERT_DBG(this->isStaticLenArray());
    return static_cast<StaticLenArrayFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const StaticLenArrayFc<UserMixinsT>& Fc<UserMixinsT>::asStaticLenArray() const noexcept
{
    BT_ASSERT_DBG(this->isStaticLenArray());
    return static_cast<const StaticLenArrayFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
DynLenArrayFc<UserMixinsT>& Fc<UserMixinsT>::asDynLenArray() noexcept
{
    BT_ASSERT_DBG(this->isDynLenArray());
    return static_cast<DynLenArrayFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const DynLenArrayFc<UserMixinsT>& Fc<UserMixinsT>::asDynLenArray() const noexcept
{
    BT_ASSERT_DBG(this->isDynLenArray());
    return static_cast<const DynLenArrayFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
StructFc<UserMixinsT>& Fc<UserMixinsT>::asStruct() noexcept
{
    BT_ASSERT_DBG(this->isStruct());
    return static_cast<StructFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const StructFc<UserMixinsT>& Fc<UserMixinsT>::asStruct() const noexcept
{
    BT_ASSERT_DBG(this->isStruct());
    return static_cast<const StructFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
OptionalFc<UserMixinsT>& Fc<UserMixinsT>::asOptional() noexcept
{
    BT_ASSERT_DBG(this->isOptional());
    return static_cast<OptionalFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const OptionalFc<UserMixinsT>& Fc<UserMixinsT>::asOptional() const noexcept
{
    BT_ASSERT_DBG(this->isOptional());
    return static_cast<const OptionalFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
OptionalWithBoolSelFc<UserMixinsT>& Fc<UserMixinsT>::asOptionalWithBoolSel() noexcept
{
    BT_ASSERT_DBG(this->isOptionalWithBoolSel());
    return static_cast<OptionalWithBoolSelFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const OptionalWithBoolSelFc<UserMixinsT>& Fc<UserMixinsT>::asOptionalWithBoolSel() const noexcept
{
    BT_ASSERT_DBG(this->isOptionalWithBoolSel());
    return static_cast<const OptionalWithBoolSelFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
OptionalWithUIntSelFc<UserMixinsT>& Fc<UserMixinsT>::asOptionalWithUIntSel() noexcept
{
    BT_ASSERT_DBG(this->isOptionalWithUIntSel());
    return static_cast<OptionalWithUIntSelFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const OptionalWithUIntSelFc<UserMixinsT>& Fc<UserMixinsT>::asOptionalWithUIntSel() const noexcept
{
    BT_ASSERT_DBG(this->isOptionalWithUIntSel());
    return static_cast<const OptionalWithUIntSelFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
OptionalWithSIntSelFc<UserMixinsT>& Fc<UserMixinsT>::asOptionalWithSIntSel() noexcept
{
    BT_ASSERT_DBG(this->isOptionalWithSIntSel());
    return static_cast<OptionalWithSIntSelFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const OptionalWithSIntSelFc<UserMixinsT>& Fc<UserMixinsT>::asOptionalWithSIntSel() const noexcept
{
    BT_ASSERT_DBG(this->isOptionalWithSIntSel());
    return static_cast<const OptionalWithSIntSelFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
VariantWithUIntSelFc<UserMixinsT>& Fc<UserMixinsT>::asVariantWithUIntSel() noexcept
{
    BT_ASSERT_DBG(this->isVariantWithUIntSel());
    return static_cast<VariantWithUIntSelFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const VariantWithUIntSelFc<UserMixinsT>& Fc<UserMixinsT>::asVariantWithUIntSel() const noexcept
{
    BT_ASSERT_DBG(this->isVariantWithUIntSel());
    return static_cast<const VariantWithUIntSelFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
VariantWithSIntSelFc<UserMixinsT>& Fc<UserMixinsT>::asVariantWithSIntSel() noexcept
{
    BT_ASSERT_DBG(this->isVariantWithSIntSel());
    return static_cast<VariantWithSIntSelFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const VariantWithSIntSelFc<UserMixinsT>& Fc<UserMixinsT>::asVariantWithSIntSel() const noexcept
{
    BT_ASSERT_DBG(this->isVariantWithSIntSel());
    return static_cast<const VariantWithSIntSelFc<UserMixinsT>&>(*this);
}

/*
 * Clock offset (seconds and cycles).
 */
class ClkOffset
{
public:
    explicit ClkOffset(const long long seconds = 0, const unsigned long long cycles = 0) noexcept :
        _mSeconds {seconds}, _mCycles {cycles}
    {
    }

    /*
     * Seconds part of this clock offset offset.
     */
    long long seconds() const noexcept
    {
        return _mSeconds;
    }

    /*
     * Cycles part of this clock offset offset.
     */
    unsigned long long cycles() const noexcept
    {
        return _mCycles;
    }

private:
    /* Seconds part of this clock offset offset */
    long long _mSeconds;

    /* Cycles part of this clock offset offset */
    unsigned long long _mCycles;
};

/*
 * Clock class.
 */
template <typename UserMixinsT>
class ClkCls :
    public internal::WithUserAttrsMixin,
    public internal::WithLibCls<bt2::ClockClass>,
    public UserMixinsT::ClkCls
{
public:
    /* Shared pointer to an event record class */
    using SP = std::shared_ptr<ClkCls>;

    explicit ClkCls(typename UserMixinsT::ClkCls mixin, std::string name,
                    const unsigned long long freq, const ClkOffset& clkOffset = ClkOffset {},
                    const bool originIsUnixEpoch = true,
                    bt2s::optional<std::string> descr = bt2s::nullopt,
                    const unsigned long long precision = 0,
                    bt2s::optional<bt2c::Uuid> uuid = bt2s::nullopt,
                    OptUserAttrs userAttrs = OptUserAttrs {}) :
        internal::WithUserAttrsMixin {std::move(userAttrs)},
        UserMixinsT::ClkCls {std::move(mixin)}, _mName {std::move(name)}, _mFreq {freq},
        _mOffset {clkOffset}, _mOriginIsUnixEpoch {originIsUnixEpoch}, _mDescr {std::move(descr)},
        _mPrecision {precision}, _mUuid {std::move(uuid)}
    {
        BT_ASSERT(_mFreq > 0);
        BT_ASSERT(_mOffset.cycles() < _mFreq);
    }

    /*
     * Name of instances of this clock class.
     */
    const std::string& name() const noexcept
    {
        return _mName;
    }

    /*
     * Frequency (Hz) of instances of this clock class.
     */
    unsigned long long freq() const noexcept
    {
        return _mFreq;
    }

    /*
     * Offset from origin of instances of this clock class.
     */
    const ClkOffset& offset() const noexcept
    {
        return _mOffset;
    }

    /*
     * Sets the offset from origin of instances of this clock class.
     */
    void offset(const ClkOffset& offset) noexcept
    {
        _mOffset = offset;
    }

    /*
     * Whether or not the origin of instances of this clock class is the
     * Unix epoch.
     */
    bool originIsUnixEpoch() const noexcept
    {
        return _mOriginIsUnixEpoch;
    }

    /*
     * Sets whether or not the origin of instances of this clock class is the
     * Unix epoch.
     */
    void originIsUnixEpoch(const bool originIsUnixEpoch) noexcept
    {
        _mOriginIsUnixEpoch = originIsUnixEpoch;
    }

    /*
     * Description of instances of this clock class.
     */
    const bt2s::optional<std::string>& descr() const noexcept
    {
        return _mDescr;
    }

    /*
     * Precision (cycles) of instances of this clock class.
     */
    unsigned long long precision() const noexcept
    {
        return _mPrecision;
    }

    /*
     * UUID of instances of this clock class.
     */
    const bt2s::optional<bt2c::Uuid>& uuid() const noexcept
    {
        return _mUuid;
    }

private:
    /* Name of instances of this clock class */
    std::string _mName;

    /* Frequency (Hz) of instances of this clock class */
    unsigned long long _mFreq;

    /* Offset from origin of instances of this clock class */
    ClkOffset _mOffset;

    /*
     * Whether or not the origin of instances of this clock class is the
     * Unix epoch.
     */
    bool _mOriginIsUnixEpoch;

    /* Description of instances of this clock class */
    bt2s::optional<std::string> _mDescr;

    /* Precision (cycles) of instances of this clock class */
    unsigned long long _mPrecision;

    /* UUID of instances of this clock class */
    bt2s::optional<bt2c::Uuid> _mUuid;
};

/*
 * Event record class.
 */
template <typename UserMixinsT>
class EventRecordCls :
    public internal::WithUserAttrsMixin,
    public internal::WithLibCls<bt2::EventClass>,
    public UserMixinsT::EventRecordCls
{
public:
    /* Unique pointer to an event record class */
    using UP = std::unique_ptr<EventRecordCls>;

    explicit EventRecordCls(typename UserMixinsT::EventRecordCls mixin, const unsigned long long id,
                            bt2s::optional<std::string> ns = bt2s::nullopt,
                            bt2s::optional<std::string> name = bt2s::nullopt,
                            typename StructFc<UserMixinsT>::UP specCtxFc = nullptr,
                            typename StructFc<UserMixinsT>::UP payloadFc = nullptr,
                            OptUserAttrs userAttrs = OptUserAttrs {}) :
        internal::WithUserAttrsMixin {std::move(userAttrs)},
        UserMixinsT::EventRecordCls {std::move(mixin)}, _mId {id}, _mNs {std::move(ns)},
        _mName {std::move(name)}, _mSpecCtxFc {std::move(specCtxFc)}, _mPayloadFc {
                                                                          std::move(payloadFc)}
    {
    }

    /*
     * ID of this event record class.
     */
    unsigned long long id() const noexcept
    {
        return _mId;
    }

    /*
     * Namespace of instances of this event record class.
     */
    const bt2s::optional<std::string>& ns() const noexcept
    {
        return _mNs;
    }

    /*
     * Name of instances of this event record class.
     */
    const bt2s::optional<std::string>& name() const noexcept
    {
        return _mName;
    }

    /*
     * Class of the specific context field of instances of this event
     * record class.
     */
    const StructFc<UserMixinsT> *specCtxFc() const noexcept
    {
        return static_cast<StructFc<UserMixinsT> *>(_mSpecCtxFc.get());
    }

    /*
     * Class of the specific context field of instances of this event
     * record class.
     */
    StructFc<UserMixinsT> *specCtxFc() noexcept
    {
        return static_cast<StructFc<UserMixinsT> *>(_mSpecCtxFc.get());
    }

    /*
     * Class of the payload field of instances of this event record
     * class.
     */
    const StructFc<UserMixinsT> *payloadFc() const noexcept
    {
        return static_cast<StructFc<UserMixinsT> *>(_mPayloadFc.get());
    }

    /*
     * Class of the payload field of instances of this event record
     * class.
     */
    StructFc<UserMixinsT> *payloadFc() noexcept
    {
        return static_cast<StructFc<UserMixinsT> *>(_mPayloadFc.get());
    }

private:
    /* ID of this event record class */
    unsigned long long _mId;

    /* Namespace of instances of this event record class */
    bt2s::optional<std::string> _mNs;

    /* Name of instances of this event record class */
    bt2s::optional<std::string> _mName;

    /*
     * Class of the specific context field of instances of this event
     * record class.
     */
    typename StructFc<UserMixinsT>::UP _mSpecCtxFc;

    /*
     * Class of the payload field of instances of this event record
     * class.
     */
    typename StructFc<UserMixinsT>::UP _mPayloadFc;
};

namespace internal {

/*
 * Less-than functor working on numeric IDs of unique pointers to
 * `ObjT`.
 */
template <typename ObjT>
struct ObjUpIdLt
{
    bool operator()(const typename ObjT::UP& objA, const typename ObjT::UP& objB) const noexcept
    {
        return objA->id() < objB->id();
    }
};

} /* namespace internal */

/*
 * Data stream class.
 */
template <typename UserMixinsT>
class DataStreamCls :
    public internal::WithUserAttrsMixin,
    public internal::WithLibCls<bt2::StreamClass>,
    public UserMixinsT::DataStreamCls
{
public:
    /* Unique pointer to a data stream class */
    using UP = std::unique_ptr<DataStreamCls>;

    /* Event record class set */
    using EventRecordClsSet = std::set<typename EventRecordCls<UserMixinsT>::UP,
                                       internal::ObjUpIdLt<EventRecordCls<UserMixinsT>>>;

    explicit DataStreamCls(typename UserMixinsT::DataStreamCls mixin, const unsigned long long id,
                           bt2s::optional<std::string> ns = bt2s::nullopt,
                           bt2s::optional<std::string> name = bt2s::nullopt,
                           typename StructFc<UserMixinsT>::UP pktCtxFc = nullptr,
                           typename StructFc<UserMixinsT>::UP eventRecordHeaderFc = nullptr,
                           typename StructFc<UserMixinsT>::UP eventRecordCommonCtxFc = nullptr,
                           typename ClkCls<UserMixinsT>::SP defClkCls = nullptr,
                           OptUserAttrs userAttrs = OptUserAttrs {}) :
        internal::WithUserAttrsMixin {std::move(userAttrs)},
        UserMixinsT::DataStreamCls {std::move(mixin)}, _mId {id}, _mNs {std::move(ns)},
        _mName {std::move(name)}, _mPktCtxFc {std::move(pktCtxFc)},
        _mEventRecordHeaderFc {std::move(eventRecordHeaderFc)},
        _mEventRecordCommonCtxFc {std::move(eventRecordCommonCtxFc)}, _mDefClkCls {
                                                                          std::move(defClkCls)}
    {
    }

    /*
     * ID of this data stream class.
     */
    unsigned long long id() const noexcept
    {
        return _mId;
    }

    /*
     * Namespace of instances of this data stream class.
     */
    const bt2s::optional<std::string>& ns() const noexcept
    {
        return _mNs;
    }

    /*
     * Name of instances of this data stream class.
     */
    const bt2s::optional<std::string>& name() const noexcept
    {
        return _mName;
    }

    /*
     * Class of the packet context field of instances of this data
     * stream class.
     */
    const StructFc<UserMixinsT> *pktCtxFc() const noexcept
    {
        return static_cast<StructFc<UserMixinsT> *>(_mPktCtxFc.get());
    }

    /*
     * Class of the context field of packets which are part of instances
     * of this data stream class.
     */
    StructFc<UserMixinsT> *pktCtxFc() noexcept
    {
        return static_cast<StructFc<UserMixinsT> *>(_mPktCtxFc.get());
    }

    /*
     * Class of the context field of packets which are part of instances
     * of this data stream class.
     */
    const StructFc<UserMixinsT> *eventRecordHeaderFc() const noexcept
    {
        return static_cast<StructFc<UserMixinsT> *>(_mEventRecordHeaderFc.get());
    }

    /*
     * Class of the header field of event records which are part of
     * instances of this data stream class.
     */
    StructFc<UserMixinsT> *eventRecordHeaderFc() noexcept
    {
        return static_cast<StructFc<UserMixinsT> *>(_mEventRecordHeaderFc.get());
    }

    /*
     * Class of the header field of event records which are part of
     * instances of this data stream class.
     */
    const StructFc<UserMixinsT> *eventRecordCommonCtxFc() const noexcept
    {
        return static_cast<StructFc<UserMixinsT> *>(_mEventRecordCommonCtxFc.get());
    }

    /*
     * Class of the common context field of event records which are part
     * of instances of this data stream class.
     */
    StructFc<UserMixinsT> *eventRecordCommonCtxFc() noexcept
    {
        return static_cast<StructFc<UserMixinsT> *>(_mEventRecordCommonCtxFc.get());
    }

    /*
     * Class of the common context field of event records which are part
     * of instances of this data stream class.
     */
    const ClkCls<UserMixinsT> *defClkCls() const noexcept
    {
        return _mDefClkCls.get();
    }

    /*
     * Class of the default clock of instances of this data stream
     * class.
     */
    ClkCls<UserMixinsT> *defClkCls() noexcept
    {
        return _mDefClkCls.get();
    }

    /*
     * Event record classes of this data stream class.
     */
    const EventRecordClsSet& eventRecordClasses() const noexcept
    {
        return _mEventRecordClasses;
    }

    /*
     * Adds the event record class `eventRecordCls` to the set of event
     * record classes of this data stream class.
     */
    void addEventRecordCls(typename EventRecordCls<UserMixinsT>::UP eventRecordCls)
    {
        BT_ASSERT_DBG(eventRecordCls);
        _mEventRecordClsIdMap[eventRecordCls->id()] = eventRecordCls.get();
        _mEventRecordClasses.emplace(std::move(eventRecordCls));
    }

    const EventRecordCls<UserMixinsT> *operator[](const unsigned long long id) const noexcept
    {
        return this->_eventRecordClsById<const EventRecordCls<UserMixinsT>>(*this, id);
    }

    EventRecordCls<UserMixinsT> *operator[](const unsigned long long id) noexcept
    {
        return this->_eventRecordClsById<EventRecordCls<UserMixinsT>>(*this, id);
    }

    typename EventRecordClsSet::size_type size() const noexcept
    {
        return _mEventRecordClasses.size();
    }

    typename EventRecordClsSet::const_iterator begin() const noexcept
    {
        return _mEventRecordClasses.begin();
    }

    typename EventRecordClsSet::iterator begin() noexcept
    {
        return _mEventRecordClasses.begin();
    }

    typename EventRecordClsSet::const_iterator end() const noexcept
    {
        return _mEventRecordClasses.end();
    }

    typename EventRecordClsSet::iterator end() noexcept
    {
        return _mEventRecordClasses.end();
    }

private:
    using _EventRecordClsByIdMap =
        std::unordered_map<unsigned long long, EventRecordCls<UserMixinsT> *>;

    template <typename ValT, typename DataStreamClsT>
    static ValT *_eventRecordClsById(DataStreamClsT& dataStreamCls,
                                     const unsigned long long id) noexcept
    {
        const auto it = dataStreamCls._mEventRecordClsIdMap.find(id);

        if (it == dataStreamCls._mEventRecordClsIdMap.end()) {
            return nullptr;
        }

        return it->second;
    }

    /* ID of this data stream class */
    unsigned long long _mId;

    /* Event record classes of this data stream class */
    EventRecordClsSet _mEventRecordClasses;

    /* Map of event record class ID to event record class */
    _EventRecordClsByIdMap _mEventRecordClsIdMap;

    /* Namespace of instances of this data stream class */
    bt2s::optional<std::string> _mNs;

    /* Name of instances of this data stream class */
    bt2s::optional<std::string> _mName;

    /*
     * Class of the context field of packets which are part of instances
     * of this data stream class.
     */
    typename Fc<UserMixinsT>::UP _mPktCtxFc;

    /*
     * Class of the header field of event records which are part of
     * instances of this data stream class.
     */
    typename Fc<UserMixinsT>::UP _mEventRecordHeaderFc;

    /*
     * Class of the common context field of event records which are part
     * of instances of this data stream class.
     */
    typename Fc<UserMixinsT>::UP _mEventRecordCommonCtxFc;

    /*
     * Class of the default clock of instances of this data stream
     * class.
     */
    typename ClkCls<UserMixinsT>::SP _mDefClkCls;
};

/*
 * Trace class.
 */
template <typename UserMixinsT>
class TraceCls :
    public internal::WithUserAttrsMixin,
    public internal::WithLibCls<bt2::TraceClass>,
    public UserMixinsT::TraceCls
{
public:
    /* Data stream class set */
    using DataStreamClsSet = std::set<typename DataStreamCls<UserMixinsT>::UP,
                                      internal::ObjUpIdLt<DataStreamCls<UserMixinsT>>>;

    explicit TraceCls(typename UserMixinsT::TraceCls mixin,
                      bt2s::optional<bt2c::Uuid> uuid = bt2s::nullopt,
                      bt2::ConstMapValue::Shared env = bt2::ConstMapValue::Shared {},
                      typename Fc<UserMixinsT>::UP pktHeaderFc = nullptr,
                      OptUserAttrs userAttrs = OptUserAttrs {}) :
        internal::WithUserAttrsMixin {std::move(userAttrs)},
        UserMixinsT::TraceCls {std::move(mixin)}, _mUuid {std::move(uuid)}, _mEnv {std::move(env)},
        _mPktHeaderFc {std::move(pktHeaderFc)}
    {
        BT_ASSERT(!_mPktHeaderFc || _mPktHeaderFc->isStruct());
    }

    /*
     * UUID of instances of this trace class.
     */
    const bt2s::optional<bt2c::Uuid>& uuid() const noexcept
    {
        return _mUuid;
    }

    /*
     * Environment of instances of this trace class.
     */
    const bt2::OptionalBorrowedObject<bt2::ConstMapValue> env() const noexcept
    {
        if (!_mEnv) {
            return {};
        }

        return *_mEnv;
    }

    /*
     * Class of the header field of packets which are part of instances
     * of this data stream class.
     */
    const StructFc<UserMixinsT> *pktHeaderFc() const noexcept
    {
        return static_cast<StructFc<UserMixinsT> *>(_mPktHeaderFc.get());
    }

    /*
     * Class of the header field of packets which are part of instances
     * of this data stream class.
     */
    StructFc<UserMixinsT> *pktHeaderFc() noexcept
    {
        return static_cast<StructFc<UserMixinsT> *>(_mPktHeaderFc.get());
    }

    /*
     * Data stream classes of this trace class.
     */
    const DataStreamClsSet& dataStreamClasses() const noexcept
    {
        return _mDataStreamClasses;
    }

    /*
     * Adds the data stream class `dataStreamCls` to the set of data
     * stream classes of this trace class.
     */
    void addDataStreamCls(typename DataStreamCls<UserMixinsT>::UP dataStreamCls)
    {
        BT_ASSERT_DBG(dataStreamCls);
        _mDataStreamClsIdMap[dataStreamCls->id()] = dataStreamCls.get();
        _mDataStreamClasses.emplace(std::move(dataStreamCls));
    }

    const DataStreamCls<UserMixinsT> *operator[](const unsigned long long id) const noexcept
    {
        return this->_dataStreamClsById<const DataStreamCls<UserMixinsT>>(*this, id);
    }

    DataStreamCls<UserMixinsT> *operator[](const unsigned long long id) noexcept
    {
        return this->_dataStreamClsById<DataStreamCls<UserMixinsT>>(*this, id);
    }

    typename DataStreamClsSet::size_type size() const noexcept
    {
        return _mDataStreamClasses.size();
    }

    typename DataStreamClsSet::const_iterator begin() const noexcept
    {
        return _mDataStreamClasses.begin();
    }

    typename DataStreamClsSet::iterator begin() noexcept
    {
        return _mDataStreamClasses.begin();
    }

    typename DataStreamClsSet::const_iterator end() const noexcept
    {
        return _mDataStreamClasses.end();
    }

    typename DataStreamClsSet::iterator end() noexcept
    {
        return _mDataStreamClasses.end();
    }

private:
    using _DataStreamClsByIdMap =
        std::unordered_map<unsigned long long, DataStreamCls<UserMixinsT> *>;

    template <typename ValT, typename TraceClsT>
    static ValT *_dataStreamClsById(TraceClsT& traceCls, const unsigned long long id) noexcept
    {
        const auto it = traceCls._mDataStreamClsIdMap.find(id);

        if (it == traceCls._mDataStreamClsIdMap.end()) {
            return nullptr;
        }

        return it->second;
    }

    /* Data stream classes of this trace class */
    DataStreamClsSet _mDataStreamClasses;

    /* Map of data stream class ID to data stream class */
    _DataStreamClsByIdMap _mDataStreamClsIdMap;

    /* UUID of instances of this trace class */
    bt2s::optional<bt2c::Uuid> _mUuid;

    /* Environment of instances of this trace class */
    bt2::ConstMapValue::Shared _mEnv;

    /*
     * Class of the header field of packets which are part of instances
     * of this data stream class.
     */
    typename Fc<UserMixinsT>::UP _mPktHeaderFc;
};

/*
 * Default user mixins.
 */
struct DefUserMixins
{
    struct FieldLoc
    {
    };

    struct Fc
    {
    };

    struct FixedLenBitArrayFc
    {
    };

    struct FixedLenBoolFc
    {
    };

    struct FixedLenIntFc
    {
    };

    struct FixedLenUIntFc
    {
    };

    struct VarLenIntFc
    {
    };

    struct VarLenUIntFc
    {
    };

    struct StaticLenStrFc
    {
    };

    struct DynLenStrFc
    {
    };

    struct StaticLenBlobFc
    {
    };

    struct DynLenBlobFc
    {
    };

    struct StaticLenArrayFc
    {
    };

    struct DynLenArrayFc
    {
    };

    struct StructFieldMemberCls
    {
    };

    struct StructFc
    {
    };

    struct OptionalFc
    {
    };

    struct OptionalWithBoolSelFc
    {
    };

    struct OptionalWithIntSelFc
    {
    };

    struct OptionalWithUIntSelFc
    {
    };

    struct OptionalWithSIntSelFc
    {
    };

    struct VariantFcOpt
    {
    };

    struct VariantFc
    {
    };

    struct VariantWithUIntSelFc
    {
    };

    struct VariantWithSIntSelFc
    {
    };

    struct ClkCls
    {
    };

    struct EventRecordCls
    {
    };

    struct DataStreamCls
    {
    };

    struct TraceCls
    {
    };
};

} /* namespace ir */
} /* namespace ctf */

#endif /* _CTF_CTF_IR_HPP */
