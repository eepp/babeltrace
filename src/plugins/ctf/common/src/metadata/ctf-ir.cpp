/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include "cpp-common/make-unique.hpp"
#include "ctf-ir.hpp"

namespace ctf {
namespace src {
namespace internal {

void ValSavingFcMixin::_addValSavingIndex(const std::size_t index, FcDeepType& deepType) noexcept
{
    _mValSavingIndexes.push_back(index);

    /*
     * At this point we know that the data stream decoder needs to save
     * the value of any instance of this field class (field).
     *
     * Adjust the deep type of the field class so as to include that
     * it's a value saving one.
     */
    switch (deepType) {
    case FcDeepType::FIXED_LEN_BOOL_BE:
        deepType = FcDeepType::FIXED_LEN_BOOL_BE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_BOOL_LE:
        deepType = FcDeepType::FIXED_LEN_BOOL_LE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_BOOL_BA_8:
        deepType = FcDeepType::FIXED_LEN_BOOL_BA_8_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_BOOL_BA_16_LE:
        deepType = FcDeepType::FIXED_LEN_BOOL_BA_16_LE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_BOOL_BA_16_BE:
        deepType = FcDeepType::FIXED_LEN_BOOL_BA_16_BE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_BOOL_BA_32_LE:
        deepType = FcDeepType::FIXED_LEN_BOOL_BA_32_LE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_BOOL_BA_32_BE:
        deepType = FcDeepType::FIXED_LEN_BOOL_BA_32_BE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_BOOL_BA_64_LE:
        deepType = FcDeepType::FIXED_LEN_BOOL_BA_64_LE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_BOOL_BA_64_BE:
        deepType = FcDeepType::FIXED_LEN_BOOL_BA_64_BE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UINT_BE:
        deepType = FcDeepType::FIXED_LEN_UINT_BE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UINT_LE:
        deepType = FcDeepType::FIXED_LEN_UINT_LE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UINT_BA_8:
        deepType = FcDeepType::FIXED_LEN_UINT_BA_8_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UINT_BA_16_LE:
        deepType = FcDeepType::FIXED_LEN_UINT_BA_16_LE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UINT_BA_16_BE:
        deepType = FcDeepType::FIXED_LEN_UINT_BA_16_BE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UINT_BA_32_LE:
        deepType = FcDeepType::FIXED_LEN_UINT_BA_32_LE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UINT_BA_32_BE:
        deepType = FcDeepType::FIXED_LEN_UINT_BA_32_BE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UINT_BA_64_LE:
        deepType = FcDeepType::FIXED_LEN_UINT_BA_64_LE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UINT_BA_64_BE:
        deepType = FcDeepType::FIXED_LEN_UINT_BA_64_BE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UINT_BE_WITH_ROLE:
        deepType = FcDeepType::FIXED_LEN_UINT_BE_WITH_ROLE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UINT_LE_WITH_ROLE:
        deepType = FcDeepType::FIXED_LEN_UINT_LE_WITH_ROLE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UINT_BA_8_WITH_ROLE:
        deepType = FcDeepType::FIXED_LEN_UINT_BA_8_WITH_ROLE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UINT_BA_16_LE_WITH_ROLE:
        deepType = FcDeepType::FIXED_LEN_UINT_BA_16_LE_WITH_ROLE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UINT_BA_16_BE_WITH_ROLE:
        deepType = FcDeepType::FIXED_LEN_UINT_BA_16_BE_WITH_ROLE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UINT_BA_32_LE_WITH_ROLE:
        deepType = FcDeepType::FIXED_LEN_UINT_BA_32_LE_WITH_ROLE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UINT_BA_32_BE_WITH_ROLE:
        deepType = FcDeepType::FIXED_LEN_UINT_BA_32_BE_WITH_ROLE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UINT_BA_64_LE_WITH_ROLE:
        deepType = FcDeepType::FIXED_LEN_UINT_BA_64_LE_WITH_ROLE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UINT_BA_64_BE_WITH_ROLE:
        deepType = FcDeepType::FIXED_LEN_UINT_BA_64_BE_WITH_ROLE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_SINT_BE:
        deepType = FcDeepType::FIXED_LEN_SINT_BE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_SINT_LE:
        deepType = FcDeepType::FIXED_LEN_SINT_LE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_SINT_BA_8:
        deepType = FcDeepType::FIXED_LEN_SINT_BA_8_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_SINT_BA_16_LE:
        deepType = FcDeepType::FIXED_LEN_SINT_BA_16_LE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_SINT_BA_16_BE:
        deepType = FcDeepType::FIXED_LEN_SINT_BA_16_BE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_SINT_BA_32_LE:
        deepType = FcDeepType::FIXED_LEN_SINT_BA_32_LE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_SINT_BA_32_BE:
        deepType = FcDeepType::FIXED_LEN_SINT_BA_32_BE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_SINT_BA_64_LE:
        deepType = FcDeepType::FIXED_LEN_SINT_BA_64_LE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_SINT_BA_64_BE:
        deepType = FcDeepType::FIXED_LEN_SINT_BA_64_BE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UENUM_BE:
        deepType = FcDeepType::FIXED_LEN_UENUM_BE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UENUM_LE:
        deepType = FcDeepType::FIXED_LEN_UENUM_LE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UENUM_BA_8:
        deepType = FcDeepType::FIXED_LEN_UENUM_BA_8_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UENUM_BA_16_LE:
        deepType = FcDeepType::FIXED_LEN_UENUM_BA_16_LE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UENUM_BA_16_BE:
        deepType = FcDeepType::FIXED_LEN_UENUM_BA_16_BE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UENUM_BA_32_LE:
        deepType = FcDeepType::FIXED_LEN_UENUM_BA_32_LE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UENUM_BA_32_BE:
        deepType = FcDeepType::FIXED_LEN_UENUM_BA_32_BE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UENUM_BA_64_LE:
        deepType = FcDeepType::FIXED_LEN_UENUM_BA_64_LE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UENUM_BA_64_BE:
        deepType = FcDeepType::FIXED_LEN_UENUM_BA_64_BE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UENUM_BE_WITH_ROLE:
        deepType = FcDeepType::FIXED_LEN_UENUM_BE_WITH_ROLE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UENUM_LE_WITH_ROLE:
        deepType = FcDeepType::FIXED_LEN_UENUM_LE_WITH_ROLE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UENUM_BA_8_WITH_ROLE:
        deepType = FcDeepType::FIXED_LEN_UENUM_BA_8_WITH_ROLE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UENUM_BA_16_LE_WITH_ROLE:
        deepType = FcDeepType::FIXED_LEN_UENUM_BA_16_LE_WITH_ROLE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UENUM_BA_16_BE_WITH_ROLE:
        deepType = FcDeepType::FIXED_LEN_UENUM_BA_16_BE_WITH_ROLE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UENUM_BA_32_LE_WITH_ROLE:
        deepType = FcDeepType::FIXED_LEN_UENUM_BA_32_LE_WITH_ROLE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UENUM_BA_32_BE_WITH_ROLE:
        deepType = FcDeepType::FIXED_LEN_UENUM_BA_32_BE_WITH_ROLE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UENUM_BA_64_LE_WITH_ROLE:
        deepType = FcDeepType::FIXED_LEN_UENUM_BA_64_LE_WITH_ROLE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_UENUM_BA_64_BE_WITH_ROLE:
        deepType = FcDeepType::FIXED_LEN_UENUM_BA_64_BE_WITH_ROLE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_SENUM_BE:
        deepType = FcDeepType::FIXED_LEN_SENUM_BE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_SENUM_LE:
        deepType = FcDeepType::FIXED_LEN_SENUM_LE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_SENUM_BA_8:
        deepType = FcDeepType::FIXED_LEN_SENUM_BA_8_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_SENUM_BA_16_LE:
        deepType = FcDeepType::FIXED_LEN_SENUM_BA_16_LE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_SENUM_BA_16_BE:
        deepType = FcDeepType::FIXED_LEN_SENUM_BA_16_BE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_SENUM_BA_32_LE:
        deepType = FcDeepType::FIXED_LEN_SENUM_BA_32_LE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_SENUM_BA_32_BE:
        deepType = FcDeepType::FIXED_LEN_SENUM_BA_32_BE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_SENUM_BA_64_LE:
        deepType = FcDeepType::FIXED_LEN_SENUM_BA_64_LE_SAVE_VAL;
        break;
    case FcDeepType::FIXED_LEN_SENUM_BA_64_BE:
        deepType = FcDeepType::FIXED_LEN_SENUM_BA_64_BE_SAVE_VAL;
        break;
    case FcDeepType::VAR_LEN_UINT:
        deepType = FcDeepType::VAR_LEN_UINT_SAVE_VAL;
        break;
    case FcDeepType::VAR_LEN_UINT_WITH_ROLE:
        deepType = FcDeepType::VAR_LEN_UINT_WITH_ROLE_SAVE_VAL;
        break;
    case FcDeepType::VAR_LEN_SINT:
        deepType = FcDeepType::VAR_LEN_SINT_SAVE_VAL;
        break;
    case FcDeepType::VAR_LEN_UENUM:
        deepType = FcDeepType::VAR_LEN_UENUM_SAVE_VAL;
        break;
    case FcDeepType::VAR_LEN_UENUM_WITH_ROLE:
        deepType = FcDeepType::VAR_LEN_UENUM_WITH_ROLE_SAVE_VAL;
        break;
    case FcDeepType::VAR_LEN_SENUM:
        deepType = FcDeepType::VAR_LEN_SENUM_SAVE_VAL;
        break;
    default:
        break;
    }
}

void FixedLenBoolFcMixin::addValSavingIndex(const std::size_t index) noexcept
{
    this->_addValSavingIndex(index, static_cast<FixedLenBoolFc&>(*this)._mDeepType);
}

void FixedLenIntFcMixin::addValSavingIndex(const std::size_t index) noexcept
{
    this->_addValSavingIndex(index, static_cast<FixedLenIntFc&>(*this)._mDeepType);
}

void VarLenIntFcMixin::addValSavingIndex(const std::size_t index) noexcept
{
    this->_addValSavingIndex(index, static_cast<VarLenIntFc&>(*this)._mDeepType);
}

} /* namespace internal */

static inline bool isStdBitArrayFc(const unsigned int align, const bt2_common::DataLen len) noexcept
{
    return align % 8 == 0 && (*len == 8 || *len == 16 || *len == 32 || *len == 64);
}

FieldLoc createFieldLoc(const ir::FieldLocScope scope, FieldLoc::Items items)
{
    return FieldLoc {internal::CtfIrMixins::FieldLoc {}, scope, std::move(items)};
}

std::unique_ptr<FixedLenBitArrayFc> createFixedLenBitArrayFc(const unsigned int align,
                                                             const bt2_common::DataLen len,
                                                             const ir::ByteOrder byteOrder,
                                                             ir::OptUserAttrs userAttrs)
{
    const auto deepType = [align, len, byteOrder] {
        if (byteOrder == ir::ByteOrder::BIG) {
            if (isStdBitArrayFc(align, len)) {
                switch (*len) {
                case 8:
                    return FcDeepType::FIXED_LEN_BIT_ARRAY_BA_8;
                case 16:
                    return FcDeepType::FIXED_LEN_BIT_ARRAY_BA_16_BE;
                case 32:
                    return FcDeepType::FIXED_LEN_BIT_ARRAY_BA_32_BE;
                case 64:
                    return FcDeepType::FIXED_LEN_BIT_ARRAY_BA_64_BE;
                default:
                    bt_common_abort();
                }
            } else {
                return FcDeepType::FIXED_LEN_BIT_ARRAY_BE;
            }
        } else {
            if (isStdBitArrayFc(align, len)) {
                switch (*len) {
                case 8:
                    return FcDeepType::FIXED_LEN_BIT_ARRAY_BA_8;
                case 16:
                    return FcDeepType::FIXED_LEN_BIT_ARRAY_BA_16_LE;
                case 32:
                    return FcDeepType::FIXED_LEN_BIT_ARRAY_BA_32_LE;
                case 64:
                    return FcDeepType::FIXED_LEN_BIT_ARRAY_BA_64_LE;
                default:
                    bt_common_abort();
                }
            } else {
                return FcDeepType::FIXED_LEN_BIT_ARRAY_LE;
            }
        }
    }();

    return bt2_common::makeUnique<FixedLenBitArrayFc>(internal::CtfIrMixins::Fc {deepType},
                                                      internal::CtfIrMixins::FixedLenBitArrayFc {},
                                                      align, len, byteOrder, std::move(userAttrs));
}

std::unique_ptr<FixedLenBoolFc> createFixedLenBoolFc(const unsigned int align,
                                                     const bt2_common::DataLen len,
                                                     const ir::ByteOrder byteOrder,
                                                     ir::OptUserAttrs userAttrs)
{
    const auto deepType = [align, len, byteOrder] {
        if (byteOrder == ir::ByteOrder::BIG) {
            if (isStdBitArrayFc(align, len)) {
                switch (*len) {
                case 8:
                    return FcDeepType::FIXED_LEN_BOOL_BA_8;
                case 16:
                    return FcDeepType::FIXED_LEN_BOOL_BA_16_BE;
                case 32:
                    return FcDeepType::FIXED_LEN_BOOL_BA_32_BE;
                case 64:
                    return FcDeepType::FIXED_LEN_BOOL_BA_64_BE;
                default:
                    bt_common_abort();
                }
            } else {
                return FcDeepType::FIXED_LEN_BOOL_BE;
            }
        } else {
            if (isStdBitArrayFc(align, len)) {
                switch (*len) {
                case 8:
                    return FcDeepType::FIXED_LEN_BOOL_BA_8;
                case 16:
                    return FcDeepType::FIXED_LEN_BOOL_BA_16_LE;
                case 32:
                    return FcDeepType::FIXED_LEN_BOOL_BA_32_LE;
                case 64:
                    return FcDeepType::FIXED_LEN_BOOL_BA_64_LE;
                default:
                    bt_common_abort();
                }
            } else {
                return FcDeepType::FIXED_LEN_BOOL_LE;
            }
        }
    }();

    return bt2_common::makeUnique<FixedLenBoolFc>(
        internal::CtfIrMixins::Fc {deepType}, internal::CtfIrMixins::FixedLenBitArrayFc {},
        internal::CtfIrMixins::FixedLenBoolFc {}, align, len, byteOrder, std::move(userAttrs));
}

std::unique_ptr<FixedLenFloatFc> createFixedLenFloatFc(const unsigned int align,
                                                       const bt2_common::DataLen len,
                                                       const ir::ByteOrder byteOrder,
                                                       ir::OptUserAttrs userAttrs)
{
    const auto deepType = [align, len, byteOrder] {
        if (byteOrder == ir::ByteOrder::BIG) {
            if (isStdBitArrayFc(align, len)) {
                switch (*len) {
                case 32:
                    return FcDeepType::FIXED_LEN_FLOAT_BA_32_BE;
                case 64:
                    return FcDeepType::FIXED_LEN_FLOAT_BA_64_BE;
                default:
                    bt_common_abort();
                }
            } else {
                switch (*len) {
                case 32:
                    return FcDeepType::FIXED_LEN_FLOAT_32_BE;
                case 64:
                    return FcDeepType::FIXED_LEN_FLOAT_64_BE;
                default:
                    bt_common_abort();
                }
            }
        } else {
            if (isStdBitArrayFc(align, len)) {
                switch (*len) {
                case 32:
                    return FcDeepType::FIXED_LEN_FLOAT_BA_32_LE;
                case 64:
                    return FcDeepType::FIXED_LEN_FLOAT_BA_64_LE;
                default:
                    bt_common_abort();
                }
            } else {
                switch (*len) {
                case 32:
                    return FcDeepType::FIXED_LEN_FLOAT_32_LE;
                case 64:
                    return FcDeepType::FIXED_LEN_FLOAT_64_LE;
                default:
                    bt_common_abort();
                }
            }
        }
    }();

    return bt2_common::makeUnique<FixedLenFloatFc>(internal::CtfIrMixins::Fc {deepType},
                                                   internal::CtfIrMixins::FixedLenBitArrayFc {},
                                                   align, len, byteOrder, std::move(userAttrs));
}

std::unique_ptr<FixedLenUIntFc>
createFixedLenUIntFc(const unsigned int align, const bt2_common::DataLen len,
                     const ir::ByteOrder byteOrder, const ir::DispBase prefDispBase,
                     ir::UIntFieldRoles roles, ir::OptUserAttrs userAttrs)
{
    const auto deepType = [align, len, byteOrder, &roles] {
        if (byteOrder == ir::ByteOrder::BIG) {
            if (isStdBitArrayFc(align, len)) {
                switch (*len) {
                case 8:
                    return roles.empty() ? FcDeepType::FIXED_LEN_UINT_BA_8 :
                                           FcDeepType::FIXED_LEN_UINT_BA_8_WITH_ROLE;
                case 16:
                    return roles.empty() ? FcDeepType::FIXED_LEN_UINT_BA_16_BE :
                                           FcDeepType::FIXED_LEN_UINT_BA_16_BE_WITH_ROLE;
                case 32:
                    return roles.empty() ? FcDeepType::FIXED_LEN_UINT_BA_32_BE :
                                           FcDeepType::FIXED_LEN_UINT_BA_32_BE_WITH_ROLE;
                case 64:
                    return roles.empty() ? FcDeepType::FIXED_LEN_UINT_BA_64_BE :
                                           FcDeepType::FIXED_LEN_UINT_BA_64_BE_WITH_ROLE;
                default:
                    bt_common_abort();
                }
            } else {
                return roles.empty() ? FcDeepType::FIXED_LEN_UINT_BE :
                                       FcDeepType::FIXED_LEN_UINT_BE_WITH_ROLE;
            }
        } else {
            if (isStdBitArrayFc(align, len)) {
                switch (*len) {
                case 8:
                    return roles.empty() ? FcDeepType::FIXED_LEN_UINT_BA_8 :
                                           FcDeepType::FIXED_LEN_UINT_BA_8_WITH_ROLE;
                case 16:
                    return roles.empty() ? FcDeepType::FIXED_LEN_UINT_BA_16_LE :
                                           FcDeepType::FIXED_LEN_UINT_BA_16_LE_WITH_ROLE;
                case 32:
                    return roles.empty() ? FcDeepType::FIXED_LEN_UINT_BA_32_LE :
                                           FcDeepType::FIXED_LEN_UINT_BA_32_LE_WITH_ROLE;
                case 64:
                    return roles.empty() ? FcDeepType::FIXED_LEN_UINT_BA_64_LE :
                                           FcDeepType::FIXED_LEN_UINT_BA_64_LE_WITH_ROLE;
                default:
                    bt_common_abort();
                }
            } else {
                return roles.empty() ? FcDeepType::FIXED_LEN_UINT_LE :
                                       FcDeepType::FIXED_LEN_UINT_LE_WITH_ROLE;
            }
        }
    }();

    return bt2_common::makeUnique<FixedLenUIntFc>(
        internal::CtfIrMixins::Fc {deepType}, internal::CtfIrMixins::FixedLenBitArrayFc {},
        internal::CtfIrMixins::FixedLenIntFc {}, internal::CtfIrMixins::FixedLenUIntFc {}, align,
        len, byteOrder, prefDispBase, std::move(roles), std::move(userAttrs));
}

std::unique_ptr<FixedLenSIntFc> createFixedLenSIntFc(const unsigned int align,
                                                     const bt2_common::DataLen len,
                                                     const ir::ByteOrder byteOrder,
                                                     const ir::DispBase prefDispBase,
                                                     ir::OptUserAttrs userAttrs)
{
    const auto deepType = [align, len, byteOrder] {
        if (byteOrder == ir::ByteOrder::BIG) {
            if (isStdBitArrayFc(align, len)) {
                switch (*len) {
                case 8:
                    return FcDeepType::FIXED_LEN_SINT_BA_8;
                case 16:
                    return FcDeepType::FIXED_LEN_SINT_BA_16_BE;
                case 32:
                    return FcDeepType::FIXED_LEN_SINT_BA_32_BE;
                case 64:
                    return FcDeepType::FIXED_LEN_SINT_BA_64_BE;
                default:
                    bt_common_abort();
                }
            } else {
                return FcDeepType::FIXED_LEN_SINT_BE;
            }
        } else {
            if (isStdBitArrayFc(align, len)) {
                switch (*len) {
                case 8:
                    return FcDeepType::FIXED_LEN_SINT_BA_8;
                case 16:
                    return FcDeepType::FIXED_LEN_SINT_BA_16_LE;
                case 32:
                    return FcDeepType::FIXED_LEN_SINT_BA_32_LE;
                case 64:
                    return FcDeepType::FIXED_LEN_SINT_BA_64_LE;
                default:
                    bt_common_abort();
                }
            } else {
                return FcDeepType::FIXED_LEN_SINT_LE;
            }
        }
    }();

    return bt2_common::makeUnique<FixedLenSIntFc>(
        internal::CtfIrMixins::Fc {deepType}, internal::CtfIrMixins::FixedLenBitArrayFc {},
        internal::CtfIrMixins::FixedLenIntFc {}, align, len, byteOrder, prefDispBase,
        std::move(userAttrs));
}

std::unique_ptr<FixedLenUEnumFc>
createFixedLenUEnumFc(const unsigned int align, const bt2_common::DataLen len,
                      const ir::ByteOrder byteOrder, FixedLenUEnumFc::Mappings mappings,
                      const ir::DispBase prefDispBase, ir::UIntFieldRoles roles,
                      ir::OptUserAttrs userAttrs)
{
    const auto deepType = [align, len, byteOrder, &roles] {
        if (byteOrder == ir::ByteOrder::BIG) {
            if (isStdBitArrayFc(align, len)) {
                switch (*len) {
                case 8:
                    return roles.empty() ? FcDeepType::FIXED_LEN_UENUM_BA_8 :
                                           FcDeepType::FIXED_LEN_UENUM_BA_8_WITH_ROLE;
                case 16:
                    return roles.empty() ? FcDeepType::FIXED_LEN_UENUM_BA_16_BE :
                                           FcDeepType::FIXED_LEN_UENUM_BA_16_BE_WITH_ROLE;
                case 32:
                    return roles.empty() ? FcDeepType::FIXED_LEN_UENUM_BA_32_BE :
                                           FcDeepType::FIXED_LEN_UENUM_BA_32_BE_WITH_ROLE;
                case 64:
                    return roles.empty() ? FcDeepType::FIXED_LEN_UENUM_BA_64_BE :
                                           FcDeepType::FIXED_LEN_UENUM_BA_64_BE_WITH_ROLE;
                default:
                    bt_common_abort();
                }
            } else {
                return roles.empty() ? FcDeepType::FIXED_LEN_UENUM_BE :
                                       FcDeepType::FIXED_LEN_UENUM_BE_WITH_ROLE;
            }
        } else {
            if (isStdBitArrayFc(align, len)) {
                switch (*len) {
                case 8:
                    return roles.empty() ? FcDeepType::FIXED_LEN_UENUM_BA_8 :
                                           FcDeepType::FIXED_LEN_UENUM_BA_8_WITH_ROLE;
                case 16:
                    return roles.empty() ? FcDeepType::FIXED_LEN_UENUM_BA_16_LE :
                                           FcDeepType::FIXED_LEN_UENUM_BA_16_LE_WITH_ROLE;
                case 32:
                    return roles.empty() ? FcDeepType::FIXED_LEN_UENUM_BA_32_LE :
                                           FcDeepType::FIXED_LEN_UENUM_BA_32_LE_WITH_ROLE;
                case 64:
                    return roles.empty() ? FcDeepType::FIXED_LEN_UENUM_BA_64_LE :
                                           FcDeepType::FIXED_LEN_UENUM_BA_64_LE_WITH_ROLE;
                default:
                    bt_common_abort();
                }
            } else {
                return roles.empty() ? FcDeepType::FIXED_LEN_UENUM_LE :
                                       FcDeepType::FIXED_LEN_UENUM_LE_WITH_ROLE;
            }
        }
    }();

    return bt2_common::makeUnique<FixedLenUEnumFc>(
        internal::CtfIrMixins::Fc {deepType}, internal::CtfIrMixins::FixedLenBitArrayFc {},
        internal::CtfIrMixins::FixedLenIntFc {}, internal::CtfIrMixins::FixedLenUIntFc {}, align,
        len, byteOrder, std::move(mappings), prefDispBase, std::move(roles), std::move(userAttrs));
}

std::unique_ptr<FixedLenSEnumFc>
createFixedLenSEnumFc(const unsigned int align, const bt2_common::DataLen len,
                      const ir::ByteOrder byteOrder, FixedLenSEnumFc::Mappings mappings,
                      const ir::DispBase prefDispBase, ir::OptUserAttrs userAttrs)
{
    const auto deepType = [align, len, byteOrder] {
        if (byteOrder == ir::ByteOrder::BIG) {
            if (isStdBitArrayFc(align, len)) {
                switch (*len) {
                case 8:
                    return FcDeepType::FIXED_LEN_SENUM_BA_8;
                case 16:
                    return FcDeepType::FIXED_LEN_SENUM_BA_16_BE;
                case 32:
                    return FcDeepType::FIXED_LEN_SENUM_BA_32_BE;
                case 64:
                    return FcDeepType::FIXED_LEN_SENUM_BA_64_BE;
                default:
                    bt_common_abort();
                }
            } else {
                return FcDeepType::FIXED_LEN_SENUM_BE;
            }
        } else {
            if (isStdBitArrayFc(align, len)) {
                switch (*len) {
                case 8:
                    return FcDeepType::FIXED_LEN_SENUM_BA_8;
                case 16:
                    return FcDeepType::FIXED_LEN_SENUM_BA_16_LE;
                case 32:
                    return FcDeepType::FIXED_LEN_SENUM_BA_32_LE;
                case 64:
                    return FcDeepType::FIXED_LEN_SENUM_BA_64_LE;
                default:
                    bt_common_abort();
                }
            } else {
                return FcDeepType::FIXED_LEN_SENUM_LE;
            }
        }
    }();

    return bt2_common::makeUnique<FixedLenSEnumFc>(
        internal::CtfIrMixins::Fc {deepType}, internal::CtfIrMixins::FixedLenBitArrayFc {},
        internal::CtfIrMixins::FixedLenIntFc {}, align, len, byteOrder, std::move(mappings),
        prefDispBase, std::move(userAttrs));
}

std::unique_ptr<VarLenUIntFc> createVarLenUIntFc(const ir::DispBase prefDispBase,
                                                 ir::UIntFieldRoles roles,
                                                 ir::OptUserAttrs userAttrs)
{
    const auto deepType =
        roles.empty() ? FcDeepType::VAR_LEN_UINT : FcDeepType::VAR_LEN_UINT_WITH_ROLE;

    return bt2_common::makeUnique<VarLenUIntFc>(
        internal::CtfIrMixins::Fc {deepType}, internal::CtfIrMixins::VarLenIntFc {},
        internal::CtfIrMixins::VarLenUIntFc {}, prefDispBase, std::move(roles),
        std::move(userAttrs));
}

std::unique_ptr<VarLenSIntFc> createVarLenSIntFc(const ir::DispBase prefDispBase,
                                                 ir::OptUserAttrs userAttrs)
{
    return bt2_common::makeUnique<VarLenSIntFc>(
        internal::CtfIrMixins::Fc {FcDeepType::VAR_LEN_SINT}, internal::CtfIrMixins::VarLenIntFc {},
        prefDispBase, std::move(userAttrs));
}

std::unique_ptr<VarLenUEnumFc> createVarLenUEnumFc(FixedLenUEnumFc::Mappings mappings,
                                                   const ir::DispBase prefDispBase,
                                                   ir::UIntFieldRoles roles,
                                                   ir::OptUserAttrs userAttrs)
{
    const auto deepType =
        roles.empty() ? FcDeepType::VAR_LEN_UENUM : FcDeepType::VAR_LEN_UENUM_WITH_ROLE;

    return bt2_common::makeUnique<VarLenUEnumFc>(
        internal::CtfIrMixins::Fc {deepType}, internal::CtfIrMixins::VarLenIntFc {},
        internal::CtfIrMixins::VarLenUIntFc {}, std::move(mappings), prefDispBase, std::move(roles),
        std::move(userAttrs));
}

std::unique_ptr<VarLenSEnumFc> createVarLenSEnumFc(FixedLenSEnumFc::Mappings mappings,
                                                   const ir::DispBase prefDispBase,
                                                   ir::OptUserAttrs userAttrs)
{
    return bt2_common::makeUnique<VarLenSEnumFc>(
        internal::CtfIrMixins::Fc {FcDeepType::VAR_LEN_SENUM},
        internal::CtfIrMixins::VarLenIntFc {}, std::move(mappings), prefDispBase,
        std::move(userAttrs));
}

std::unique_ptr<NullTerminatedStrFc> createNullTerminatedStrFc(ir::OptUserAttrs userAttrs)
{
    return bt2_common::makeUnique<NullTerminatedStrFc>(
        internal::CtfIrMixins::Fc {FcDeepType::NULL_TERMINATED_STR}, std::move(userAttrs));
}

std::unique_ptr<StaticLenArrayFc> createStaticLenArrayFc(const std::size_t len, Fc::UP elemFc,
                                                         const unsigned int minAlign,
                                                         ir::OptUserAttrs userAttrs,
                                                         const bool hasMetadataStreamUuidRole)
{
    const auto deepType = hasMetadataStreamUuidRole ?
                              FcDeepType::STATIC_LEN_ARRAY_WITH_METADATA_STREAM_UUID_ROLE :
                              FcDeepType::STATIC_LEN_ARRAY;

    return bt2_common::makeUnique<StaticLenArrayFc>(
        internal::CtfIrMixins::Fc {deepType}, internal::CtfIrMixins::StaticLenArrayFc {}, len,
        std::move(elemFc), minAlign, std::move(userAttrs));
}

std::unique_ptr<DynLenArrayFc> createDynLenArrayFc(FieldLoc lenFieldLoc, Fc::UP elemFc,
                                                   const unsigned int minAlign,
                                                   ir::OptUserAttrs userAttrs)
{
    return bt2_common::makeUnique<DynLenArrayFc>(
        internal::CtfIrMixins::Fc {FcDeepType::DYN_LEN_ARRAY},
        internal::CtfIrMixins::DynLenArrayFc {}, std::move(lenFieldLoc), std::move(elemFc),
        minAlign, std::move(userAttrs));
}

std::unique_ptr<StaticLenStrFc> createStaticLenStrFc(const std::size_t len,
                                                     ir::OptUserAttrs userAttrs)
{
    return bt2_common::makeUnique<StaticLenStrFc>(
        internal::CtfIrMixins::Fc {FcDeepType::STATIC_LEN_STR},
        internal::CtfIrMixins::StaticLenStrFc {}, len, std::move(userAttrs));
}

std::unique_ptr<DynLenStrFc> createDynLenStrFc(FieldLoc lenFieldLoc, ir::OptUserAttrs userAttrs)
{
    return bt2_common::makeUnique<DynLenStrFc>(internal::CtfIrMixins::Fc {FcDeepType::DYN_LEN_STR},
                                               internal::CtfIrMixins::DynLenStrFc {},
                                               std::move(lenFieldLoc), std::move(userAttrs));
}

std::unique_ptr<StaticLenBlobFc> createStaticLenBlobFc(const std::size_t len, std::string mediaType,
                                                       const bool hasMetadataStreamUuidRole,
                                                       ir::OptUserAttrs userAttrs)
{
    const auto deepType = hasMetadataStreamUuidRole ?
                              FcDeepType::STATIC_LEN_BLOB_WITH_METADATA_STREAM_UUID_ROLE :
                              FcDeepType::STATIC_LEN_BLOB;

    return bt2_common::makeUnique<StaticLenBlobFc>(
        internal::CtfIrMixins::Fc {deepType}, internal::CtfIrMixins::StaticLenBlobFc {}, len,
        std::move(mediaType), hasMetadataStreamUuidRole, std::move(userAttrs));
}

std::unique_ptr<DynLenBlobFc> createDynLenBlobFc(FieldLoc lenFieldLoc, std::string mediaType,
                                                 ir::OptUserAttrs userAttrs)
{
    return bt2_common::makeUnique<DynLenBlobFc>(
        internal::CtfIrMixins::Fc {FcDeepType::DYN_LEN_BLOB},
        internal::CtfIrMixins::DynLenBlobFc {}, std::move(lenFieldLoc), std::move(mediaType),
        std::move(userAttrs));
}

StructFieldMemberCls createStructFieldMemberCls(std::string name, Fc::UP fc,
                                                ir::OptUserAttrs userAttrs)
{
    return StructFieldMemberCls {internal::CtfIrMixins::StructFieldMemberCls {}, std::move(name),
                                 std::move(fc), std::move(userAttrs)};
}

std::unique_ptr<StructFc> createStructFc(StructFc::MemberClasses&& memberClasses,
                                         const unsigned int minAlign, ir::OptUserAttrs userAttrs)
{
    return bt2_common::makeUnique<StructFc>(
        internal::CtfIrMixins::Fc {FcDeepType::STRUCT}, internal::CtfIrMixins::StructFc {},
        std::move(memberClasses), minAlign, std::move(userAttrs));
}

std::unique_ptr<OptionalWithBoolSelFc> createOptionalFc(Fc::UP fc, FieldLoc selFieldLoc,
                                                        ir::OptUserAttrs userAttrs)
{
    return bt2_common::makeUnique<OptionalWithBoolSelFc>(
        internal::CtfIrMixins::Fc {FcDeepType::OPTIONAL_WITH_BOOL_SEL},
        internal::CtfIrMixins::OptionalFc {}, internal::CtfIrMixins::OptionalWithBoolSelFc {},
        std::move(fc), std::move(selFieldLoc), std::move(userAttrs));
}

std::unique_ptr<OptionalWithUIntSelFc> createOptionalFc(Fc::UP fc, FieldLoc selFieldLoc,
                                                        UIntRangeSet selFieldRanges,
                                                        ir::OptUserAttrs userAttrs)
{
    return bt2_common::makeUnique<OptionalWithUIntSelFc>(
        internal::CtfIrMixins::Fc {FcDeepType::OPTIONAL_WITH_UINT_SEL},
        internal::CtfIrMixins::OptionalFc {}, internal::CtfIrMixins::OptionalWithIntSelFc {},
        internal::CtfIrMixins::OptionalWithUIntSelFc {}, std::move(fc), std::move(selFieldLoc),
        std::move(selFieldRanges), std::move(userAttrs));
}

std::unique_ptr<OptionalWithSIntSelFc> createOptionalFc(Fc::UP fc, FieldLoc selFieldLoc,
                                                        SIntRangeSet selFieldRanges,
                                                        ir::OptUserAttrs userAttrs)
{
    return bt2_common::makeUnique<OptionalWithSIntSelFc>(
        internal::CtfIrMixins::Fc {FcDeepType::OPTIONAL_WITH_SINT_SEL},
        internal::CtfIrMixins::OptionalFc {}, internal::CtfIrMixins::OptionalWithIntSelFc {},
        internal::CtfIrMixins::OptionalWithSIntSelFc {}, std::move(fc), std::move(selFieldLoc),
        std::move(selFieldRanges), std::move(userAttrs));
}

VariantWithUIntSelFc::Opt createVariantFcOpt(Fc::UP fc, UIntRangeSet selFieldRanges,
                                             nonstd::optional<std::string> name,
                                             ir::OptUserAttrs userAttrs)
{
    return VariantWithUIntSelFc::Opt {internal::CtfIrMixins::VariantFcOpt {}, std::move(fc),
                                      std::move(selFieldRanges), std::move(name),
                                      std::move(userAttrs)};
}

VariantWithSIntSelFc::Opt createVariantFcOpt(Fc::UP fc, SIntRangeSet selFieldRanges,
                                             nonstd::optional<std::string> name,
                                             ir::OptUserAttrs userAttrs)
{
    return VariantWithSIntSelFc::Opt {internal::CtfIrMixins::VariantFcOpt {}, std::move(fc),
                                      std::move(selFieldRanges), std::move(name),
                                      std::move(userAttrs)};
}

std::unique_ptr<VariantWithUIntSelFc>
createVariantFc(VariantWithUIntSelFc::Opts&& opts, FieldLoc selFieldLoc, ir::OptUserAttrs userAttrs)
{
    return bt2_common::makeUnique<VariantWithUIntSelFc>(
        internal::CtfIrMixins::Fc {FcDeepType::VARIANT_WITH_UINT_SEL},
        internal::CtfIrMixins::VariantFc {}, internal::CtfIrMixins::VariantWithUIntSelFc {},
        std::move(opts), std::move(selFieldLoc), std::move(userAttrs));
}

std::unique_ptr<VariantWithSIntSelFc>
createVariantFc(VariantWithSIntSelFc::Opts&& opts, FieldLoc selFieldLoc, ir::OptUserAttrs userAttrs)
{
    return bt2_common::makeUnique<VariantWithSIntSelFc>(
        internal::CtfIrMixins::Fc {FcDeepType::VARIANT_WITH_SINT_SEL},
        internal::CtfIrMixins::VariantFc {}, internal::CtfIrMixins::VariantWithSIntSelFc {},
        std::move(opts), std::move(selFieldLoc), std::move(userAttrs));
}

ClkCls::SP createClkCls(std::string name, const unsigned long long freq,
                        const ir::ClkOffset& clkOffset, const bool originIsUnixEpoch,
                        nonstd::optional<std::string> descr, const unsigned long long precision,
                        nonstd::optional<bt2_common::Uuid> uuid, ir::OptUserAttrs userAttrs)
{
    return std::make_shared<ClkCls>(internal::CtfIrMixins::ClkCls {}, std::move(name), freq,
                                    clkOffset, originIsUnixEpoch, std::move(descr), precision,
                                    std::move(uuid), std::move(userAttrs));
}

std::unique_ptr<EventRecordCls> createEventRecordCls(const unsigned long long id,
                                                     nonstd::optional<std::string> ns,
                                                     nonstd::optional<std::string> name,
                                                     Fc::UP specCtxFc, Fc::UP payloadFc,
                                                     ir::OptUserAttrs userAttrs)
{
    return bt2_common::makeUnique<EventRecordCls>(
        internal::CtfIrMixins::EventRecordCls {}, id, std::move(ns), std::move(name),
        std::move(specCtxFc), std::move(payloadFc), std::move(userAttrs));
}

std::unique_ptr<DataStreamCls>
createDataStreamCls(const unsigned long long id, nonstd::optional<std::string> ns,
                    nonstd::optional<std::string> name, Fc::UP pktCtxFc, Fc::UP eventRecordHeaderFc,
                    Fc::UP eventRecordCommonCtxFc, ClkCls::SP defClkCls, ir::OptUserAttrs userAttrs)
{
    return bt2_common::makeUnique<DataStreamCls>(
        internal::CtfIrMixins::DataStreamCls {}, id, std::move(ns), std::move(name),
        std::move(pktCtxFc), std::move(eventRecordHeaderFc), std::move(eventRecordCommonCtxFc),
        std::move(defClkCls), std::move(userAttrs));
}

std::unique_ptr<TraceCls> createTraceCls(nonstd::optional<bt2_common::Uuid> uuid,
                                         nonstd::optional<bt2::ConstMapValue::Shared> env,
                                         Fc::UP pktHeaderFc, ir::OptUserAttrs userAttrs)
{
    return bt2_common::makeUnique<TraceCls>(internal::CtfIrMixins::TraceCls {}, std::move(uuid),
                                            std::move(env), std::move(pktHeaderFc),
                                            std::move(userAttrs));
}

} /* namespace src */
} /* namespace ctf */
