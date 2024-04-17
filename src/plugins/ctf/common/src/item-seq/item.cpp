/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include "item.hpp"

namespace ctf {
namespace src {

Item::Item(const Type type) noexcept : _mType {type}
{
}

BeginItem::BeginItem(const Type type) noexcept : Item {type}
{
}

EndItem::EndItem(const Type type) noexcept : Item {type}
{
}

PktBeginItem::PktBeginItem() noexcept : BeginItem {Type::PKT_BEGIN}
{
}

void PktBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

PktEndItem::PktEndItem() noexcept : EndItem {Type::PKT_END}
{
}

void PktEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

ScopeBeginItem::ScopeBeginItem() noexcept : BeginItem {Type::SCOPE_BEGIN}
{
}

void ScopeBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

ScopeEndItem::ScopeEndItem() noexcept : EndItem {Type::SCOPE_END}
{
}

void ScopeEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

EventRecordBeginItem::EventRecordBeginItem() noexcept : BeginItem {Type::EVENT_RECORD_BEGIN}
{
}

void EventRecordBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

EventRecordEndItem::EventRecordEndItem() noexcept : EndItem {Type::EVENT_RECORD_END}
{
}

void EventRecordEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

PktContentBeginItem::PktContentBeginItem() noexcept : BeginItem {Type::PKT_CONTENT_BEGIN}
{
}

void PktContentBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

PktContentEndItem::PktContentEndItem() noexcept : EndItem {Type::PKT_CONTENT_END}
{
}

void PktContentEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

PktMagicNumberItem::PktMagicNumberItem() noexcept : Item {Type::PKT_MAGIC_NUMBER}
{
}

void PktMagicNumberItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

MetadataStreamUuidItem::MetadataStreamUuidItem() noexcept : Item {Type::METADATA_STREAM_UUID}
{
}

void MetadataStreamUuidItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

DataStreamInfoItem::DataStreamInfoItem() noexcept : Item {Type::DATA_STREAM_INFO}
{
}

void DataStreamInfoItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

DefClkValItem::DefClkValItem() noexcept : Item {Type::DEF_CLK_VALUE}
{
}

void DefClkValItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

PktInfoItem::PktInfoItem() noexcept : Item {Type::PKT_INFO}
{
}

void PktInfoItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

EventRecordInfoItem::EventRecordInfoItem() noexcept : Item {Type::EVENT_RECORD_INFO}
{
}

void EventRecordInfoItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

FixedLenBitArrayFieldItem::FixedLenBitArrayFieldItem(const Type type) noexcept : Item {type}
{
}

FixedLenBitArrayFieldItem::FixedLenBitArrayFieldItem() noexcept :
    FixedLenBitArrayFieldItem {Type::FIXED_LEN_BIT_ARRAY_FIELD}
{
}

void FixedLenBitArrayFieldItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

FixedLenBoolFieldItem::FixedLenBoolFieldItem() noexcept :
    FixedLenBitArrayFieldItem {Type::FIXED_LEN_BOOL_FIELD}
{
}

void FixedLenBoolFieldItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

FixedLenSIntFieldItem::FixedLenSIntFieldItem(const Type type) noexcept :
    FixedLenBitArrayFieldItem {type}
{
}

FixedLenSIntFieldItem::FixedLenSIntFieldItem() noexcept :
    FixedLenSIntFieldItem {Type::FIXED_LEN_SINT_FIELD}
{
}

void FixedLenSIntFieldItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

FixedLenUIntFieldItem::FixedLenUIntFieldItem(const Type type) noexcept :
    FixedLenBitArrayFieldItem {type}
{
}

FixedLenUIntFieldItem::FixedLenUIntFieldItem() noexcept :
    FixedLenUIntFieldItem {Type::FIXED_LEN_UINT_FIELD}
{
}

void FixedLenUIntFieldItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

FixedLenSEnumFieldItem::FixedLenSEnumFieldItem() noexcept :
    FixedLenSIntFieldItem {Type::FIXED_LEN_SENUM_FIELD}
{
}

void FixedLenSEnumFieldItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

FixedLenUEnumFieldItem::FixedLenUEnumFieldItem() noexcept :
    FixedLenUIntFieldItem {Type::FIXED_LEN_UENUM_FIELD}
{
}

void FixedLenUEnumFieldItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

FixedLenFloatFieldItem::FixedLenFloatFieldItem() noexcept :
    FixedLenBitArrayFieldItem {Type::FIXED_LEN_FLOAT_FIELD}
{
}

void FixedLenFloatFieldItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

VarLenIntFieldItem::VarLenIntFieldItem(const Type type) noexcept :
    Item {type}, _mLen {bt2c::DataLen::fromBits(0)}
{
}

VarLenSIntFieldItem::VarLenSIntFieldItem(const Type type) noexcept : VarLenIntFieldItem {type}
{
}

VarLenSIntFieldItem::VarLenSIntFieldItem() noexcept : VarLenSIntFieldItem {Type::VAR_LEN_SINT_FIELD}
{
}

void VarLenSIntFieldItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

VarLenUIntFieldItem::VarLenUIntFieldItem(const Type type) noexcept : VarLenIntFieldItem {type}
{
}

VarLenUIntFieldItem::VarLenUIntFieldItem() noexcept : VarLenUIntFieldItem {Type::VAR_LEN_UINT_FIELD}
{
}

void VarLenUIntFieldItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

VarLenSEnumFieldItem::VarLenSEnumFieldItem() noexcept :
    VarLenSIntFieldItem {Type::VAR_LEN_SENUM_FIELD}
{
}

void VarLenSEnumFieldItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

VarLenUEnumFieldItem::VarLenUEnumFieldItem() noexcept :
    VarLenUIntFieldItem {Type::VAR_LEN_UENUM_FIELD}
{
}

void VarLenUEnumFieldItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

NullTerminatedStrFieldBeginItem::NullTerminatedStrFieldBeginItem() noexcept :
    BeginItem {Type::NULL_TERMINATED_STR_FIELD_BEGIN}
{
}

void NullTerminatedStrFieldBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

NullTerminatedStrFieldEndItem::NullTerminatedStrFieldEndItem() noexcept :
    EndItem {Type::NULL_TERMINATED_STR_FIELD_END}
{
}

void NullTerminatedStrFieldEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

StrFieldSubstrItem::StrFieldSubstrItem() noexcept : Item {Type::STR_FIELD_SUBSTR}
{
}

void StrFieldSubstrItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

BlobFieldSectionItem::BlobFieldSectionItem() noexcept : Item {Type::BLOB_FIELD_SECTION}
{
}

void BlobFieldSectionItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

ArrayFieldBeginItem::ArrayFieldBeginItem(const Type type) noexcept : BeginItem {type}
{
}

ArrayFieldEndItem::ArrayFieldEndItem(const Type type) noexcept : EndItem {type}
{
}

StaticLenArrayFieldBeginItem::StaticLenArrayFieldBeginItem() noexcept :
    ArrayFieldBeginItem {Type::STATIC_LEN_ARRAY_FIELD_BEGIN}
{
}

void StaticLenArrayFieldBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

StaticLenArrayFieldEndItem::StaticLenArrayFieldEndItem() noexcept :
    ArrayFieldEndItem {Type::STATIC_LEN_ARRAY_FIELD_END}
{
}

void StaticLenArrayFieldEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

DynLenArrayFieldBeginItem::DynLenArrayFieldBeginItem() noexcept :
    ArrayFieldBeginItem {Type::DYN_LEN_ARRAY_FIELD_BEGIN}
{
}

void DynLenArrayFieldBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

DynLenArrayFieldEndItem::DynLenArrayFieldEndItem() noexcept :
    ArrayFieldEndItem {Type::DYN_LEN_ARRAY_FIELD_END}
{
}

void DynLenArrayFieldEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

StaticLenStrFieldBeginItem::StaticLenStrFieldBeginItem() noexcept :
    NonNullTerminatedStrFieldBeginItem {Type::STATIC_LEN_STR_FIELD_BEGIN}
{
}

void StaticLenStrFieldBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

StaticLenStrFieldEndItem::StaticLenStrFieldEndItem() noexcept :
    NonNullTerminatedStrFieldEndItem {Type::STATIC_LEN_STR_FIELD_END}
{
}

void StaticLenStrFieldEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

DynLenStrFieldBeginItem::DynLenStrFieldBeginItem() noexcept :
    NonNullTerminatedStrFieldBeginItem {Type::DYN_LEN_STR_FIELD_BEGIN}
{
}

void DynLenStrFieldBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

DynLenStrFieldEndItem::DynLenStrFieldEndItem() noexcept :
    NonNullTerminatedStrFieldEndItem {Type::DYN_LEN_STR_FIELD_END}
{
}

void DynLenStrFieldEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

StaticLenBlobFieldBeginItem::StaticLenBlobFieldBeginItem() noexcept :
    BlobFieldBeginItem {Type::STATIC_LEN_BLOB_FIELD_BEGIN}
{
}

void StaticLenBlobFieldBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

StaticLenBlobFieldEndItem::StaticLenBlobFieldEndItem() noexcept :
    BlobFieldEndItem {Type::STATIC_LEN_BLOB_FIELD_END}
{
}

void StaticLenBlobFieldEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

DynLenBlobFieldBeginItem::DynLenBlobFieldBeginItem() noexcept :
    BlobFieldBeginItem {Type::DYN_LEN_BLOB_FIELD_BEGIN}
{
}

void DynLenBlobFieldBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

DynLenBlobFieldEndItem::DynLenBlobFieldEndItem() noexcept :
    BlobFieldEndItem {Type::DYN_LEN_BLOB_FIELD_END}
{
}

void DynLenBlobFieldEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

StructFieldBeginItem::StructFieldBeginItem() noexcept : BeginItem {Type::STRUCT_FIELD_BEGIN}
{
}

void StructFieldBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

StructFieldEndItem::StructFieldEndItem() noexcept : EndItem {Type::STRUCT_FIELD_END}
{
}

void StructFieldEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

VariantFieldBeginItem::VariantFieldBeginItem(const Type type) noexcept : BeginItem {type}
{
}

VariantFieldEndItem::VariantFieldEndItem(const Type type) noexcept : EndItem {type}
{
}

void VariantFieldWithUIntSelBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

void VariantFieldWithUIntSelEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

void VariantFieldWithSIntSelBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

void VariantFieldWithSIntSelEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

OptionalFieldBeginItem::OptionalFieldBeginItem(const Type type) noexcept : BeginItem {type}
{
}

OptionalFieldEndItem::OptionalFieldEndItem(const Type type) noexcept : EndItem {type}
{
}

OptionalFieldWithBoolSelBeginItem::OptionalFieldWithBoolSelBeginItem() noexcept :
    OptionalFieldBeginItem {Item::Type::OPTIONAL_FIELD_WITH_BOOL_SEL_BEGIN}
{
}

void OptionalFieldWithBoolSelBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

OptionalFieldWithBoolSelEndItem::OptionalFieldWithBoolSelEndItem() noexcept :
    OptionalFieldEndItem {Item::Type::OPTIONAL_FIELD_WITH_BOOL_SEL_END}
{
}

void OptionalFieldWithBoolSelEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

void OptionalFieldWithUIntSelBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

void OptionalFieldWithUIntSelEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

void OptionalFieldWithSIntSelBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

void OptionalFieldWithSIntSelEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

} /* namespace src */
} /* namespace ctf */
