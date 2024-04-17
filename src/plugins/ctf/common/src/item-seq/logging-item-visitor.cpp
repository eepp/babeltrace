/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 Simon Marchi <simon.marchi@efficios.com>
 * Copyright (c) 2022 Philippe Proulx <eeppeliteloop@gmail.com>
 */

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <string>

#include "common/assert.h"
#include "common/common.h"

#include "item.hpp"
#include "logging-item-visitor.hpp"

namespace ctf {
namespace src {

LoggingItemVisitor::LoggingItemVisitor(const bt2c::Logger& parentLogger) :
    LoggingItemVisitor {"Processing item", parentLogger}
{
}

LoggingItemVisitor::LoggingItemVisitor(std::string intro, const bt2c::Logger& parentLogger) :
    _mIntro {std::move(intro)}, _mLogger {parentLogger, "PLUGIN/CTF/LOGGING-ITEM-VISITOR"}
{
}

template <typename ValT>
void appendVal(std::ostringstream& ss, const ValT& val)
{
    ss << val;
}

template <>
inline void appendVal<bool>(std::ostringstream& ss, const bool& val)
{
    ss << (val ? "true" : "false");
}

template <typename ValT>
void appendField(std::ostringstream& ss, const char * const name, const ValT& val)
{
    ss << ", " << name << '=';
    appendVal(ss, val);
}

static void appendDataLenBitsField(std::ostringstream& ss, const bt2c::DataLen& len)
{
    appendField(ss, "len-bits", len.bits());
}

static void appendDataLenBytesField(std::ostringstream& ss, const bt2c::DataLen& len)
{
    BT_ASSERT_DBG(!len.hasExtraBits());
    appendField(ss, "len-bytes", len.bytes());
}

template <typename ItemT>
void appendItemDataLenBitsField(std::ostringstream& ss, const ItemT& item)
{
    appendDataLenBitsField(ss, item.len());
}

template <typename ItemT>
void appendItemDataLenBytesField(std::ostringstream& ss, const ItemT& item)
{
    appendDataLenBytesField(ss, item.len());
}

template <typename ItemT>
void appendItemLenField(std::ostringstream& ss, const ItemT& item)
{
    appendField(ss, "len", item.len());
}

template <typename ItemT>
void appendItemFirstBytesField(std::ostringstream& ss, const ItemT& item)
{
    if (item.size().bytes() > 0) {
        const auto fill = ss.fill();

        ss << ", first-bytes=";

        for (std::size_t i = 0; i < std::min(item.size().bytes(), 8ULL); ++i) {
            ss << std::setbase(16) << std::setw(2) << std::setfill('0')
               << static_cast<unsigned int>(item.begin()[i]);
        }

        ss << std::setbase(0) << std::setw(0) << std::setfill(fill);
    }
}

void LoggingItemVisitor::visit(const Item& item)
{
    std::ostringstream ss;

    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const BlobFieldSectionItem& item)
{
    std::ostringstream ss;

    appendDataLenBytesField(ss, item.size());
    appendItemFirstBytesField(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const DataStreamInfoItem& item)
{
    std::ostringstream ss;

    if (item.id()) {
        appendField(ss, "id", *item.id());
    }

    appendField(ss, "cls-id", item.cls()->id());
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const DefClkValItem& item)
{
    std::ostringstream ss;

    appendField(ss, "cycles", item.cycles());
    this->_log(item, ss);
}

template <typename ItemT>
void appendItemMinAlignField(std::ostringstream& ss, const ItemT& item)
{
    appendField(ss, "min-align", item.cls().minAlign());
}

void LoggingItemVisitor::visit(const DynLenArrayFieldBeginItem& item)
{
    std::ostringstream ss;

    appendItemMinAlignField(ss, item);
    appendItemLenField(ss, item);
    this->_log(item, ss);
}

template <typename ItemT>
void appendBlobFieldBeginItemMediaTypeField(std::ostringstream& ss, const ItemT& item)
{
    appendField(ss, "media-type", item.cls().mediaType());
}

void LoggingItemVisitor::visit(const DynLenBlobFieldBeginItem& item)
{
    std::ostringstream ss;

    appendBlobFieldBeginItemMediaTypeField(ss, item);
    appendItemDataLenBytesField(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const DynLenStrFieldBeginItem& item)
{
    std::ostringstream ss;

    appendItemDataLenBytesField(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const EventRecordInfoItem& item)
{
    std::ostringstream ss;

    if (item.defClkVal()) {
        appendField(ss, "def-clk-val", *item.defClkVal());
    }

    if (item.cls()) {
        appendField(ss, "cls-id", item.cls()->id());

        if (item.cls()->name()) {
            appendField(ss, "cls-name", *item.cls()->name());
        }

        if (item.cls()->ns()) {
            appendField(ss, "cls-ns", *item.cls()->ns());
        }
    }

    this->_log(item, ss);
}

static void appendFixedLenBitArrayFieldItemFields(std::ostringstream& ss,
                                                  const FixedLenBitArrayFieldItem& item)
{
    appendDataLenBitsField(ss, item.cls().len());
    appendField(ss, "byte-order", item.cls().byteOrder() == ir::ByteOrder::BIG ? "be" : "le");
    appendField(ss, "align", item.cls().align());
}

void LoggingItemVisitor::visit(const FixedLenBitArrayFieldItem& item)
{
    std::ostringstream ss;

    appendFixedLenBitArrayFieldItemFields(ss, item);
    appendField(ss, "val-as-uint", item.uIntVal());
    this->_log(item, ss);
}

template <typename ItemT>
void appendItemValField(std::ostringstream& ss, const ItemT& item)
{
    appendField(ss, "val", item.val());
}

void LoggingItemVisitor::visit(const FixedLenBoolFieldItem& item)
{
    std::ostringstream ss;

    appendFixedLenBitArrayFieldItemFields(ss, item);
    appendItemValField(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const FixedLenFloatFieldItem& item)
{
    std::ostringstream ss;

    appendFixedLenBitArrayFieldItemFields(ss, item);
    appendItemValField(ss, item);
    this->_log(item, ss);
}

template <typename ItemT>
void appendIntFieldItemVal(std::ostringstream& ss, const ItemT& item)
{
    ss << ", val=";

    switch (item.cls().prefDispBase()) {
    case ir::DispBase::OCT:
        ss << '0' << std::setbase(8) << item.val() << std::setbase(0);
        break;
    case ir::DispBase::DEC:
    case ir::DispBase::BIN:
        /* TODO: Implement binary formatting */
        ss << item.val();
        break;
    case ir::DispBase::HEX:
        ss << "0x" << std::setbase(16) << item.val() << std::setbase(0);
        break;
    default:
        bt_common_abort();
    }
}

void LoggingItemVisitor::visit(const FixedLenSIntFieldItem& item)
{
    std::ostringstream ss;

    appendFixedLenBitArrayFieldItemFields(ss, item);
    appendIntFieldItemVal(ss, item);
    this->_log(item, ss);
}

static const char *uIntFieldRoleStr(const ir::UIntFieldRole role) noexcept
{
    switch (role) {
    case ir::UIntFieldRole::PKT_MAGIC_NUMBER:
        return "PKT_MAGIC_NUMBER";
    case ir::UIntFieldRole::DATA_STREAM_CLS_ID:
        return "DATA_STREAM_CLS_ID";
    case ir::UIntFieldRole::DATA_STREAM_ID:
        return "DATA_STREAM_ID";
    case ir::UIntFieldRole::PKT_TOTAL_LEN:
        return "PKT_TOTAL_LEN";
    case ir::UIntFieldRole::PKT_CONTENT_LEN:
        return "PKT_CONTENT_LEN";
    case ir::UIntFieldRole::DEF_CLK_TS:
        return "DEF_CLK_TS";
    case ir::UIntFieldRole::PKT_END_DEF_CLK_TS:
        return "PKT_END_DEF_CLK_TS";
    case ir::UIntFieldRole::DISC_EVENT_RECORD_COUNTER_SNAP:
        return "DISC_EVENT_RECORD_COUNTER_SNAP";
    case ir::UIntFieldRole::PKT_SEQ_NUM:
        return "PKT_SEQ_NUM";
    case ir::UIntFieldRole::EVENT_RECORD_CLS_ID:
        return "EVENT_RECORD_CLS_ID";
    default:
        bt_common_abort();
    }
}

template <typename ItemT>
void appendUIntFieldItemRolesField(std::ostringstream& ss, const ItemT& item)
{
    if (item.cls().roles().empty()) {
        return;
    }

    ss << ", roles=[";

    auto prependComma = false;

    for (const auto role : item.cls().roles()) {
        if (prependComma) {
            ss << ", ";
        }

        ss << uIntFieldRoleStr(role);
        prependComma = true;
    }

    ss << ']';
}

void LoggingItemVisitor::visit(const FixedLenUIntFieldItem& item)
{
    std::ostringstream ss;

    appendFixedLenBitArrayFieldItemFields(ss, item);
    appendUIntFieldItemRolesField(ss, item);
    appendIntFieldItemVal(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const MetadataStreamUuidItem& item)
{
    std::ostringstream ss;

    appendField(ss, "uuid", item.uuid().str().c_str());
    this->_log(item, ss);
}

template <typename ItemT>
void appendItemSelValField(std::ostringstream& ss, const ItemT& item)
{
    appendField(ss, "sel-val", item.selVal());
}

template <typename ItemT>
void appendOptionalFieldBeginItemFields(std::ostringstream& ss, const ItemT& item)
{
    appendItemSelValField(ss, item);
    appendField(ss, "is-enabled", item.isEnabled());
}

void LoggingItemVisitor::visit(const OptionalFieldWithBoolSelBeginItem& item)
{
    std::ostringstream ss;

    appendOptionalFieldBeginItemFields(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const OptionalFieldWithSIntSelBeginItem& item)
{
    std::ostringstream ss;

    appendOptionalFieldBeginItemFields(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const OptionalFieldWithUIntSelBeginItem& item)
{
    std::ostringstream ss;

    appendOptionalFieldBeginItemFields(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const PktInfoItem& item)
{
    std::ostringstream ss;

    if (item.seqNum()) {
        appendField(ss, "seq-num", *item.seqNum());
    }

    if (item.discEventRecordCounterSnap()) {
        appendField(ss, "disc-er-counter-snap", *item.discEventRecordCounterSnap());
    }

    if (item.expectedTotalLen()) {
        appendField(ss, "exp-total-len-bits", item.expectedTotalLen()->bits());
    }

    if (item.expectedContentLen()) {
        appendField(ss, "exp-content-len-bits", item.expectedContentLen()->bits());
    }

    if (item.beginDefClkVal()) {
        appendField(ss, "begin-def-clk-val", *item.beginDefClkVal());
    }

    if (item.endDefClkVal()) {
        appendField(ss, "end-def-clk-val", *item.endDefClkVal());
    }

    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const PktMagicNumberItem& item)
{
    std::ostringstream ss;

    appendItemValField(ss, item);
    this->_log(item, ss);
}

static const char *fieldLocScopeStr(const ir::FieldLocScope scope) noexcept
{
    switch (scope) {
    case ir::FieldLocScope::PKT_HEADER:
        return "PKT_HEADER";
    case ir::FieldLocScope::PKT_CTX:
        return "PKT_CTX";
    case ir::FieldLocScope::EVENT_RECORD_HEADER:
        return "EVENT_RECORD_HEADER";
    case ir::FieldLocScope::EVENT_RECORD_COMMON_CTX:
        return "EVENT_RECORD_COMMON_CTX";
    case ir::FieldLocScope::EVENT_RECORD_SPEC_CTX:
        return "EVENT_RECORD_SPEC_CTX";
    case ir::FieldLocScope::EVENT_RECORD_PAYLOAD:
        return "EVENT_RECORD_PAYLOAD";
    default:
        bt_common_abort();
    }
}

static void appendScopeItemScopeField(std::ostringstream& ss, const ScopeItem& item)
{
    appendField(ss, "scope", fieldLocScopeStr(item.scope()));
}

void LoggingItemVisitor::visit(const ScopeBeginItem& item)
{
    std::ostringstream ss;

    appendScopeItemScopeField(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const ScopeEndItem& item)
{
    std::ostringstream ss;

    appendScopeItemScopeField(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const StaticLenArrayFieldBeginItem& item)
{
    std::ostringstream ss;

    appendItemMinAlignField(ss, item);
    appendField(ss, "len", item.cls().len());
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const StaticLenBlobFieldBeginItem& item)
{
    std::ostringstream ss;

    appendBlobFieldBeginItemMediaTypeField(ss, item);
    appendDataLenBytesField(ss, bt2c::DataLen::fromBytes(item.cls().len()));
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const StaticLenStrFieldBeginItem& item)
{
    std::ostringstream ss;

    appendDataLenBytesField(ss, bt2c::DataLen::fromBytes(item.cls().len()));
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const StrFieldSubstrItem& item)
{
    std::ostringstream ss;

    appendDataLenBytesField(ss, item.size());
    appendItemFirstBytesField(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const StructFieldBeginItem& item)
{
    std::ostringstream ss;

    appendItemMinAlignField(ss, item);
    appendField(ss, "member-count", item.cls().size());
    this->_log(item, ss);
}

static void appendVariantFieldBeginItemSelOptIndexField(std::ostringstream& ss,
                                                        const VariantFieldBeginItem& item)
{
    appendField(ss, "sel-opt-index", item.selectedOptIndex());
}

void LoggingItemVisitor::visit(const VariantFieldWithSIntSelBeginItem& item)
{
    std::ostringstream ss;

    appendItemSelValField(ss, item);
    appendVariantFieldBeginItemSelOptIndexField(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const VariantFieldWithUIntSelBeginItem& item)
{
    std::ostringstream ss;

    appendItemSelValField(ss, item);
    appendVariantFieldBeginItemSelOptIndexField(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const VarLenSIntFieldItem& item)
{
    std::ostringstream ss;

    appendItemDataLenBitsField(ss, item);
    appendIntFieldItemVal(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const VarLenUIntFieldItem& item)
{
    std::ostringstream ss;

    appendItemDataLenBitsField(ss, item);
    appendUIntFieldItemRolesField(ss, item);
    appendIntFieldItemVal(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::_log(const Item& item, const std::ostringstream& extra)
{
    BT_CPPLOGT("{}: type={}{}", _mIntro, item.type(), extra.str());
}

} /* namespace src */
} /* namespace ctf */
