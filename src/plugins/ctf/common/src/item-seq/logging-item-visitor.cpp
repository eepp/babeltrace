/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 Simon Marchi <simon.marchi@efficios.com>
 */

#define BT_CLOG_CFG         (_mLogCfg)
#define BT_LOG_OUTPUT_LEVEL (_mLogCfg.logLevel())
#define BT_LOG_TAG          "PLUGIN/CTF/LOGGING-ITEM-VISITOR"
#include "logging/comp-logging.h"

#include "logging-item-visitor.hpp"
#include "common/common.h"
#include <string>
#include "item.hpp"
#include "cpp-common/cfg-logging.hpp"

namespace ctf {
namespace src {

void LoggingItemVisitor::_log(const Item& item, const char *extra)
{
    std::string indent(_mNesting * 2, ' ');

    if (extra) {
        BT_CLOGD("%s%s (%s)", indent.c_str(), ItemTypeStr(item.type()), extra);
    } else {
        BT_CLOGD("%s%s", indent.c_str(), ItemTypeStr(item.type()));
    }
}

void LoggingItemVisitor::visit(const Item& item)
{
    this->_log(item);
}

void LoggingItemVisitor::visit(const BeginItem& item)
{
    this->_log(item);
    ++_mNesting;
}

void LoggingItemVisitor::visit(const EndItem& item)
{
    --_mNesting;
    this->_log(item);
}

void LoggingItemVisitor::visit(const ScopeBeginItem& item)
{
    std::stringstream ss;
    ss << "scope: " << ir::FieldLocScopeStr(item.scope());
    this->_log(item, ss);
    ++_mNesting;
}

void LoggingItemVisitor::visit(const ScopeEndItem& item)
{
    --_mNesting;
    std::stringstream ss;
    ss << "scope: " << ir::FieldLocScopeStr(item.scope());
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const DataStreamInfoItem& item)
{
    std::stringstream ss;

    if (item.id()) {
        ss << "id: " << *item.id() << ", ";
    }

    ss << "cls-id: " << item.cls()->id();
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const PktInfoItem& item)
{
    std::stringstream ss;
    const char *maybeComma = "";

    if (item.seqNum()) {
        ss << "seq-num: " << *item.seqNum();
        maybeComma = ", ";
    }

    if (item.discEventRecordCounterSnap()) {
        ss << maybeComma << "disc-evts: " << *item.discEventRecordCounterSnap();
        maybeComma = ", ";
    }

    if (item.expectedTotalLen()) {
        ss << maybeComma << "total-len: " << item.expectedTotalLen()->bits() << " bits";
        maybeComma = ", ";
    }

    if (item.expectedContentLen()) {
        ss << maybeComma << "content-len: " << item.expectedContentLen()->bits() << " bits";
        maybeComma = ", ";
    }

    if (item.beginDefClkVal()) {
        ss << maybeComma << "begin-clk: " << *item.beginDefClkVal();
        maybeComma = ", ";
    }

    if (item.endDefClkVal()) {
        ss << maybeComma << "end-clk: " << *item.endDefClkVal();
        maybeComma = ", ";
    }

    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const EventRecordInfoItem& item)
{
    std::stringstream ss;
    const char *maybeComma = "";

    if (item.defClkVal()) {
        ss << "clk-val: " << *item.defClkVal();
        maybeComma = ", ";
    }

    if (item.cls()) {
        ss << maybeComma << "cls-id: " << item.cls()->id();

        if (item.cls()->name()) {
            ss << ", cls-name: " << *item.cls()->name();
        }

        if (item.cls()->ns()) {
            ss << ", cls-ns: " << *item.cls()->ns();
        }
    }

    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const StaticLenArrayFieldBeginItem& item)
{
    std::stringstream ss;

    ss << "len: " << item.cls().len() << " elements";
    this->_log(item, ss);
    ++_mNesting;
}
void LoggingItemVisitor::visit(const DynLenArrayFieldBeginItem& item)
{
    std::stringstream ss;

    ss << "len: " << item.len() << " elements";
    this->_log(item, ss);
    ++_mNesting;
}

void LoggingItemVisitor::visit(const PktMagicNumberItem& item)
{
    std::stringstream ss;
    ss << "magic: 0x" << std::setbase(16) << item.val();
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const MetadataStreamUuidItem& item)
{
    std::stringstream ss;
    ss << "uuid: " << item.uuid().str().c_str();
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const DefClkValItem& item)
{
    std::stringstream ss;
    ss << "cycles: " << item.cycles();
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const FixedLenUIntFieldItem& item)
{
    std::stringstream ss;
    this->_commonIntVal(ss, item);
    ss << ", ";
    this->_commonLenBits(ss, item.cls());
    this->_commonRoles(ss, item.cls());
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const VarLenUIntFieldItem& item)
{
    std::stringstream ss;
    this->_commonIntVal(ss, item);
    ss << ", ";
    this->_commonLenBits(ss, item);
    this->_commonRoles(ss, item.cls());
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const FixedLenSIntFieldItem& item)
{
    std::stringstream ss;
    this->_commonIntVal(ss, item);
    ss << ", ";
    this->_commonLenBits(ss, item.cls());
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const VarLenSIntFieldItem& item)
{
    std::stringstream ss;
    this->_commonIntVal(ss, item);
    ss << ", ";
    this->_commonLenBits(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const StaticLenStrFieldBeginItem& item)
{
    std::stringstream ss;
    ss << "len: " << item.cls().len() << " bytes";
    this->_log(item, ss);
    ++_mNesting;
}

void LoggingItemVisitor::visit(const DynLenStrFieldBeginItem& item)
{
    std::stringstream ss;
    this->_commonLenBytes(ss, item);
    this->_log(item, ss);
    ++_mNesting;
}

void LoggingItemVisitor::visit(const StrFieldSubstrItem& item)
{
    std::stringstream ss;

    ss << "val: ";

    for (const char c : item) {
        if (c == '\\') {
            ss << "\\\\";
        } else if (std::isprint(c)) {
            ss << c;
        } else {
            auto flags = ss.flags();
            ss << "\\x" << std::setbase(16) << std::setfill('0') << std::setw(2) << (int) c;
            ss.flags(flags);
        }
    }

    this->_log(item, ss);
}

} /* namespace src */
} /* namespace ctf */
