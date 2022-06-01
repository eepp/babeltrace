/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 Simon Marchi <simon.marchi@efficios.com>
 */

#ifndef SRC_PLUGINS_CTF_COMMON_SRC_ITEM_SEQ_LOGGING_ITEM_VISITOR_HPP
#define SRC_PLUGINS_CTF_COMMON_SRC_ITEM_SEQ_LOGGING_ITEM_VISITOR_HPP

#include "common/common.h"
#include "item-visitor.hpp"
#include "cpp-common/log-cfg.hpp"
#include "item.hpp"
#include <iomanip>
#include <sstream>

namespace ctf {
namespace src {

class LoggingItemVisitor final : public ctf::src::ItemVisitor
{
public:
    LoggingItemVisitor(const bt2_common::LogCfg logCfg) : _mLogCfg {logCfg}
    {
    }

    void visit(const Item& item) override;

    void visit(const BeginItem& item) override;
    void visit(const EndItem& item) override;
    void visit(const ScopeBeginItem& item) override;
    void visit(const ScopeEndItem& item) override;

    void visit(const DataStreamInfoItem& item) override;
    void visit(const PktInfoItem& item) override;
    void visit(const EventRecordInfoItem& item) override;

    void visit(const StaticLenArrayFieldBeginItem& item) override;
    void visit(const DynLenArrayFieldBeginItem& item) override;

    void visit(const PktMagicNumberItem& item) override;
    void visit(const MetadataStreamUuidItem& item) override;
    void visit(const DefClkValItem& item) override;

    void visit(const FixedLenUIntFieldItem& item) override;
    void visit(const VarLenUIntFieldItem& item) override;
    void visit(const FixedLenSIntFieldItem& item) override;
    void visit(const VarLenSIntFieldItem& item) override;

    void visit(const StaticLenStrFieldBeginItem& item) override;
    void visit(const DynLenStrFieldBeginItem& item) override;
    void visit(const StrFieldSubstrItem& item) override;

private:
    void _log(const Item& item, const char *extra = nullptr);

    void _log(const Item& item, const std::stringstream& ss)
    {
        this->_log(item, ss.str().c_str());
    }

    template <typename FcT>
    void _commonRoles(std::stringstream& ss, const FcT& fc)
    {
        if (fc.roles().empty()) {
            return;
        }

        /*
         * Assume `roles` is never the first one printed, so print a leading
         * comma.
         */
        ss << ", roles: [";
        const char *maybeComma = "";
        for (auto role : fc.roles()) {
            ss << maybeComma << ir::UIntFieldRoleStr(role);
            maybeComma = ", ";
        }
        ss << ']';
    }

    template <typename ItemT>
    void _commonIntVal(std::stringstream& ss, const ItemT& item)
    {
        ss << "val: ";

        switch (item.cls().prefDispBase()) {
        case ir::DispBase::OCT:
            ss << std::setbase(8) << '0' << item.val() << std::setbase(10);
            break;

        case ir::DispBase::DEC:
        case ir::DispBase::BIN:
            // FIXME: implement BIN
            ss << item.val();
            break;

        case ir::DispBase::HEX:
            ss << std::setbase(16) << "0x" << item.val() << std::setbase(10);
            break;
        }
    }

    template <typename ItemT>
    void _commonLenBits(std::stringstream& ss, const ItemT& item)
    {
        ss << "len: " << item.len().bits() << " bits";
    }

    template <typename ItemT>
    void _commonLenBytes(std::stringstream& ss, const ItemT& item)
    {
        BT_ASSERT(!item.len().hasExtraBits());
        ss << "len: " << item.len().bytes() << " bytes";
    }

    int _mNesting = 0;
    const bt2_common::LogCfg _mLogCfg;
};

} /* namespace src */
} /* namespace ctf */

#endif /* SRC_PLUGINS_CTF_COMMON_SRC_ITEM_SEQ_LOGGING_ITEM_VISITOR_HPP */
