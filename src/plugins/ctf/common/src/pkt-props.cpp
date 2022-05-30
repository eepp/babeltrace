/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 EfficiOS Inc. and Linux Foundation
 */

#define BT_LOG_TAG  "PLUGIN/CTF/PKT-PROPS"
#define BT_CLOG_CFG logCfg

#include "pkt-props.hpp"
#include "../../common/src/item-seq/item-seq-iter.hpp"
#include "../../common/src/item-seq/logging-item-visitor.hpp"
#include "cpp-common/cfg-logging.hpp"

namespace ctf {
namespace src {
namespace {

struct ReadPacketPropertiesItemVisitor final : public ItemVisitor
{
    void visit(const DataStreamInfoItem& item) override
    {
        props.dataStreamCls = item.cls();
        props.dataStreamId = item.id();
    }

    void visit(const PktInfoItem& item) override
    {
        props.expectedTotalLen = item.expectedTotalLen();
        props.expectedContentLen = item.expectedContentLen();
        props.snapshots.discEventRecordCounter = item.discEventRecordCounterSnap();
        props.snapshots.beginDefClk = item.beginDefClkVal();
        props.snapshots.endDefClk = item.endDefClkVal();
        _mDone = true;
    }

    bool done() const noexcept
    {
        return _mDone;
    }

    PktProps props;

private:
    bool _mDone = false;
};
} /* namespace */

PktProps readPktProps(const TraceCls& traceCls, Medium::UP medium,
                      const bt2_common::DataLen pktOffset, const bt2_common::LogCfg& logCfg)
{
    BT_CLOGD("Read packet properties: pkt-offset-bytes=%llu", pktOffset.bytes());

    ItemSeqIter itemSeqIter {std::move(medium), traceCls, pktOffset, logCfg};
    ReadPacketPropertiesItemVisitor visitor;
    LoggingItemVisitor loggingVisitor {logCfg};

    while (!visitor.done()) {
        const Item *item = itemSeqIter.next();
        BT_ASSERT(item);

        if (BT_LOG_ON_TRACE) {
            item->accept(loggingVisitor);
        }

        item->accept(visitor);
    }

    return visitor.props;
}

} /* namespace src */
} /* namespace ctf */
