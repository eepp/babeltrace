/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 EfficiOS Inc. and Linux Foundation
 */

#include "pkt-props.hpp"
#include "plugins/ctf/common/src/item-seq/item-seq-iter.hpp"

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
                      const bt2_common::DataLen pktOffset)
{
    ItemSeqIter itemSeqIter {std::move(medium), traceCls, pktOffset};
    ReadPacketPropertiesItemVisitor visitor;

    while (!visitor.done()) {
        itemSeqIter->accept(visitor);
        ++itemSeqIter;
    }

    return visitor.props;
}

} /* namespace src */
} /* namespace ctf */
