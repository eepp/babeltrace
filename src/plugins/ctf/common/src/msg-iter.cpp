/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2015-2018 EfficiOS Inc. and Linux Foundation
 * Copyright (c) 2015-2018 Philippe Proulx <pproulx@efficios.com>
 *
 * Babeltrace - CTF message iterator
 */

#define BT_CLOG_CFG         (_mLogCfg)
#define BT_LOG_OUTPUT_LEVEL (_mLogCfg.logLevel())
#define BT_LOG_TAG          "PLUGIN/CTF/MSG-ITER"
#include "logging/comp-logging.h"

#include "msg-iter.hpp"

#include "cpp-common/cfg-logging.hpp"
#include "cpp-common/cfg-logging-error-reporting-throw.hpp"
#include "cpp-common/data-len.hpp"

#include "item-seq/item.hpp"

using namespace bt2_common::literals::datalen;

namespace ctf {
namespace src {

static bool ignoreField(const FieldItem& item)
{
    return !item.cls().libCls();
}

namespace internal {

MsgIterItemVisitor::MsgIterItemVisitor(bt_self_message_iterator *selfMsgIter,
                                       ItemSeqIter& itemSeqIter, LoggingItemVisitor& loggingVisitor,
                                       bt2::Stream stream, const Quirks quirks,
                                       const bt2_common::LogCfg& logCfg) :
    _mSelfMsgIter(selfMsgIter),
    _mLibStream(stream), _mQuirks(quirks), _mLogCfg(logCfg)
{
}

void MsgIterItemVisitor::visit(const Item& item)
{
    /*
     * This is used to detect which item types we don't handle yet.  This is
     * useful for development, but it can eventually be removed (along with
     * empty visit methods).
     */
    BT_CLOGD("MsgIterItemVisitor unhandled item: item-type=%s", ItemTypeStr(item.type()));
    abort();
}

void MsgIterItemVisitor::visit(const DefClkValItem& item)
{
}

void MsgIterItemVisitor::visit(const PktBeginItem& item)
{
    BT_ASSERT_DBG(!this->_currentPacket());
    this->_currentPacket(_mLibStream.createPacket());
}

void MsgIterItemVisitor::visit(const PktContentBeginItem& item)
{
}

void MsgIterItemVisitor::visit(const PktInfoItem& item)
{
    /*
     * Record the packet begin and end times. Save the previous packet's end,
     * we might need it if there are discarded events.
     */
    nonstd::optional<unsigned long long> prevPacketEndDefClkVal = _mPacketEndDefClkVal;
    _mPacketBeginDefClkVal = item.beginDefClkVal();
    _mPacketEndDefClkVal = item.endDefClkVal();

    /*
     * Emit a discarded events message if the count of discarded events went up
     * since the previous packet.  For the first packet, `_mLastDiscardedEventsSnap`
     * does not have a value (we don't have anything to compare to).
     */
    const nonstd::optional<unsigned long long> discardedEventsSnap =
        item.discEventRecordCounterSnap();
    if (_mLastDiscardedEventsSnap) {
        /*
         * If we have a discarded events snapshot in a previous packet of this
         * stream, we must have one now too.
         */
        BT_ASSERT_DBG(discardedEventsSnap);

        if (*discardedEventsSnap > *_mLastDiscardedEventsSnap) {
            bt_message *msg;

            if (_mLibStream.cls().discardedEventsHaveDefaultClockSnapshots()) {
                /*
                 * We know there was a previous packet, since we can't reach
                 * this point for the first packet.
                 */
                BT_ASSERT_DBG(prevPacketEndDefClkVal);
                unsigned long long beginningClkVal = *prevPacketEndDefClkVal;

                msg = bt_message_discarded_events_create_with_default_clock_snapshots(
                    _mSelfMsgIter, _mLibStream.libObjPtr(), beginningClkVal, *_mPacketEndDefClkVal);
            } else {
                msg = bt_message_discarded_events_create(_mSelfMsgIter, _mLibStream.libObjPtr());
            }

            bt_message_discarded_events_set_count(msg, *discardedEventsSnap -
                                                           *_mLastDiscardedEventsSnap);
            _mMessagesReady.emplace(bt2::ConstMessage::Shared::createWithoutRef(msg));
        }
    }

    _mLastDiscardedEventsSnap = discardedEventsSnap;

    /*
     * Emit a discarded packets message if there's a gap between the previous
     * seen packet sequence number of this packet's sequence number.
     */
    const nonstd::optional<unsigned long long> seqNum = item.seqNum();
    if (_mLastPacketSeqNum) {
        BT_ASSERT_DBG(seqNum);

        if (*_mLastPacketSeqNum + 1 < *seqNum) {
            bt_message *msg;

            if (_mLibStream.cls().discardedPacketsHaveDefaultClockSnapshots()) {
                BT_ASSERT_DBG(prevPacketEndDefClkVal);
                msg = bt_message_discarded_packets_create_with_default_clock_snapshots(
                    _mSelfMsgIter, _mLibStream.libObjPtr(), *prevPacketEndDefClkVal,
                    *_mPacketBeginDefClkVal);
            } else {
                msg = bt_message_discarded_packets_create(_mSelfMsgIter, _mLibStream.libObjPtr());
            }

            bt_message_discarded_packets_set_count(msg, *seqNum - *_mLastPacketSeqNum - 1);
            _mMessagesReady.emplace(bt2::ConstMessage::Shared::createWithoutRef(msg));
        }
    }

    _mLastPacketSeqNum = seqNum;

    BT_ASSERT_DBG(!_mCurrentMessage);

    if (G_LIKELY(!_mQuirks.barectfEventBeforePacket)) {
        _emitPacketBeginningMsg(_mPacketBeginDefClkVal);
    } else {
        _mEmitDelayedPacketBeginning = true;
    }
}

void MsgIterItemVisitor::_emitDelayedPacketBeginning(
    nonstd::optional<unsigned long long> otherClkVal)
{
    BT_ASSERT_DBG(_mEmitDelayedPacketBeginning);
    _mEmitDelayedPacketBeginning = false;

    /*
     * Only fix the packet's timestamp_begin if it's larger than the first
     * event of the packet. If there was no event in the packet, the
     * `default_clock_snapshot` field will be either equal or greater than
     * `snapshots.beginning_clock` so there is not fix needed.
     */
    nonstd::optional<unsigned long long> clkVal;

    if (_mPacketBeginDefClkVal && otherClkVal) {
        clkVal = std::min(*_mPacketBeginDefClkVal, *otherClkVal);
    } else if (_mPacketBeginDefClkVal) {
        clkVal = _mPacketBeginDefClkVal;
    } else if (otherClkVal) {
        clkVal = otherClkVal;
    }

    return _emitPacketBeginningMsg(clkVal);
}

void MsgIterItemVisitor::_emitPacketBeginningMsg(nonstd::optional<unsigned long long> clkVal)
{
    bt_message *msg;

    if (clkVal) {
        _mLastClkVal = clkVal;

        msg = bt_message_packet_beginning_create_with_default_clock_snapshot(
            _mSelfMsgIter, this->_currentPacket(), *clkVal);
    } else {
        msg = bt_message_packet_beginning_create(_mSelfMsgIter, this->_currentPacket());
    }

    _mMessagesReady.emplace(bt2::ConstMessage::Shared::createWithoutRef(msg));
}

void MsgIterItemVisitor::visit(const DataStreamInfoItem& item)
{
    if (!_mSentStreamBeginning) {
        _mMessagesReady.emplace(bt2::ConstMessage::Shared::createWithoutRef(
            bt_message_stream_beginning_create(_mSelfMsgIter, _mLibStream.libObjPtr())));
        _mSentStreamBeginning = true;
    }
}

void MsgIterItemVisitor::visit(const PktContentEndItem& item)
{
    BT_ASSERT_DBG(this->_currentPacket());
}

void MsgIterItemVisitor::visit(const PktEndItem& item)
{
    BT_ASSERT_DBG(!_mCurrentMessage);
    BT_ASSERT_DBG(this->_currentPacket());

    if (G_UNLIKELY(_mEmitDelayedPacketBeginning)) {
        this->_emitDelayedPacketBeginning(_mPacketEndDefClkVal);
    }

    bt_message *msg;
    if (_mPacketEndDefClkVal) {
        bool lttngCrashBug = _mQuirks.lttngCrash && _mPacketBeginDefClkVal &&
                             _mPacketEndDefClkVal && *_mPacketBeginDefClkVal != 0 &&
                             *_mPacketEndDefClkVal == 0;
        bool lttngEventAfterPacketBug = _mQuirks.lttngEventAfterPacket && _mLastClkVal &&
                                        _mPacketEndDefClkVal &&
                                        *_mPacketEndDefClkVal < _mLastClkVal;

        nonstd::optional<unsigned long long> clkVal =
            (lttngCrashBug || lttngEventAfterPacketBug) ? _mLastClkVal : _mPacketEndDefClkVal;

        BT_ASSERT_DBG(clkVal);

        msg = bt_message_packet_end_create_with_default_clock_snapshot(
            _mSelfMsgIter, this->_currentPacket(), *clkVal);

        if (!lttngCrashBug && !lttngEventAfterPacketBug) {
            _mLastClkVal = _mPacketEndDefClkVal;
        }
    } else {
        msg = bt_message_packet_end_create(_mSelfMsgIter, this->_currentPacket());
    }

    _mMessagesReady.emplace(bt2::ConstMessage::Shared::createWithoutRef(msg));

    this->_resetCurrentPacket();
}

void MsgIterItemVisitor::visit(const EventRecordInfoItem& item)
{
    // TODO: test having a trace with only event headers
    const EventRecordCls *erc = item.cls();
    BT_ASSERT_DBG(erc);
    nonstd::optional<unsigned long long> defClkVal = item.defClkVal();

    BT_ASSERT_DBG(!_mCurrentMessage);

    if (_mEmitDelayedPacketBeginning) {
        this->_emitDelayedPacketBeginning(defClkVal);
    }

    bt_packet *packet = this->_currentPacket();
    bt_message *msg;
    if (defClkVal) {
        if (packet) {
            msg = bt_message_event_create_with_packet_and_default_clock_snapshot(
                _mSelfMsgIter, erc->libCls()->libObjPtr(), packet, *defClkVal);
        } else {
            msg = bt_message_event_create_with_default_clock_snapshot(
                _mSelfMsgIter, erc->libCls()->libObjPtr(), _mLibStream.libObjPtr(), *defClkVal);
        }

        _mLastClkVal = defClkVal;
    } else {
        if (packet) {
            msg = bt_message_event_create_with_packet(_mSelfMsgIter, erc->libCls()->libObjPtr(),
                                                      packet);
        } else {
            msg = bt_message_event_create(_mSelfMsgIter, erc->libCls()->libObjPtr(),
                                          _mLibStream.libObjPtr());
        }
    }

    _mCurrentMessage.emplace(bt2::Message::Shared::createWithoutRef(msg));
}

void MsgIterItemVisitor::visit(const EventRecordBeginItem& item)
{
}

void MsgIterItemVisitor::visit(const EventRecordEndItem& item)
{
    BT_ASSERT_DBG(_mStack.empty());
    BT_ASSERT_DBG(_mCurrentMessage);
    _mMessagesReady.emplace(
        bt2::ConstMessage::Shared::createWithoutRef((_mCurrentMessage->release())));
    _mCurrentMessage.reset();
}

void MsgIterItemVisitor::visit(const ScopeBeginItem& item)
{
    BT_ASSERT(_mStack.empty());
    BT_ASSERT(!_mCurRootScopeStructField);

    switch (item.scope()) {
    case ctf::ir::FieldLocScope::PKT_HEADER:
    {
        /*
         * We don't need anything in the packet header, just fast-forward.
         */
        _mSkipUntilScopeEnd = true;
        return;
    }

    case ir::FieldLocScope::PKT_CTX:
    {
        bt_packet *packet = this->_currentPacket();
        BT_ASSERT_DBG(packet);
        bt_field *packetContextField = bt_packet_borrow_context_field(packet);

        if (packetContextField)
            _mCurRootScopeStructField = bt2::StructureField {packetContextField};
        else
            _mSkipUntilScopeEnd = true;

        return;
    }

    case ir::FieldLocScope::EVENT_RECORD_HEADER:
    {
        /*
         * We don't need anything in the event record header, just
         * fast-forward.
         */
        _mSkipUntilScopeEnd = true;
        return;
    }

    case ir::FieldLocScope::EVENT_RECORD_COMMON_CTX:
    {
        bt_event *event = bt_message_event_borrow_event((*_mCurrentMessage)->libObjPtr());
        bt_field *commonContextField = bt_event_borrow_common_context_field(event);

        if (commonContextField)
            _mCurRootScopeStructField = bt2::StructureField {commonContextField};
        else
            _mSkipUntilScopeEnd = true;

        return;
    }

    case ir::FieldLocScope::EVENT_RECORD_SPEC_CTX:
    {
        bt_event *event = bt_message_event_borrow_event((*_mCurrentMessage)->libObjPtr());
        bt_field *specificContextField = bt_event_borrow_specific_context_field(event);

        if (specificContextField)
            _mCurRootScopeStructField = bt2::StructureField {specificContextField};
        else
            _mSkipUntilScopeEnd = true;

        return;
    }

    case ir::FieldLocScope::EVENT_RECORD_PAYLOAD:
    {
        bt_event *event = bt_message_event_borrow_event((*_mCurrentMessage)->libObjPtr());
        bt_field *payloadField = bt_event_borrow_payload_field(event);

        if (payloadField)
            _mCurRootScopeStructField = bt2::StructureField {payloadField};
        else
            _mSkipUntilScopeEnd = true;

        return;
    }
    }

    bt_common_abort();
}

void MsgIterItemVisitor::visit(const ScopeEndItem& item)
{
    /* The last context frame has been popped but StructFieldEndItem.  */
    BT_ASSERT_DBG(_mStack.empty());

    _mCurRootScopeStructField.reset();
    _mSkipUntilScopeEnd = false;
}

void MsgIterItemVisitor::visit(const StructFieldBeginItem& item)
{
    if (_mStack.empty()) {
        /* This is the root struct of a scope. */
        BT_ASSERT_DBG(_mCurRootScopeStructField);
        _mStack.push(StackFrame(*_mCurRootScopeStructField));
    } else {
        bt2::Field field = _currentFieldAndAdvance();
        bt2::StructureField structureField = field.asStructure();
        _mStack.push(StackFrame(structureField));
    }
}

void MsgIterItemVisitor::visit(const StructFieldEndItem& item)
{
    BT_ASSERT_DBG(!_mStack.empty());
    _mStack.pop();
}

void MsgIterItemVisitor::visit(const VariantFieldBeginItem& item)
{
    if (BT_LOG_ON_DEBUG) {
        std::stringstream ss;
        ss << "selected-option-index=" << item.selectedOptIndex();
    }

    bt2::Field field = _currentFieldAndAdvance();
    bt2::VariantField variantField = field.asVariant();
    variantField.selectOption(item.selectedOptIndex());
    _mStack.push(StackFrame(variantField));
}

void MsgIterItemVisitor::visit(const VariantFieldEndItem& item)
{
    BT_ASSERT_DBG(!_mStack.empty());
    _mStack.pop();
}

void MsgIterItemVisitor::visit(const StaticLenArrayFieldBeginItem& item)
{
    bt2::Field field = _currentFieldAndAdvance();
    bt2::ArrayField arrayField = field.asArray();
    _mStack.push(StackFrame(arrayField));
}

void MsgIterItemVisitor::visit(const DynLenArrayFieldBeginItem& item)
{
    bt2::Field field = _currentFieldAndAdvance();
    bt2::DynamicArrayField arrayField = field.asDynamicArray();
    arrayField.length(item.len());
    _mStack.push(StackFrame(arrayField));
}

void MsgIterItemVisitor::visit(const ArrayFieldEndItem& item)
{
    BT_ASSERT_DBG(!_mStack.empty());
    _mStack.pop();
}

void MsgIterItemVisitor::visit(const FixedLenUIntFieldItem& item)
{
    if (ignoreField(item)) {
        return;
    }

    bt2::Field field = _currentFieldAndAdvance();
    bt2::UnsignedIntegerField uintField = field.asUnsignedInteger();
    uintField = item.val();
}

void MsgIterItemVisitor::visit(const FixedLenSIntFieldItem& item)
{
    if (ignoreField(item)) {
        return;
    }

    bt2::Field field = _currentFieldAndAdvance();
    bt2::SignedIntegerField sintField = field.asSignedInteger();
    sintField = item.val();
}

void MsgIterItemVisitor::visit(const FixedLenUEnumFieldItem& item)
{
    bt2::Field field = _currentFieldAndAdvance();
    bt2::UnsignedEnumerationField uEnumField = field.asUnsignedEnumeration();
    uEnumField = item.val();
}

void MsgIterItemVisitor::visit(const FixedLenSEnumFieldItem& item)
{
    bt2::Field field = _currentFieldAndAdvance();
    bt2::SignedEnumerationField sEnumField = field.asSignedEnumeration();
    sEnumField = item.val();
}

void MsgIterItemVisitor::visit(const NullTerminatedStrFieldBeginItem& item)
{
    _currentField().asString() = "";
    _mSubStrSeenNullByte = false;
}

void MsgIterItemVisitor::visit(const NullTerminatedStrFieldEndItem& item)
{
    _advanceField();
}

void MsgIterItemVisitor::visit(const StaticLenStrFieldBeginItem& item)
{
    _currentField().asString() = "";
    _mSubStrSeenNullByte = false;
}

void MsgIterItemVisitor::visit(const StaticLenStrFieldEndItem& item)
{
    _advanceField();
}

void MsgIterItemVisitor::visit(const DynLenStrFieldBeginItem& item)
{
    _currentField().asString() = "";
    _mSubStrSeenNullByte = false;
}

void MsgIterItemVisitor::visit(const DynLenStrFieldEndItem& item)
{
    _advanceField();
}

void MsgIterItemVisitor::visit(const StrFieldSubstrItem& item)
{
    if (_mSubStrSeenNullByte) {
        return;
    }

    const char *end = item.strEnd();
    _currentField().asString().append(item.begin(), end - item.begin());
    _mSubStrSeenNullByte = end != item.end();
}

void MsgIterItemVisitor::visit(const FixedLenFloatFieldItem& item)
{
    bt2::Field field = _currentFieldAndAdvance();

    if (item.cls().len() == 32_bits) {
        field.asSinglePrecisionReal() = item.val();
    } else {
        BT_ASSERT_DBG(item.cls().len() == 64_bits);
        field.asDoublePrecisionReal() = item.val();
    }
}

nonstd::optional<bt2::ConstMessage::Shared> MsgIterItemVisitor::releaseMessageIfReady()
{
    if (_mMessagesReady.empty())
        return nonstd::nullopt;

    bt2::ConstMessage::Shared ret = std::move(_mMessagesReady.front());
    _mMessagesReady.pop();
    return ret;
}

void MsgIterItemVisitor::_advanceField()
{
    BT_ASSERT_DBG(!_mStack.empty());
    _mStack.top().advanceField();
}

bt2::Field MsgIterItemVisitor::_currentField()
{
    BT_ASSERT_DBG(!_mStack.empty());
    return _mStack.top().currentField();
}

bt2::Field MsgIterItemVisitor::_currentFieldAndAdvance()
{
    BT_ASSERT_DBG(!_mStack.empty());
    return _mStack.top().currentFieldAndAdvance();
}

} /* namespace internal */

MsgIter::MsgIter(bt_self_message_iterator *selfMsgIter, const ctf::src::TraceCls& tc,
                 bt2::Stream stream, std::unique_ptr<ctf::src::Medium> medium, const Quirks quirks,
                 const bt2_common::LogCfg logCfg) :
    _mSelfMsgIter {selfMsgIter},
    _mLogCfg {logCfg}, _mStream {stream}, _mItemSeqIter {std::move(medium), tc},
    _mLoggingVisitor {logCfg}, _mItemVisitor {selfMsgIter, _mItemSeqIter, _mLoggingVisitor,
                                              stream,      quirks,        logCfg}
{
    BT_CLOGD("Created CTF plugin message iterator: "
             "trace-addr=%p, msg-it-addr=%p, log-level=%s",
             &tc, this, bt_common_logging_level_string(logCfg.logLevel()));
}

nonstd::optional<bt2::ConstMessage::Shared> MsgIter::next()
{
    BT_CLOGD("Getting next message: msg-it-addr=%p", this);

    try {
        /*
         * Return any already ready message (one increment on the item sequence
         * iterator can yield more than one message, but we return one at a time).
         */
        if (nonstd::optional<bt2::ConstMessage::Shared> msg =
                _mItemVisitor.releaseMessageIfReady()) {
            return *msg;
        }

        if (!_mDone) {
            while (true) {
                const Item *item = _mItemSeqIter.next();

                if (!item) {
                    break;
                }

                if (BT_LOG_ON_TRACE) {
                    item->accept(_mLoggingVisitor);
                }

                if (!_mItemVisitor._mSkipUntilScopeEnd || item->isScopeEndItem()) {
                    item->accept(_mItemVisitor);

                    if (nonstd::optional<bt2::ConstMessage::Shared> msg =
                            _mItemVisitor.releaseMessageIfReady()) {
                        return *msg;
                    }
                }
            }

            _mDone = true;
            return bt2::Message::Shared::createWithoutRef(
                bt_message_stream_end_create(_mSelfMsgIter, _mStream.libObjPtr()));
        }

        return nonstd::nullopt;
    } catch (const ctf::src::DecodingError& ex) {
        BT_CLOGE_APPEND_CAUSE_AND_RETHROW("%s", ex.what());
    }
}

} /* namespace src */
} /* namespace ctf */
