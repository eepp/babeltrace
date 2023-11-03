/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 Simon Marchi <simon.marchi@efficios.com>
 * Copyright (c) 2015-2022 Philippe Proulx <pproulx@efficios.com>
 */

#include <algorithm>

#include "cpp-common/bt2c/fmt.hpp"
#include "cpp-common/vendor/fmt/format.h"

#include "item-seq/item.hpp"
#include "msg-iter.hpp"

namespace ctf {
namespace src {

using namespace bt2c::literals::datalen;

MsgIter::MsgIter(bt_self_message_iterator * const selfMsgIter, const ctf::src::TraceCls& traceCls,
                 bt2s::optional<bt2c::Uuid> expectedMetadataStreamUuid, const bt2::Stream stream,
                 Medium::UP medium, const MsgIterQuirks& quirks, const bt2c::Logger& parentLogger) :
    _mLogger {parentLogger, "PLUGIN/CTF/MSG-ITER"},
    _mSelfMsgIter {selfMsgIter}, _mStream {stream},
    _mExpectedMetadataStreamUuid {std::move(expectedMetadataStreamUuid)}, _mQuirks {quirks},
    _mItemSeqIter {std::move(medium), traceCls, _mLogger}, _mLoggingVisitor {"Handling item",
                                                                             _mLogger}
{
    BT_CPPLOGD("Created CTF plugin message iterator: "
               "addr={}, trace-cls-addr={}, log-level={}",
               fmt::ptr(this), fmt::ptr(&traceCls), _mLogger.level());
}

bt2::ConstMessage::Shared MsgIter::next()
{
    BT_CPPLOGD("Getting next message: addr={}", fmt::ptr(this));

    if (_mIsDone) {
        return bt2::ConstMessage::Shared {};
    }

    /*
     * Return any message that's already in the queue (one iteration
     * of the underlying item sequence iterator may yield more than
     * one message, but we return one at a time).
     */
    if (auto msg = this->_releaseNextMsg()) {
        return msg;
    }

    try {
        while (true) {
            /*
             * Get the next item from the underlying item sequence
             * iterator.
             */
            const auto item = _mItemSeqIter.next();

            if (!item) {
                /* No more items: this is the end! */
                break;
            }

            /* Handle item if needed */
            if (!_mSkipItemsUntilScopeEndItem || item->isScopeEndItem()) {
                this->_handleItem(*item);

                if (auto msg = this->_releaseNextMsg()) {
                    return msg;
                }
            }
        }

        /* We're done! */
        _mIsDone = true;
        return bt2::ConstMessage::Shared::createWithoutRef(
            bt_message_stream_end_create(_mSelfMsgIter, _mStream.libObjPtr()));
    } catch (const bt2c::Error&) {
        BT_CPPLOGE_APPEND_CAUSE_AND_RETHROW("Failed to create next message: addr={}",
                                            fmt::ptr(this));
    }
}

void MsgIter::_handleItem(const Item& item)
{
    /* Log item details */
    if (_mLogger.wouldLogT()) {
        item.accept(_mLoggingVisitor);
    }

    /* Defer to specific handler */
    switch (item.type()) {
    case Item::Type::PKT_BEGIN:
        this->_handleItem(static_cast<const PktBeginItem&>(item));
        break;
    case Item::Type::PKT_END:
        this->_handleItem(static_cast<const PktEndItem&>(item));
        break;
    case Item::Type::SCOPE_BEGIN:
        this->_handleItem(static_cast<const ScopeBeginItem&>(item));
        break;
    case Item::Type::SCOPE_END:
        this->_handleItem(static_cast<const ScopeEndItem&>(item));
        break;
    case Item::Type::PKT_CONTENT_END:
        this->_handleItem(static_cast<const PktContentEndItem&>(item));
        break;
    case Item::Type::EVENT_RECORD_END:
        this->_handleItem(static_cast<const EventRecordEndItem&>(item));
        break;
    case Item::Type::PKT_MAGIC_NUMBER:
        this->_handleItem(static_cast<const PktMagicNumberItem&>(item));
        break;
    case Item::Type::METADATA_STREAM_UUID:
        this->_handleItem(static_cast<const MetadataStreamUuidItem&>(item));
        break;
    case Item::Type::DATA_STREAM_INFO:
        this->_handleItem(static_cast<const DataStreamInfoItem&>(item));
        break;
    case Item::Type::PKT_INFO:
        this->_handleItem(static_cast<const PktInfoItem&>(item));
        break;
    case Item::Type::EVENT_RECORD_INFO:
        this->_handleItem(static_cast<const EventRecordInfoItem&>(item));
        break;
    case Item::Type::FIXED_LEN_BIT_ARRAY_FIELD:
        this->_handleItem(static_cast<const FixedLenBitArrayFieldItem&>(item));
        break;
    case Item::Type::FIXED_LEN_BOOL_FIELD:
        this->_handleItem(static_cast<const FixedLenBoolFieldItem&>(item));
        break;
    case Item::Type::FIXED_LEN_SINT_FIELD:
    case Item::Type::FIXED_LEN_SENUM_FIELD:
        this->_handleItem(static_cast<const FixedLenSIntFieldItem&>(item));
        break;
    case Item::Type::FIXED_LEN_UINT_FIELD:
    case Item::Type::FIXED_LEN_UENUM_FIELD:
        this->_handleItem(static_cast<const FixedLenUIntFieldItem&>(item));
        break;
    case Item::Type::FIXED_LEN_FLOAT_FIELD:
        this->_handleItem(static_cast<const FixedLenFloatFieldItem&>(item));
        break;
    case Item::Type::VAR_LEN_SINT_FIELD:
    case Item::Type::VAR_LEN_SENUM_FIELD:
        this->_handleItem(static_cast<const VarLenSIntFieldItem&>(item));
        break;
    case Item::Type::VAR_LEN_UINT_FIELD:
    case Item::Type::VAR_LEN_UENUM_FIELD:
        this->_handleItem(static_cast<const VarLenUIntFieldItem&>(item));
        break;
    case Item::Type::NULL_TERMINATED_STR_FIELD_BEGIN:
        this->_handleItem(static_cast<const NullTerminatedStrFieldBeginItem&>(item));
        break;
    case Item::Type::NULL_TERMINATED_STR_FIELD_END:
        this->_handleItem(static_cast<const NullTerminatedStrFieldEndItem&>(item));
        break;
    case Item::Type::STR_FIELD_SUBSTR:
        this->_handleItem(static_cast<const StrFieldSubstrItem&>(item));
        break;
    case Item::Type::BLOB_FIELD_SECTION:
        this->_handleItem(static_cast<const BlobFieldSectionItem&>(item));
        break;
    case Item::Type::STRUCT_FIELD_BEGIN:
        this->_handleItem(static_cast<const StructFieldBeginItem&>(item));
        break;
    case Item::Type::STRUCT_FIELD_END:
        this->_handleItem(static_cast<const StructFieldEndItem&>(item));
        break;
    case Item::Type::STATIC_LEN_ARRAY_FIELD_BEGIN:
        this->_handleItem(static_cast<const StaticLenArrayFieldBeginItem&>(item));
        break;
    case Item::Type::STATIC_LEN_ARRAY_FIELD_END:
    case Item::Type::DYN_LEN_ARRAY_FIELD_END:
        this->_handleItem(static_cast<const ArrayFieldEndItem&>(item));
        break;
    case Item::Type::DYN_LEN_ARRAY_FIELD_BEGIN:
        this->_handleItem(static_cast<const DynLenArrayFieldBeginItem&>(item));
        break;
    case Item::Type::STATIC_LEN_BLOB_FIELD_BEGIN:
        this->_handleItem(static_cast<const StaticLenBlobFieldBeginItem&>(item));
        break;
    case Item::Type::STATIC_LEN_BLOB_FIELD_END:
    case Item::Type::DYN_LEN_BLOB_FIELD_END:
        this->_handleItem(static_cast<const BlobFieldEndItem&>(item));
        break;
    case Item::Type::DYN_LEN_BLOB_FIELD_BEGIN:
        this->_handleItem(static_cast<const DynLenBlobFieldBeginItem&>(item));
        break;
    case Item::Type::STATIC_LEN_STR_FIELD_BEGIN:
    case Item::Type::DYN_LEN_STR_FIELD_BEGIN:
        this->_handleItem(static_cast<const NonNullTerminatedStrFieldBeginItem&>(item));
        break;
    case Item::Type::STATIC_LEN_STR_FIELD_END:
    case Item::Type::DYN_LEN_STR_FIELD_END:
        this->_handleItem(static_cast<const NonNullTerminatedStrFieldEndItem&>(item));
        break;
    case Item::Type::VARIANT_FIELD_WITH_SINT_SEL_BEGIN:
    case Item::Type::VARIANT_FIELD_WITH_UINT_SEL_BEGIN:
        this->_handleItem(static_cast<const VariantFieldBeginItem&>(item));
        break;
    case Item::Type::VARIANT_FIELD_WITH_SINT_SEL_END:
    case Item::Type::VARIANT_FIELD_WITH_UINT_SEL_END:
        this->_handleItem(static_cast<const VariantFieldEndItem&>(item));
        break;
    case Item::Type::OPTIONAL_FIELD_WITH_BOOL_SEL_BEGIN:
    case Item::Type::OPTIONAL_FIELD_WITH_SINT_SEL_BEGIN:
    case Item::Type::OPTIONAL_FIELD_WITH_UINT_SEL_BEGIN:
        this->_handleItem(static_cast<const OptionalFieldBeginItem&>(item));
        break;
    case Item::Type::OPTIONAL_FIELD_WITH_BOOL_SEL_END:
    case Item::Type::OPTIONAL_FIELD_WITH_SINT_SEL_END:
    case Item::Type::OPTIONAL_FIELD_WITH_UINT_SEL_END:
        this->_handleItem(static_cast<const OptionalFieldEndItem&>(item));
        break;
    default:
        BT_CPPLOGT("Skipping item.");
        return;
    }
}

void MsgIter::_handleItem(const PktBeginItem&)
{
    BT_ASSERT_DBG(!this->_curPkt());
    this->_curPkt(_mStream.createPacket());
}

bt_message *MsgIter::_createPktEndMsgAndUpdateCurDefClkVal()
{
    if (_mPktEndDefClkVal) {
        const auto pktEndDefClkValZeroBug = _mQuirks.pktEndDefClkValZero && _mPktBeginDefClkVal &&
                                            _mPktEndDefClkVal && *_mPktBeginDefClkVal != 0 &&
                                            *_mPktEndDefClkVal == 0;
        const auto eventRecordDefClkValGtNextPktBeginDefClkValBug =
            _mQuirks.eventRecordDefClkValGtNextPktBeginDefClkVal && _mCurDefClkVal &&
            _mPktEndDefClkVal && *_mPktEndDefClkVal < _mCurDefClkVal;
        const auto anyBug =
            pktEndDefClkValZeroBug || eventRecordDefClkValGtNextPktBeginDefClkValBug;
        const auto defClkVal = anyBug ? *_mCurDefClkVal : *_mPktEndDefClkVal;

        if (!anyBug) {
            _mCurDefClkVal = _mPktEndDefClkVal;
        }

        return bt_message_packet_end_create_with_default_clock_snapshot(_mSelfMsgIter,
                                                                        this->_curPkt(), defClkVal);
    } else {
        return bt_message_packet_end_create(_mSelfMsgIter, this->_curPkt());
    }
}

void MsgIter::_handleItem(const PktEndItem&)
{
    BT_ASSERT_DBG(!_mCurMsg);
    BT_ASSERT_DBG(this->_curPkt());

    /* Emit a packet beginning message now if required to fix a quirk */
    if (_mDelayPktBeginMsgEmission) {
        this->_emitDelayedPktBeginMsg(_mPktEndDefClkVal);
    }

    /* Emit a packet end message */
    this->_addMsgToQueue(this->_createPktEndMsgAndUpdateCurDefClkVal());

    /* No more current packet */
    this->_resetCurPkt();
}

void MsgIter::_handleItem(const ScopeBeginItem& item)
{
    BT_ASSERT(_mStack.empty());
    BT_ASSERT(!_mCurScopeField);

    /* Handle specific scope */
    switch (item.scope()) {
    case ir::FieldLocScope::PKT_HEADER:
        /* Nothing needed from the packet header: fast-forward */
        _mSkipItemsUntilScopeEndItem = true;
        break;
    case ir::FieldLocScope::PKT_CTX:
    {
        const auto pkt = this->_curPkt();

        BT_ASSERT_DBG(pkt);

        const auto pktCtxField = bt_packet_borrow_context_field(pkt);

        if (pktCtxField) {
            _mCurScopeField = bt2::StructureField {pktCtxField};
        } else {
            /* Nothing needed from the packet context: fast-forward */
            _mSkipItemsUntilScopeEndItem = true;
        }

        break;
    }
    case ir::FieldLocScope::EVENT_RECORD_HEADER:
        /* Nothing needed from the event record header: fast-forward */
        _mSkipItemsUntilScopeEndItem = true;
        break;
    case ir::FieldLocScope::EVENT_RECORD_COMMON_CTX:
    {
        const auto event = bt_message_event_borrow_event(_mCurMsg->libObjPtr());
        const auto commonCtxField = bt_event_borrow_common_context_field(event);

        if (commonCtxField) {
            _mCurScopeField = bt2::StructureField {commonCtxField};
        } else {
            /* Nothing needed from the common context: fast-forward */
            _mSkipItemsUntilScopeEndItem = true;
        }

        break;
    }
    case ir::FieldLocScope::EVENT_RECORD_SPEC_CTX:
    {
        const auto event = bt_message_event_borrow_event(_mCurMsg->libObjPtr());
        const auto specCtxField = bt_event_borrow_specific_context_field(event);

        if (specCtxField) {
            _mCurScopeField = bt2::StructureField {specCtxField};
        } else {
            /* Nothing needed from the specific context: fast-forward */
            _mSkipItemsUntilScopeEndItem = true;
        }

        break;
    }
    case ir::FieldLocScope::EVENT_RECORD_PAYLOAD:
    {
        const auto event = bt_message_event_borrow_event(_mCurMsg->libObjPtr());
        const auto payloadField = bt_event_borrow_payload_field(event);

        if (payloadField) {
            _mCurScopeField = bt2::StructureField {payloadField};
        } else {
            /* Nothing needed from the payload: fast-forward */
            _mSkipItemsUntilScopeEndItem = true;
        }

        break;
    }
    default:
        bt_common_abort();
    }
}

void MsgIter::_handleItem(const ScopeEndItem&)
{
    /*
     * The last stack frame was removed by the `StructFieldEndItem`
     * handler.
     */
    BT_ASSERT_DBG(_mStack.empty());

    /* No more current scope root field */
    _mCurScopeField.reset();

    /* Reset this flag */
    _mSkipItemsUntilScopeEndItem = false;
}

void MsgIter::_handleItem(const PktContentEndItem&)
{
    BT_ASSERT_DBG(this->_curPkt());
}

void MsgIter::_handleItem(const EventRecordEndItem&)
{
    BT_ASSERT_DBG(_mStack.empty());
    BT_ASSERT_DBG(_mCurMsg);

    /* Emit current message */
    _mMsgs.emplace(bt2::ConstMessage::Shared::createWithoutRef(_mCurMsg.release()));
    _mCurMsg.reset();
}

void MsgIter::_handleItem(const PktMagicNumberItem& item)
{
    if (!item.isValid()) {
        BT_CPPLOGE_APPEND_CAUSE_AND_THROW(
            bt2c::Error, "Invalid packet magic number: val={:#x}, expected-val={:#x}", item.val(),
            item.expectedVal());
    }
}

void MsgIter::_handleItem(const MetadataStreamUuidItem& item)
{
    BT_ASSERT_DBG(_mExpectedMetadataStreamUuid);

    if (item.uuid() != *_mExpectedMetadataStreamUuid) {
        BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error,
                                          "Invalid metadata stream UUID: uuid={}, expected-uuid={}",
                                          item.uuid(), *_mExpectedMetadataStreamUuid);
    }
}

void MsgIter::_handleItem(const DataStreamInfoItem&)
{
    if (!_mEmittedStreamBeginMsg) {
        this->_addMsgToQueue(
            bt_message_stream_beginning_create(_mSelfMsgIter, _mStream.libObjPtr()));
        _mEmittedStreamBeginMsg = true;
    }
}

bt_message *MsgIter::_createInitDiscEventsMsg(const _OptUll& prevPktEndDefClkVal)
{
    if (_mStream.cls().discardedEventsHaveDefaultClockSnapshots()) {
        /*
         * We know there was a previous packet since we can't reach this
         * point for the first packet.
         */
        BT_ASSERT_DBG(prevPktEndDefClkVal);
        return bt_message_discarded_events_create_with_default_clock_snapshots(
            _mSelfMsgIter, _mStream.libObjPtr(), *prevPktEndDefClkVal, *_mPktEndDefClkVal);
    } else {
        return bt_message_discarded_events_create(_mSelfMsgIter, _mStream.libObjPtr());
    }
}

bt_message *MsgIter::_createInitDiscPktsMsg(const _OptUll& prevPktEndDefClkVal)
{
    if (_mStream.cls().discardedPacketsHaveDefaultClockSnapshots()) {
        /*
         * We know there was a previous packet since we can't reach this
         * point for the first packet.
         */
        BT_ASSERT_DBG(prevPktEndDefClkVal);
        return bt_message_discarded_packets_create_with_default_clock_snapshots(
            _mSelfMsgIter, _mStream.libObjPtr(), *prevPktEndDefClkVal, *_mPktBeginDefClkVal);
    } else {
        return bt_message_discarded_packets_create(_mSelfMsgIter, _mStream.libObjPtr());
    }
}

void MsgIter::_emitPktBeginMsg(const _OptUll& defClkVal)
{
    /* Create message */
    const auto msg = [this, &defClkVal] {
        if (defClkVal) {
            _mCurDefClkVal = defClkVal;
            return bt_message_packet_beginning_create_with_default_clock_snapshot(
                _mSelfMsgIter, this->_curPkt(), *defClkVal);
        } else {
            return bt_message_packet_beginning_create(_mSelfMsgIter, this->_curPkt());
        }
    }();

    /* Add to queue */
    this->_addMsgToQueue(msg);
}

void MsgIter::_emitDelayedPktBeginMsg(const _OptUll& otherDefClkVal)
{
    BT_ASSERT_DBG(_mDelayPktBeginMsgEmission);

    /* Reset the flag */
    _mDelayPktBeginMsgEmission = false;

    /*
     * Only fix the beginning timestamp of the packet if it's larger
     * than the timestamp of its first event record.
     */
    const auto defClkVal = [this, &otherDefClkVal]() -> _OptUll {
        if (_mPktBeginDefClkVal && otherDefClkVal) {
            return std::min(*_mPktBeginDefClkVal, *otherDefClkVal);
        } else if (_mPktBeginDefClkVal) {
            return _mPktBeginDefClkVal;
        } else if (otherDefClkVal) {
            return otherDefClkVal;
        }

        return bt2s::nullopt;
    }();

    /* Emit a packet beginning message now */
    this->_emitPktBeginMsg(defClkVal);
}

void MsgIter::_handleItem(const PktInfoItem& item)
{
    /*
     * Save the packet beginning and end timestamps.
     *
     * Also keep the end timestamp of the previous packet: we might need
     * it if there are discarded event records.
     */
    const auto prevPktEndDefClkVal = _mPktEndDefClkVal;

    _mPktBeginDefClkVal = item.beginDefClkVal();
    _mPktEndDefClkVal = item.endDefClkVal();

    /*
     * Emit a discarded events message if the count of discarded event
     * records went up since the previous packet.
     *
     * For the first packet, `_mCurDiscErCounterSnap` isn't set: we
     * don't have anything to compare to.
     */
    const auto& discErCounterSnap = item.discEventRecordCounterSnap();

    if (_mCurDiscErCounterSnap) {
        /*
         * If the previous packet of this same stream had a discarded
         * event record counter snapshot, then this one must have one
         * too.
         */
        BT_ASSERT_DBG(discErCounterSnap);

        if (*discErCounterSnap > *_mCurDiscErCounterSnap) {
            /* Create and initialize the message */
            const auto msg = this->_createInitDiscEventsMsg(prevPktEndDefClkVal);

            /* Set its count */
            bt_message_discarded_events_set_count(msg,
                                                  *discErCounterSnap - *_mCurDiscErCounterSnap);

            /* Add to queue */
            this->_addMsgToQueue(msg);
        }
    }

    /* Set new current discarded event record counter snapshot */
    _mCurDiscErCounterSnap = discErCounterSnap;

    /*
     * Emit a discarded packets message if there's a gap between the
     * previous packet sequence number and the sequence number of this
     * new packet.
     */
    const auto& seqNum = item.seqNum();

    if (_mCurPktSeqNum) {
        /*
         * If the previous packet of this same stream had a sequence
         * number, then this one must have one too.
         */
        BT_ASSERT_DBG(seqNum);

        if (*_mCurPktSeqNum + 1 < *seqNum) {
            /* Create and initialize the message */
            const auto msg = this->_createInitDiscPktsMsg(prevPktEndDefClkVal);

            /* Set its count */
            bt_message_discarded_packets_set_count(msg, *seqNum - *_mCurPktSeqNum - 1);

            /* Add to queue */
            this->_addMsgToQueue(msg);
        }
    }

    /* Set new packet sequence number */
    _mCurPktSeqNum = seqNum;

    /* There's no pending message */
    BT_ASSERT_DBG(!_mCurMsg);

    /*
     * Depending on a quirk to handle, emit a packet beginning message
     * now or delay said emission.
     */
    if (_mQuirks.eventRecordDefClkValLtPktBeginDefClkVal) {
        _mDelayPktBeginMsgEmission = true;
    } else {
        /* No quirk to handle: emit the message now */
        this->_emitPktBeginMsg(_mPktBeginDefClkVal);
    }
}

bt_message *MsgIter::_createEventMsg(const bt2::EventClass cls, const _OptUll& defClkVal)
{
    if (defClkVal) {
        if (this->_curPkt()) {
            return bt_message_event_create_with_packet_and_default_clock_snapshot(
                _mSelfMsgIter, cls.libObjPtr(), this->_curPkt(), *defClkVal);
        } else {
            return bt_message_event_create_with_default_clock_snapshot(
                _mSelfMsgIter, cls.libObjPtr(), _mStream.libObjPtr(), *defClkVal);
        }
    } else {
        if (this->_curPkt()) {
            return bt_message_event_create_with_packet(_mSelfMsgIter, cls.libObjPtr(),
                                                       this->_curPkt());
        } else {
            return bt_message_event_create(_mSelfMsgIter, cls.libObjPtr(), _mStream.libObjPtr());
        }
    }
}

void MsgIter::_handleItem(const EventRecordInfoItem& item)
{
    /* TODO: Test having a trace with only event record headers */
    BT_ASSERT_DBG(item.cls());
    BT_ASSERT_DBG(item.cls()->libCls());
    BT_ASSERT_DBG(!_mCurMsg);

    /* Emit a packet beginning message now if required to fix a quirk */
    if (_mDelayPktBeginMsgEmission) {
        this->_emitDelayedPktBeginMsg(item.defClkVal());
    }

    /* Update the default clock value if needed */
    if (item.defClkVal()) {
        _mCurDefClkVal = *item.defClkVal();
    }

    /*
     * Set as current message.
     *
     * The following items will gradually fill this message.
     *
     * This message will be emitted (added to the message queue) when
     * handling the next `EventRecordEndItem`.
     */
    _mCurMsg = bt2::Message::Shared::createWithoutRef(
        this->_createEventMsg(*item.cls()->libCls(), item.defClkVal()));
}

void MsgIter::_handleItem(const FixedLenBitArrayFieldItem& item)
{
    if (_ignoreFieldItem(item)) {
        return;
    }

    this->_stackTopCurSubFieldAndGoToNextSubField().asBitArray().valueAsInteger(item.uIntVal());
}

void MsgIter::_handleItem(const FixedLenBoolFieldItem& item)
{
    if (_ignoreFieldItem(item)) {
        return;
    }

    this->_stackTopCurSubFieldAndGoToNextSubField().asBool().value(item.val());
}

void MsgIter::_handleItem(const FixedLenSIntFieldItem& item)
{
    this->_handleSIntFieldItem(item);
}

void MsgIter::_handleItem(const FixedLenUIntFieldItem& item)
{
    this->_handleUIntFieldItem(item);
}

void MsgIter::_handleItem(const FixedLenFloatFieldItem& item)
{
    const auto field = this->_stackTopCurSubFieldAndGoToNextSubField();

    if (item.cls().len() == 32_bits) {
        field.asSinglePrecisionReal().value(item.val());
    } else {
        BT_ASSERT_DBG(item.cls().len() == 64_bits);
        field.asDoublePrecisionReal().value(item.val());
    }
}

void MsgIter::_handleItem(const VarLenSIntFieldItem& item)
{
    this->_handleSIntFieldItem(item);
}

void MsgIter::_handleItem(const VarLenUIntFieldItem& item)
{
    this->_handleUIntFieldItem(item);
}

void MsgIter::_handleStrFieldBeginItem()
{
    this->_stackTopCurSubField().asString().value("");
    _mHaveStrFieldSubstrItemNullChar = false;
}

void MsgIter::_handleStrFieldEndItem()
{
    this->_stackTopGoToNextSubField();
}

void MsgIter::_handleItem(const NullTerminatedStrFieldBeginItem&)
{
    this->_handleStrFieldBeginItem();
}

void MsgIter::_handleItem(const NullTerminatedStrFieldEndItem&)
{
    this->_handleStrFieldEndItem();
}

void MsgIter::_handleItem(const StrFieldSubstrItem& item)
{
    if (_mHaveStrFieldSubstrItemNullChar) {
        /* No more text data */
        return;
    }

    const auto end = item.strEnd();

    this->_stackTopCurSubField().asString().append(item.begin(), end - item.begin());
    _mHaveStrFieldSubstrItemNullChar = end != item.end();
}

void MsgIter::_handleItem(const BlobFieldSectionItem& item)
{
    std::memcpy(&this->_stackTopCurSubField().asBlob().data()[_mCurBlobFieldDataOffset],
                item.begin(), item.size().bytes());
    _mCurBlobFieldDataOffset += item.size().bytes();
}

void MsgIter::_handleItem(const StructFieldBeginItem&)
{
    if (_mStack.empty()) {
        /* This is the root field of the current scope */
        BT_ASSERT_DBG(_mCurScopeField);
        this->_stackPush(*_mCurScopeField);
    } else {
        /* Use sub-field */
        this->_stackPush(this->_stackTopCurSubFieldAndGoToNextSubField().asStructure());
    }
}

void MsgIter::_handleItem(const StructFieldEndItem&)
{
    this->_stackPop();
}

void MsgIter::_handleItem(const StaticLenArrayFieldBeginItem&)
{
    this->_stackPush(this->_stackTopCurSubFieldAndGoToNextSubField().asArray());
}

void MsgIter::_handleItem(const DynLenArrayFieldBeginItem& item)
{
    auto arrayField = this->_stackTopCurSubFieldAndGoToNextSubField().asDynamicArray();

    arrayField.length(item.len());
    this->_stackPush(arrayField);
}

void MsgIter::_handleItem(const ArrayFieldEndItem&)
{
    this->_stackPop();
}

void MsgIter::_handleItem(const StaticLenBlobFieldBeginItem&)
{
    _mCurBlobFieldDataOffset = 0;
}

void MsgIter::_handleItem(const DynLenBlobFieldBeginItem& item)
{
    this->_stackTopCurSubField().asDynamicBlob().length(item.len().bytes());
    _mCurBlobFieldDataOffset = 0;
}

void MsgIter::_handleItem(const BlobFieldEndItem&)
{
    this->_stackTopGoToNextSubField();
}

void MsgIter::_handleItem(const NonNullTerminatedStrFieldBeginItem&)
{
    this->_handleStrFieldBeginItem();
}

void MsgIter::_handleItem(const NonNullTerminatedStrFieldEndItem&)
{
    this->_handleStrFieldEndItem();
}

void MsgIter::_handleItem(const VariantFieldBeginItem& item)
{
    auto field = this->_stackTopCurSubFieldAndGoToNextSubField().asVariant();

    field.selectOption(item.selectedOptIndex());
    this->_stackPush(field);
}

void MsgIter::_handleItem(const VariantFieldEndItem&)
{
    this->_stackPop();
}

void MsgIter::_handleItem(const OptionalFieldBeginItem& item)
{
    auto field = this->_stackTopCurSubFieldAndGoToNextSubField().asOption();

    field.hasField(item.isEnabled());
    this->_stackPush(field);
}

void MsgIter::_handleItem(const OptionalFieldEndItem&)
{
    this->_stackPop();
}

void MsgIter::_addMsgToQueue(bt_message * const msg)
{
    _mMsgs.emplace(bt2::ConstMessage::Shared::createWithoutRef(msg));
}

bt2::ConstMessage::Shared MsgIter::_releaseNextMsg()
{
    if (_mMsgs.empty()) {
        return bt2::ConstMessage::Shared {};
    }

    auto msg = std::move(_mMsgs.front());

    _mMsgs.pop();
    return msg;
}

} /* namespace src */
} /* namespace ctf */
