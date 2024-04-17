/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <algorithm>

#include "common/assert.h"

#include "item-seq-iter.hpp"
#include "item.hpp"

namespace ctf {
namespace src {

using namespace bt2c::literals::datalen;

ItemSeqIter::ItemSeqIter(std::unique_ptr<Medium> medium, const TraceCls& traceCls,
                         const bt2c::Logger& parentLogger) :
    _mMedium {std::move(medium)},
    _mTraceCls {&traceCls},
    _mTraceClsSavedValueCountUpdatedObservableToken(
        _mTraceCls->savedValCountUpdatedObservable().attach(
            std::bind(&ItemSeqIter::_savedValCountUpdated, this, std::placeholders::_1))),
    _mLogger {parentLogger, "PLUGIN/CTF/ITEM-SEQ-ITER"}
{
    /* Allocate enough elements to save values for dependent fields */
    _mSavedVals.resize(traceCls.savedValCount());
}

ItemSeqIter::ItemSeqIter(std::unique_ptr<Medium> medium, const TraceCls& traceCls,
                         const bt2c::DataLen pktOffset, const bt2c::Logger& parentLogger) :
    ItemSeqIter {std::move(medium), traceCls, parentLogger}
{
    this->seekPkt(pktOffset);
}

ItemSeqIter::_StackFrame::_StackFrame(const _State restoringStateParam) noexcept :
    restoringState {restoringStateParam}
{
}

ItemSeqIter::_StackFrame::_StackFrame(const _State restoringStateParam, const Fc& fcParam) noexcept
    :
    restoringState {restoringStateParam},
    fc {&fcParam}
{
}

void ItemSeqIter::seekPkt(const bt2c::DataLen pktOffset)
{
    /* New packet offset within the whole item sequence */
    _mCurPktOffsetInItemSeq = pktOffset;

    /*
     * Reset the current buffer so as to make the next call to _tryHaveData()
     * request a new buffer at the beginning of this packet from the medium.
     */
    this->_mBuf = Buf {};

    /* Next: try to begin reading a packet */
    this->_state(_State::TRY_BEGIN_READ_PKT);
}

void ItemSeqIter::_updateDefClkVal(const unsigned long long val, const bt2c::DataLen len) noexcept
{
    /*
     * Special case for a 64-bit new value, which is the limit of a
     * clock value as of this version: overwrite the current value
     * directly.
     */
    if (len == 64_bits) {
        _mDefClkVal = val;
        return;
    }

    const auto newValMask = (1ULL << *len) - 1;
    const auto curValMasked = _mDefClkVal & newValMask;

    if (val < curValMasked) {
        /*
         * It looks like a wrap occurred on the number of bits of the
         * new value. Assume that the clock value wrapped only once.
         */
        _mDefClkVal += newValMask + 1;
    }

    /* Clear the low bits of the current default clock value */
    _mDefClkVal &= ~newValMask;

    /* Set the low bits of the current default clock value */
    _mDefClkVal |= val;
}

void ItemSeqIter::_resetForNewPkt()
{
    _mCurClsId = bt2s::nullopt;
    _mLastFixedLenBitArrayFieldByteOrder = bt2s::nullopt;
    _mStack.clear();
    _mDefClkVal = 0;

    /* Reset decoding head to the beginning of the new packet */
    _mHeadOffsetInCurPkt = 0_bits;

    /*
     * Reset informative items as a given item sequence could contain
     * packets from data streams having different classes, therefore
     * having different packet context and event record header field
     * classes.
     */
    _mItems.dataStreamInfo._reset();
    _mItems.pktInfo._reset();
    _mItems.eventRecordInfo._reset();

    /*
     * Reset both expected total and content packet lengths to
     * "infinity" so that, if both are missing at the
     * `_State::SET_PKT_INFO_ITEM` state, then _remainingPktContentLen()
     * will always return a very large value so as to read the whole
     * medium data (the medium offers a single packet).
     */
    _mCurPktExpectedLens.total = this->_infDataLen();
    _mCurPktExpectedLens.content = this->_infDataLen();

    /*
     * Any state handler which calls _handleCommonVarLenIntFieldState()
     * may be reentered as is. This may happen if its
     * _requireContentData() call throws `bt2c::TryAgain`, for
     * example.
     *
     * This means there's no initial setup to read a variable-length
     * integer field: the state handlers just call
     * _handleCommonVarLenIntFieldState() to start _and_ to continue.
     *
     * Because of this, and because both `_mCurVarLenInt.val` and
     * `_mCurVarLenInt.len` must be zero before starting to read a
     * variable-length integer field, we reset them here for the first
     * variable-length integer field reading operation of this new
     * packet.
     *
     * _handleCommonVarLenIntFieldState() also resets both variables
     * when it finishes decoding a variable-length integer field.
     */
    _mCurVarLenInt.val = 0;
    _mCurVarLenInt.len = 0_bits;
}

void ItemSeqIter::_newBuf(const bt2c::DataLen offsetInItemSeq, const bt2c::DataLen minSize)
{
    BT_ASSERT_DBG(minSize <= 9_bytes);

    _mBuf = _mMedium->buf(offsetInItemSeq, minSize);
    _mBufOffsetInCurPkt = offsetInItemSeq - _mCurPktOffsetInItemSeq;
}

[[noreturn]] void ItemSeqIter::_logAppendCauseAndThrow(const std::string& msg) const
{
    BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error, "At {} bits: {}", *this->_headOffsetInItemSeq(),
                                      msg);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleInitState()
{
    /* Next: try to begin reading a packet */
    this->_state(_State::TRY_BEGIN_READ_PKT);
    return _StateHandlingReaction::CONTINUE;
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleTryBeginReadPktState()
{
    /* This is a new packet */
    this->_resetForNewPkt();

    if (this->_remainingBufLen() == 0_bits) {
        /*
         * Try getting a single bit to see if we're at the end of the
         * item sequence.
         */
        if (!this->_tryHaveData(1_bits)) {
            /* No more data: no more packets */
            _mCurItem = nullptr;
            _mState = _State::DONE;
            return _StateHandlingReaction::STOP;
        }
    }

    /* Update for user */
    this->_updateForUser(_mItems.pktBegin);

    /* Next: begin reading packet content */
    this->_state(_State::BEGIN_READ_PKT_CONTENT);
    return _StateHandlingReaction::STOP;
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleEndReadPktState()
{
    /* Update for user */
    this->_updateForUser(_mItems.pktEnd);

    /* Adjust offsets */
    _mCurPktOffsetInItemSeq = this->_headOffsetInItemSeq();
    BT_ASSERT_DBG(!_mCurPktOffsetInItemSeq.hasExtraBits());
    _mHeadOffsetInCurPkt = 0_bits;

    /* Adjust current buffer for the next packet, if any */
    if (_mCurPktExpectedLens.total == this->_infDataLen()) {
        /* Item sequence contains a single packet: reset the buffer */
        _mBuf = Buf {};
    } else {
        /*
         * Make it so that the beginning of the buffer is the beginning
         * of the next packet to read.
         *
         * For example, before:
         *
         * ╔═══════════════════════════════════════════════════════════════════╗
         * ║ Packet: ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                    ║
         * ║         ┆                Buffer: ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ ║
         * ║         ┆                        ┆           ┆                  ┆ ║
         * ║         ┣┅ _mBufOffsetInCurPkt ┅┅┫           ┆                  ┆ ║
         * ║         ┆                        ┣┅┅┅┅┅┅┅┅ _mBuf.size() ┅┅┅┅┅┅┅┅┫ ║
         * ║         ┣┅┅┅┅ _mCurPktExpectedLens.total ┅┅┅┅┫                    ║
         * ╚═══════════════════════════════════════════════════════════════════╝
         *
         * After (`_mBufOffsetInCurPkt` will be reset to zero):
         *
         * ╔═══════════════════════════════════════════════════════════════════╗
         * ║ Packet: ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                    ║
         * ║         ┆                            Buffer: ┆▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ ║
         * ║         ┆                                    ┆┆                 ┆ ║
         * ║         ┆                                    ┆┣┅┅ _mBuf.size() ┅┫ ║
         * ║         ┣┅┅┅┅ _mCurPktExpectedLens.total ┅┅┅┅┫                    ║
         * ╚═══════════════════════════════════════════════════════════════════╝
         */
        _mBuf = _mBuf.slice(_mCurPktExpectedLens.total - _mBufOffsetInCurPkt);
    }

    _mBufOffsetInCurPkt = 0_bits;

    /* Next: try reading a packet */
    this->_state(_State::TRY_BEGIN_READ_PKT);
    return _StateHandlingReaction::STOP;
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleBeginReadPktContentState()
{
    /* Update for user */
    this->_updateForUser(_mItems.pktContentBegin);

    /* Next: try reading packet header field */
    this->_prepareToTryReadScope(_State::TRY_BEGIN_READ_PKT_HEADER_SCOPE,
                                 _State::END_READ_PKT_HEADER_SCOPE, ir::FieldLocScope::PKT_HEADER,
                                 _mTraceCls->pktHeaderFc());
    return _StateHandlingReaction::STOP;
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleEndReadPktContentState()
{
    /* Update for user */
    this->_updateForUser(_mItems.pktContentEnd);

    /* Next step depends on whether or not there's a single packet */
    if (_mCurPktExpectedLens.total == this->_infDataLen()) {
        /* Single packet: next, end reading the packet */
        this->_state(_State::END_READ_PKT);
    } else {
        /*
         * Compute the non-content padding data to skip to reach the end
         * of the packet.
         */
        BT_ASSERT_DBG(_mCurPktExpectedLens.content != this->_infDataLen());

        const auto lenToSkip = _mCurPktExpectedLens.total - _mHeadOffsetInCurPkt;

        if (lenToSkip > 0_bits) {
            /*
             * Set the state so as to skip padding, but also try to skip
             * all of it immediately.
             */
            _mRemainingLenToSkip = lenToSkip;
            _mPostSkipPaddingState = _State::END_READ_PKT;
            this->_state(_State::SKIP_PADDING);
            this->_skipPadding<false>();
        } else {
            /* No padding: next, end reading the packet*/
            this->_state(_State::END_READ_PKT);
        }
    }

    return _StateHandlingReaction::STOP;
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleSkipPaddingState()
{
    this->_skipPadding<false>();

    /* Continue to `_mPostSkipPaddingState` */
    return _StateHandlingReaction::CONTINUE;
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleSkipContentPaddingState()
{
    this->_skipPadding<true>();

    /* Continue to `_mPostSkipPaddingState` */
    return _StateHandlingReaction::CONTINUE;
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleSetPktMagicNumberItem()
{
    /*
     * Update for user (the previous _handleUIntFieldRole() call already
     * set the value).
     */
    this->_updateForUser(_mItems.pktMagicNumber);

    /* Next: read next field */
    this->_prepareToReadNextField();
    return _StateHandlingReaction::STOP;
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleSetDefClkValItem()
{
    /*
     * Update for user (the previous _handleUIntFieldRole() call already
     * set the value).
     */
    this->_updateForUser(_mItems.defClkVal);

    /* Next: read next field */
    this->_prepareToReadNextField();
    return _StateHandlingReaction::STOP;
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleCommonBeginReadScopeState(const ir::FieldLocScope scope)
{
    /* Update for user */
    _mItems.scopeBegin._mScope = scope;
    this->_updateForUser(_mItems.scopeBegin);

    /* Next: read the scope structure field */
    BT_ASSERT_DBG(_mCurScope.fc);
    this->_prepareToReadStructField(*_mCurScope.fc);
    return _StateHandlingReaction::STOP;
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleCommonEndReadScopeState(const ir::FieldLocScope scope)
{
    /* Update for user */
    {
        _mItems.scopeEnd._mScope = scope;
        this->_updateForUser(_mItems.scopeEnd);
    }

    return _StateHandlingReaction::STOP;
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleTryBeginReadPktHeaderScopeState()
{
    if (!_mCurScope.fc) {
        /* No packet header field: set data stream info item immediately */
        this->_state(_State::SET_DATA_STREAM_INFO_ITEM);
        return _StateHandlingReaction::CONTINUE;
    }

    return this->_handleCommonBeginReadScopeState(ir::FieldLocScope::PKT_HEADER);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleEndReadPktHeaderScopeState()
{
    /* Next: set data stream info item */
    this->_state(_State::SET_DATA_STREAM_INFO_ITEM);

    /* End reading packet header scope */
    return this->_handleCommonEndReadScopeState(ir::FieldLocScope::PKT_HEADER);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleTryBeginReadPktCtxScopeState()
{
    if (!_mCurScope.fc) {
        /* No packet context field: set packet info item immediately */
        this->_state(_State::SET_PKT_INFO_ITEM);
        return _StateHandlingReaction::CONTINUE;
    }

    return this->_handleCommonBeginReadScopeState(ir::FieldLocScope::PKT_CTX);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleEndReadPktCtxScopeState()
{
    /* Next: set packet info item */
    this->_state(_State::SET_PKT_INFO_ITEM);

    /* End reading packet context scope */
    return this->_handleCommonEndReadScopeState(ir::FieldLocScope::PKT_CTX);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleTryBeginReadEventRecordHeaderScopeState()
{
    if (!_mCurScope.fc) {
        /*
         * No event record header field: set event record info item
         * immediately.
         */
        this->_state(_State::SET_EVENT_RECORD_INFO_ITEM);
        return _StateHandlingReaction::CONTINUE;
    }

    return this->_handleCommonBeginReadScopeState(ir::FieldLocScope::EVENT_RECORD_HEADER);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleEndReadEventRecordHeaderScopeState()
{
    /* Next: set event record info item */
    this->_state(_State::SET_EVENT_RECORD_INFO_ITEM);

    /* End reading event record header scope */
    return this->_handleCommonEndReadScopeState(ir::FieldLocScope::EVENT_RECORD_HEADER);
}

void ItemSeqIter::_handleCommonAfterEventRecordCommonCtxScopeState()
{
    if (_mItems.eventRecordInfo._mCls) {
        /* Next: try reading specific context field */
        this->_prepareToTryReadScope(_State::TRY_BEGIN_READ_EVENT_RECORD_SPEC_CTX_SCOPE,
                                     _State::END_READ_EVENT_RECORD_SPEC_CTX_SCOPE,
                                     ir::FieldLocScope::EVENT_RECORD_SPEC_CTX,
                                     _mItems.eventRecordInfo._mCls->specCtxFc());
    } else {
        /* Next: end event record */
        this->_state(_State::END_READ_EVENT_RECORD);
    }
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleTryBeginReadEventRecordCommonCtxScopeState()
{
    if (!_mCurScope.fc) {
        /* No common event record context field */
        this->_handleCommonAfterEventRecordCommonCtxScopeState();
        return _StateHandlingReaction::CONTINUE;
    }

    return this->_handleCommonBeginReadScopeState(ir::FieldLocScope::EVENT_RECORD_COMMON_CTX);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleEndReadEventRecordCommonCtxScopeState()
{
    this->_handleCommonAfterEventRecordCommonCtxScopeState();
    return this->_handleCommonEndReadScopeState(ir::FieldLocScope::EVENT_RECORD_COMMON_CTX);
}

void ItemSeqIter::_handleCommonAfterEventRecordSpecCtxScopeState()
{
    BT_ASSERT_DBG(_mItems.eventRecordInfo._mCls);

    /* Next: try reading payload field */
    this->_prepareToTryReadScope(_State::TRY_BEGIN_READ_EVENT_RECORD_PAYLOAD_SCOPE,
                                 _State::END_READ_EVENT_RECORD_PAYLOAD_SCOPE,
                                 ir::FieldLocScope::EVENT_RECORD_PAYLOAD,
                                 _mItems.eventRecordInfo._mCls->payloadFc());
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleTryBeginReadEventRecordSpecCtxScopeState()
{
    if (!_mCurScope.fc) {
        /* No specific event record context field */
        this->_handleCommonAfterEventRecordSpecCtxScopeState();
        return _StateHandlingReaction::CONTINUE;
    }

    return this->_handleCommonBeginReadScopeState(ir::FieldLocScope::EVENT_RECORD_SPEC_CTX);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleEndReadEventRecordSpecCtxScopeState()
{
    this->_handleCommonAfterEventRecordSpecCtxScopeState();
    return this->_handleCommonEndReadScopeState(ir::FieldLocScope::EVENT_RECORD_SPEC_CTX);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleTryBeginReadEventRecordPayloadScopeState()
{
    if (!_mCurScope.fc) {
        /* No event record payload field: end event record immediately */
        this->_state(_State::END_READ_EVENT_RECORD);
        return _StateHandlingReaction::CONTINUE;
    }

    return this->_handleCommonBeginReadScopeState(ir::FieldLocScope::EVENT_RECORD_PAYLOAD);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleEndReadEventRecordPayloadScopeState()
{
    /* Next: end reading event record */
    this->_state(_State::END_READ_EVENT_RECORD);

    /* End reading event record payload scope */
    return this->_handleCommonEndReadScopeState(ir::FieldLocScope::EVENT_RECORD_PAYLOAD);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleSetDataStreamInfoItemState()
{
    /* Set data stream class, if any */
    if (_mCurClsId) {
        _mItems.dataStreamInfo._mCls = (*_mTraceCls)[*_mCurClsId];

        if (!_mItems.dataStreamInfo._mCls) {
            std::ostringstream ss;

            ss << "no data stream class exists with ID " << *_mCurClsId << '.';
            this->_logAppendCauseAndThrow(ss);
        }

        /*
         * Reset `_mCurClsId` because we also use this member for the
         * current event record class ID.
         */
        _mCurClsId = bt2s::nullopt;
    } else {
        /*
         * If there's no current data stream class ID and our trace
         * class has a single data stream class, then use this one.
         */
        BT_ASSERT_DBG(_mTraceCls->size() <= 1);

        if (_mTraceCls->size() == 1) {
            _mItems.dataStreamInfo._mCls = _mTraceCls->begin()->get();
        }
    }

    /* Update for user */
    this->_updateForUser(_mItems.dataStreamInfo);

    /*
     * Next step depends on whether or not there's a current data stream
     * class.
     */
    if (_mItems.dataStreamInfo._mCls) {
        /* Next: try reading its packet context field */
        this->_prepareToTryReadScope(_State::TRY_BEGIN_READ_PKT_CTX_SCOPE,
                                     _State::END_READ_PKT_CTX_SCOPE, ir::FieldLocScope::PKT_CTX,
                                     _mItems.dataStreamInfo._mCls->pktCtxFc());
    } else {
        /* Next: end of packet content: set packet info item */
        this->_state(_State::SET_PKT_INFO_ITEM);
    }

    return _StateHandlingReaction::STOP;
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleSetPktInfoItemState()
{
    /* Automatically set expected packet lengths from each other */
    {
        if (_mCurPktExpectedLens.total == this->_infDataLen()) {
            _mCurPktExpectedLens.total = _mCurPktExpectedLens.content;
        }

        if (_mCurPktExpectedLens.content == this->_infDataLen()) {
            _mCurPktExpectedLens.content = _mCurPktExpectedLens.total;
        }
    }

    /* Validate expected packet lengths */
    {
        if (_mCurPktExpectedLens.total.hasExtraBits()) {
            std::ostringstream ss;

            ss << "expected total length of current packet (" << *_mCurPktExpectedLens.total
               << " bits) isn't a multiple of 8 bits.";
            this->_logAppendCauseAndThrow(ss);
        }

        if (_mCurPktExpectedLens.content > _mCurPktExpectedLens.total) {
            std::ostringstream ss;

            ss << "expected content length of current packet (" << *_mCurPktExpectedLens.content
               << " bits) is greater than its expected total length ("
               << *_mCurPktExpectedLens.total << " bits).";
            this->_logAppendCauseAndThrow(ss);
        }
    }

    /* Update for user */
    if (_mItems.dataStreamInfo._mCls && _mItems.dataStreamInfo._mCls->defClkCls()) {
        _mItems.pktInfo._mBeginDefClkVal = _mDefClkVal;
    }

    this->_updateForUser(_mItems.pktInfo);

    /* Next: try reading an event record */
    this->_state(_State::TRY_BEGIN_READ_EVENT_RECORD);
    return _StateHandlingReaction::STOP;
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleSetEventRecordInfoItemState()
{
    BT_ASSERT_DBG(_mItems.dataStreamInfo._mCls);

    auto& dataStreamCls = *_mItems.dataStreamInfo._mCls;

    /* Set event record class, if any */
    if (_mCurClsId) {
        _mItems.eventRecordInfo._mCls = (*_mItems.dataStreamInfo._mCls)[*_mCurClsId];

        if (!_mItems.eventRecordInfo._mCls) {
            std::ostringstream ss;

            ss << "no event record class exists with ID " << *_mCurClsId << " within the "
               << "data stream class with ID " << _mItems.dataStreamInfo._mCls->id() << '.';
            this->_logAppendCauseAndThrow(ss);
        }
    } else {
        /*
         * If there's no current event record class ID and our current
         * data stream class has a single event record class, then use
         * this one.
         */
        BT_ASSERT_DBG(dataStreamCls.size() <= 1);

        if (dataStreamCls.size() == 1) {
            _mItems.eventRecordInfo._mCls = dataStreamCls.begin()->get();
        }
    }

    /* Update for user */
    if (dataStreamCls.defClkCls()) {
        _mItems.eventRecordInfo._mDefClkVal = _mDefClkVal;
    }

    this->_updateForUser(_mItems.eventRecordInfo);

    /* Next: try reading common event record context field */
    this->_prepareToTryReadScope(_State::TRY_BEGIN_READ_EVENT_RECORD_COMMON_CTX_SCOPE,
                                 _State::END_READ_EVENT_RECORD_COMMON_CTX_SCOPE,
                                 ir::FieldLocScope::EVENT_RECORD_COMMON_CTX,
                                 dataStreamCls.eventRecordCommonCtxFc());
    return _StateHandlingReaction::STOP;
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleTryBeginReadEventRecordState()
{
    /*
     * Next step depends on whether or not there's remaining packet
     * content data and whether or not it's a single-packet item
     * sequence.
     */
    BT_ASSERT_DBG(_mItems.dataStreamInfo._mCls);

    if (_mCurPktExpectedLens.content == this->_infDataLen()) {
        /* Single packet */
        if (this->_remainingBufLen() == 0_bits) {
            /*
             * Try having 1 bit to see if we're at the end of the
             * packet.
             */
            if (!this->_tryHaveData(1_bits)) {
                /* No more data: no more event records */
                this->_state(_State::END_READ_PKT_CONTENT);
                return _StateHandlingReaction::CONTINUE;
            }
        }
    } else if (this->_remainingPktContentLen() == 0_bits) {
        /* End of packet content: no more event records */
        this->_state(_State::END_READ_PKT_CONTENT);
        return _StateHandlingReaction::CONTINUE;
    }

    /* Update for user */
    this->_updateForUser(_mItems.eventRecordBegin);

    /* Next: try reading the event record header field */
    BT_ASSERT_DBG(this->_remainingPktContentLen() > 0_bits);
    this->_prepareToTryReadScope(_State::TRY_BEGIN_READ_EVENT_RECORD_HEADER_SCOPE,
                                 _State::END_READ_EVENT_RECORD_HEADER_SCOPE,
                                 ir::FieldLocScope::EVENT_RECORD_HEADER,
                                 _mItems.dataStreamInfo._mCls->eventRecordHeaderFc());
    return _StateHandlingReaction::STOP;
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleEndReadEventRecordState()
{
    /* Update for user */
    this->_updateForUser(_mItems.eventRecordEnd);

    /* Next: try reading the next event record */
    this->_state(_State::TRY_BEGIN_READ_EVENT_RECORD);
    return _StateHandlingReaction::STOP;
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleBeginReadStructFieldState()
{
    /* Update for user */
    this->_setFieldItemFcAndUpdateForUser(_mItems.structFieldBegin, *this->_stackTop().fc);

    /* Structure field class */
    auto& structFc = this->_stackTop().fc->asStruct();

    /* Align head for structure field */
    this->_alignHead(structFc);

    /* Next step depends on whether or not the structure field is empty */
    if (structFc.isEmpty()) {
        /* Next: end reading the structure field */
        this->_restoreState();
    } else {
        /* Set length (member count) */
        this->_stackTop().len = structFc.size();

        /* Next: read the first struct field */
        this->_prepareToReadField(structFc.begin()->fc());
    }

    return _StateHandlingReaction::STOP;
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleEndReadStructFieldState()
{
    return this->_handleCommonEndReadCompoundFieldState(_mItems.structFieldEnd);
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleCommonBeginReadArrayFieldState(const unsigned long long len,
                                                   const ArrayFc& arrayFc)
{
    /* Align head for array field */
    this->_alignHead(arrayFc);

    /* Next step depends on whether or not the array field is empty */
    if (len == 0) {
        /* Next: end reading the array field */
        this->_restoreState();
    } else {
        /* Set length (element count) */
        this->_stackTop().len = len;

        /* Next: read the first element field */
        this->_prepareToReadField(arrayFc.elemFc());
    }

    return _StateHandlingReaction::STOP;
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleBeginReadStaticLenArrayFieldState()
{
    /* Update for user */
    this->_setFieldItemFcAndUpdateForUser(_mItems.staticLenArrayFieldBegin, *this->_stackTop().fc);

    /* Static-length array field class */
    auto& arrayFc = this->_stackTop().fc->asStaticLenArray();

    /* Begin reading static-length array field */
    return this->_handleCommonBeginReadArrayFieldState(arrayFc.len(), arrayFc);
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleBeginReadStaticLenArrayFieldMetadataStreamUuidState()
{
    /* Update for user */
    this->_setFieldItemFcAndUpdateForUser(_mItems.staticLenArrayFieldBegin, *this->_stackTop().fc);

    /* Static-length array field class */
    auto& arrayFc = this->_stackTop().fc->asStaticLenArray();

    BT_ASSERT_DBG(arrayFc.len() == _mItems.metadataStreamUuid._mUuid.size());

    /* Align head for array field */
    this->_alignHead(arrayFc);

    /* Next step: read the first byte field */
    {
        _mCurScalarFc = &arrayFc.elemFc();

        if (arrayFc.elemFc().type() == Fc::Type::FIXED_LEN_UINT) {
            this->_state(_State::READ_FIXED_LEN_METADATA_STREAM_UUID_BYTE_UINT_FIELD_BA_8);
        } else {
            BT_ASSERT_DBG(arrayFc.elemFc().type() == Fc::Type::FIXED_LEN_UENUM);
            this->_state(_State::READ_FIXED_LEN_METADATA_STREAM_UUID_BYTE_UENUM_FIELD_BA_8);
        }
    }

    return _StateHandlingReaction::STOP;
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleSetMetadataStreamUuidItemState()
{
    /* Update for user */
    this->_updateForUser(_mItems.metadataStreamUuid);

    /*
     * Next: end reading static-length metadata stream UUID array/BLOB
     * field.
     */
    this->_restoreState();
    return _StateHandlingReaction::STOP;
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleEndReadStaticLenArrayFieldState()
{
    return this->_handleCommonEndReadCompoundFieldState(_mItems.staticLenArrayFieldEnd);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleBeginReadDynLenArrayFieldState()
{
    /* Dynamic-length array field class */
    auto& arrayFc = this->_stackTop().fc->asDynLenArray();

    /* Get length of array field */
    const auto len = this->_savedUIntVal(arrayFc);

    /* Update for user */
    this->_setFieldItemFcAndUpdateForUser(_mItems.dynLenArrayFieldBegin, *this->_stackTop().fc);
    _mItems.dynLenArrayFieldBegin._mLen = len;

    /* Begin reading dynamic-length array field */
    return this->_handleCommonBeginReadArrayFieldState(len, arrayFc);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleEndReadDynLenArrayFieldState()
{
    return this->_handleCommonEndReadCompoundFieldState(_mItems.dynLenArrayFieldEnd);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleBeginReadNullTerminatedStrFieldState()
{
    /* Update for user */
    this->_setFieldItemFcAndUpdateForUser(_mItems.nullTerminatedStrFieldBegin,
                                          *this->_stackTop().fc);

    /* Align head for string field */
    this->_alignHead(*this->_stackTop().fc);

    /* Next: read substring until (and including) a null character */
    this->_state(_State::READ_SUBSTR_UNTIL_NULL_CHAR);
    return _StateHandlingReaction::STOP;
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleEndReadNullTerminatedStrFieldState()
{
    return this->_handleCommonEndReadCompoundFieldState(_mItems.nullTerminatedStrFieldEnd);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadSubstrUntilNullCharState()
{
    BT_ASSERT_DBG(!_mHeadOffsetInCurPkt.hasExtraBits());

    /* Require at least one byte of packet content */
    this->_requireContentData(1_bytes);
    BT_ASSERT_DBG(this->_remainingBufLen() >= 1_bytes);

    /* Find any null character within the current buffer */
    const auto begin = this->_bufAtHead();
    const auto maxEnd = begin + this->_remainingBufLen().bytes();
    auto end = std::find(begin, maxEnd, '\0');
    auto foundNullChar = false;

    if (end != maxEnd) {
        /* Include the null character found */
        ++end;
        foundNullChar = true;
    }

    /* Make sure the substring is completely part of the packet content */
    const auto substrLen = bt2c::DataLen::fromBytes(end - begin);

    if (substrLen > this->_remainingPktContentLen()) {
        std::ostringstream ss;

        ss << substrLen.bytes() << " string field substring bytes "
           << " required at this point, but only " << *this->_remainingPktContentLen()
           << " bits of packet content remain.";
        this->_logAppendCauseAndThrow(ss);
    }

    /* Update for user */
    _mItems.strFieldSubstr._mBegin = reinterpret_cast<const char *>(begin);
    _mItems.strFieldSubstr._mEnd = reinterpret_cast<const char *>(end);
    BT_ASSERT_DBG(substrLen >= 1_bytes);
    this->_updateForUser(_mItems.strFieldSubstr);

    /* Mark the substring as consumed */
    this->_consumeAvailData(substrLen);

    /* End found yet? */
    if (foundNullChar) {
        /* Next: end reading null-terminated string field */
        this->_restoreState();
    }

    return _StateHandlingReaction::STOP;
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleCommonBeginReadStrBlobFieldState(const unsigned long long len,
                                                     const _State contentState, const Fc& fc)
{
    /* Align head for string/BLOB field */
    this->_alignHead(fc);

    /* Next step depends on whether or not the string/BLOB field is empty */
    if (len == 0) {
        /* Next: end reading the string/BLOB field */
        this->_restoreState();
    } else {
        /* Set length (byte count) */
        this->_stackTop().len = len;

        /* Next: new state */
        this->_state(contentState);
    }

    return _StateHandlingReaction::STOP;
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleBeginReadStaticLenStrFieldState()
{
    /* Update for user */
    this->_setFieldItemFcAndUpdateForUser(_mItems.staticLenStrFieldBegin, *this->_stackTop().fc);

    /* Static-length string field class */
    auto& strFc = this->_stackTop().fc->asStaticLenStr();

    /* Begin reading static-length string field */
    return this->_handleCommonBeginReadStrBlobFieldState(strFc.len(), _State::READ_SUBSTR, strFc);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleEndReadStaticLenStrFieldState()
{
    return this->_handleCommonEndReadCompoundFieldState(_mItems.staticLenStrFieldEnd);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleBeginReadDynLenStrFieldState()
{
    /* Dynamic-length string field class */
    auto& strFc = this->_stackTop().fc->asDynLenStr();

    /* Get length of string field */
    const auto len = this->_savedUIntVal(strFc);

    /* Update for user */
    this->_setFieldItemFcAndUpdateForUser(_mItems.dynLenStrFieldBegin, *this->_stackTop().fc);
    _mItems.dynLenStrFieldBegin._mLen = bt2c::DataLen::fromBytes(len);

    /* Begin reading dynamic-length string field */
    return this->_handleCommonBeginReadStrBlobFieldState(len, _State::READ_SUBSTR, strFc);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleEndReadDynLenStrFieldState()
{
    return this->_handleCommonEndReadCompoundFieldState(_mItems.dynLenStrFieldEnd);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadSubstrState()
{
    return this->_handleCommonReadBytesState<char>(_mItems.strFieldSubstr);
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleCommonBeginReadStaticLenBlobFieldState(const _State contentState)
{
    /* Update for user */
    this->_setFieldItemFcAndUpdateForUser(_mItems.staticLenBlobFieldBegin, *this->_stackTop().fc);

    /* Static-length BLOB field class */
    auto& blobFc = this->_stackTop().fc->asStaticLenBlob();

    /* Begin reading static-length BLOB field */
    return this->_handleCommonBeginReadStrBlobFieldState(blobFc.len(), contentState, blobFc);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleBeginReadStaticLenBlobFieldState()
{
    return this->_handleCommonBeginReadStaticLenBlobFieldState(_State::READ_BLOB_FIELD_SECTION);
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleBeginReadStaticLenBlobFieldMetadataStreamUuidState()
{
    return this->_handleCommonBeginReadStaticLenBlobFieldState(
        _State::READ_METADATA_STREAM_UUID_BLOB_FIELD_SECTION);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleEndReadStaticLenBlobFieldState()
{
    return this->_handleCommonEndReadCompoundFieldState(_mItems.staticLenBlobFieldEnd);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleBeginReadDynLenBlobFieldState()
{
    /* Dynamic-length BLOB field class */
    auto& blobFc = this->_stackTop().fc->asDynLenBlob();

    /* Get length of BLOB field */
    const auto len = this->_savedUIntVal(blobFc);

    /* Update for user */
    this->_setFieldItemFcAndUpdateForUser(_mItems.dynLenBlobFieldBegin, *this->_stackTop().fc);
    _mItems.dynLenBlobFieldBegin._mLen = bt2c::DataLen::fromBytes(len);

    /* Begin reading dynamic-length BLOB field */
    return this->_handleCommonBeginReadStrBlobFieldState(len, _State::READ_BLOB_FIELD_SECTION,
                                                         blobFc);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleEndReadDynLenBlobFieldState()
{
    return this->_handleCommonEndReadCompoundFieldState(_mItems.dynLenBlobFieldEnd);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadBlobFieldSectionState()
{
    return this->_handleCommonReadBytesState<std::uint8_t>(_mItems.blobFieldSection);
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleReadMetadataStreamUuidBlobFieldSectionState()
{
    const auto uuidByteIndex = this->_stackTop().elemIndex;

    this->_handleCommonReadBytesNoNextState<std::uint8_t>(_mItems.blobFieldSection);

    /*
     * Set current metadata stream UUID bytes from current BLOB section.
     */
    BT_ASSERT_DBG(uuidByteIndex + _mItems.blobFieldSection.size().bytes() <=
                  _mItems.metadataStreamUuid._mUuid.size());
    std::copy(_mItems.blobFieldSection._mBegin, _mItems.blobFieldSection._mEnd,
              _mCurMetadataStreamUuid.data() + uuidByteIndex);

    /*
     * Next step depends on whether or not we're done reading all the
     * metadata stream UUID bytes.
     */
    if (this->_stackTop().elemIndex == _mItems.metadataStreamUuid._mUuid.size()) {
        /* Update for user */
        _mItems.metadataStreamUuid._mUuid = bt2c::Uuid {_mCurMetadataStreamUuid.data()};

        /* Next: set metadata stream UUID item */
        this->_state(_State::SET_METADATA_STREAM_UUID_ITEM);
    }

    return _StateHandlingReaction::STOP;
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleBeginReadVariantFieldWithUIntSelState()
{
    return this->_handleCommonBeginReadVariantField<VariantWithUIntSelFc>(
        _mItems.variantFieldWithUIntSelBegin);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleEndReadVariantFieldWithUIntSelState()
{
    return this->_handleCommonEndReadCompoundFieldState(_mItems.variantFieldWithUIntSelEnd);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleBeginReadVariantFieldWithSIntSelState()
{
    return this->_handleCommonBeginReadVariantField<VariantWithSIntSelFc>(
        _mItems.variantFieldWithSIntSelBegin);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleEndReadVariantFieldWithSIntSelState()
{
    return this->_handleCommonEndReadCompoundFieldState(_mItems.variantFieldWithSIntSelEnd);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleBeginReadOptionalFieldWithBoolSelState()
{
    return this->_handleCommonBeginReadOptionalField<OptionalWithBoolSelFc>(
        _mItems.optionalFieldWithBoolSelBegin);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleEndReadOptionalFieldWithBoolSelState()
{
    return this->_handleCommonEndReadCompoundFieldState(_mItems.optionalFieldWithBoolSelEnd);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleBeginReadOptionalFieldWithUIntSelState()
{
    return this->_handleCommonBeginReadOptionalField<OptionalWithUIntSelFc>(
        _mItems.optionalFieldWithUIntSelBegin);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleEndReadOptionalFieldWithUIntSelState()
{
    return this->_handleCommonEndReadCompoundFieldState(_mItems.optionalFieldWithUIntSelEnd);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleBeginReadOptionalFieldWithSIntSelState()
{
    return this->_handleCommonBeginReadOptionalField<OptionalWithSIntSelFc>(
        _mItems.optionalFieldWithSIntSelBegin);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleEndReadOptionalFieldWithSIntSelState()
{
    return this->_handleCommonEndReadCompoundFieldState(_mItems.optionalFieldWithSIntSelEnd);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBitArrayFieldBeState()
{
    return this->_handleCommonReadFixedLenBitArrayFieldState<0, ir::ByteOrder::BIG>(
        _mItems.fixedLenBitArrayField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBitArrayFieldLeState()
{
    return this->_handleCommonReadFixedLenBitArrayFieldState<0, ir::ByteOrder::LITTLE>(
        _mItems.fixedLenBitArrayField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBitArrayFieldBa8State()
{
    return this->_handleCommonReadFixedLenBitArrayFieldState<8, ir::ByteOrder::BIG>(
        _mItems.fixedLenBitArrayField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBitArrayFieldBa16LeState()
{
    return this->_handleCommonReadFixedLenBitArrayFieldState<16, ir::ByteOrder::LITTLE>(
        _mItems.fixedLenBitArrayField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBitArrayFieldBa16BeState()
{
    return this->_handleCommonReadFixedLenBitArrayFieldState<16, ir::ByteOrder::BIG>(
        _mItems.fixedLenBitArrayField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBitArrayFieldBa32LeState()
{
    return this->_handleCommonReadFixedLenBitArrayFieldState<32, ir::ByteOrder::LITTLE>(
        _mItems.fixedLenBitArrayField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBitArrayFieldBa32BeState()
{
    return this->_handleCommonReadFixedLenBitArrayFieldState<32, ir::ByteOrder::BIG>(
        _mItems.fixedLenBitArrayField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBitArrayFieldBa64LeState()
{
    return this->_handleCommonReadFixedLenBitArrayFieldState<64, ir::ByteOrder::LITTLE>(
        _mItems.fixedLenBitArrayField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBitArrayFieldBa64BeState()
{
    return this->_handleCommonReadFixedLenBitArrayFieldState<64, ir::ByteOrder::BIG>(
        _mItems.fixedLenBitArrayField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBoolFieldBeState()
{
    return this->_handleCommonReadFixedLenBoolFieldState<0, ir::ByteOrder::BIG, _SaveVal::NO>(
        _mItems.fixedLenBoolField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBoolFieldLeState()
{
    return this->_handleCommonReadFixedLenBoolFieldState<0, ir::ByteOrder::LITTLE, _SaveVal::NO>(
        _mItems.fixedLenBoolField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBoolFieldBa8State()
{
    return this->_handleCommonReadFixedLenBoolFieldState<8, ir::ByteOrder::BIG, _SaveVal::NO>(
        _mItems.fixedLenBoolField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBoolFieldBa16LeState()
{
    return this->_handleCommonReadFixedLenBoolFieldState<16, ir::ByteOrder::LITTLE, _SaveVal::NO>(
        _mItems.fixedLenBoolField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBoolFieldBa16BeState()
{
    return this->_handleCommonReadFixedLenBoolFieldState<16, ir::ByteOrder::BIG, _SaveVal::NO>(
        _mItems.fixedLenBoolField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBoolFieldBa32LeState()
{
    return this->_handleCommonReadFixedLenBoolFieldState<32, ir::ByteOrder::LITTLE, _SaveVal::NO>(
        _mItems.fixedLenBoolField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBoolFieldBa32BeState()
{
    return this->_handleCommonReadFixedLenBoolFieldState<32, ir::ByteOrder::BIG, _SaveVal::NO>(
        _mItems.fixedLenBoolField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBoolFieldBa64LeState()
{
    return this->_handleCommonReadFixedLenBoolFieldState<64, ir::ByteOrder::LITTLE, _SaveVal::NO>(
        _mItems.fixedLenBoolField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBoolFieldBa64BeState()
{
    return this->_handleCommonReadFixedLenBoolFieldState<64, ir::ByteOrder::BIG, _SaveVal::NO>(
        _mItems.fixedLenBoolField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBoolFieldBeSaveValState()
{
    return this->_handleCommonReadFixedLenBoolFieldState<0, ir::ByteOrder::BIG, _SaveVal::YES>(
        _mItems.fixedLenBoolField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBoolFieldLeSaveValState()
{
    return this->_handleCommonReadFixedLenBoolFieldState<0, ir::ByteOrder::LITTLE, _SaveVal::YES>(
        _mItems.fixedLenBoolField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBoolFieldBa8SaveValState()
{
    return this->_handleCommonReadFixedLenBoolFieldState<8, ir::ByteOrder::BIG, _SaveVal::YES>(
        _mItems.fixedLenBoolField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBoolFieldBa16LeSaveValState()
{
    return this->_handleCommonReadFixedLenBoolFieldState<16, ir::ByteOrder::LITTLE, _SaveVal::YES>(
        _mItems.fixedLenBoolField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBoolFieldBa16BeSaveValState()
{
    return this->_handleCommonReadFixedLenBoolFieldState<16, ir::ByteOrder::BIG, _SaveVal::YES>(
        _mItems.fixedLenBoolField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBoolFieldBa32LeSaveValState()
{
    return this->_handleCommonReadFixedLenBoolFieldState<32, ir::ByteOrder::LITTLE, _SaveVal::YES>(
        _mItems.fixedLenBoolField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBoolFieldBa32BeSaveValState()
{
    return this->_handleCommonReadFixedLenBoolFieldState<32, ir::ByteOrder::BIG, _SaveVal::YES>(
        _mItems.fixedLenBoolField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBoolFieldBa64LeSaveValState()
{
    return this->_handleCommonReadFixedLenBoolFieldState<64, ir::ByteOrder::LITTLE, _SaveVal::YES>(
        _mItems.fixedLenBoolField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenBoolFieldBa64BeSaveValState()
{
    return this->_handleCommonReadFixedLenBoolFieldState<64, ir::ByteOrder::BIG, _SaveVal::YES>(
        _mItems.fixedLenBoolField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenFloatField32BeState()
{
    return this->_handleCommonReadFixedLenFloatFieldState<0, ir::ByteOrder::BIG, float>();
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenFloatField32LeState()
{
    return this->_handleCommonReadFixedLenFloatFieldState<0, ir::ByteOrder::LITTLE, float>();
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenFloatField64BeState()
{
    return this->_handleCommonReadFixedLenFloatFieldState<0, ir::ByteOrder::BIG, double>();
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenFloatField64LeState()
{
    return this->_handleCommonReadFixedLenFloatFieldState<0, ir::ByteOrder::LITTLE, double>();
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenFloatFieldBa32LeState()
{
    return this->_handleCommonReadFixedLenFloatFieldState<32, ir::ByteOrder::LITTLE, float>();
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenFloatFieldBa32BeState()
{
    return this->_handleCommonReadFixedLenFloatFieldState<32, ir::ByteOrder::BIG, float>();
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenFloatFieldBa64LeState()
{
    return this->_handleCommonReadFixedLenFloatFieldState<64, ir::ByteOrder::LITTLE, double>();
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenFloatFieldBa64BeState()
{
    return this->_handleCommonReadFixedLenFloatFieldState<64, ir::ByteOrder::BIG, double>();
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldBeState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 0, ir::ByteOrder::BIG,
                                                         _WithRole::NO, _SaveVal::NO>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldLeState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 0, ir::ByteOrder::LITTLE,
                                                         _WithRole::NO, _SaveVal::NO>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldBa8State()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 8, ir::ByteOrder::BIG,
                                                         _WithRole::NO, _SaveVal::NO>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldBa16LeState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 16, ir::ByteOrder::LITTLE,
                                                         _WithRole::NO, _SaveVal::NO>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldBa16BeState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 16, ir::ByteOrder::BIG,
                                                         _WithRole::NO, _SaveVal::NO>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldBa32LeState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 32, ir::ByteOrder::LITTLE,
                                                         _WithRole::NO, _SaveVal::NO>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldBa32BeState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 32, ir::ByteOrder::BIG,
                                                         _WithRole::NO, _SaveVal::NO>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldBa64LeState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 64, ir::ByteOrder::LITTLE,
                                                         _WithRole::NO, _SaveVal::NO>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldBa64BeState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 64, ir::ByteOrder::BIG,
                                                         _WithRole::NO, _SaveVal::NO>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldBeWithRoleState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 0, ir::ByteOrder::BIG,
                                                         _WithRole::YES, _SaveVal::NO>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldLeWithRoleState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 0, ir::ByteOrder::LITTLE,
                                                         _WithRole::YES, _SaveVal::NO>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldBa8WithRoleState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 8, ir::ByteOrder::BIG,
                                                         _WithRole::YES, _SaveVal::NO>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldBa16LeWithRoleState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 16, ir::ByteOrder::LITTLE,
                                                         _WithRole::YES, _SaveVal::NO>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldBa16BeWithRoleState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 16, ir::ByteOrder::BIG,
                                                         _WithRole::YES, _SaveVal::NO>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldBa32LeWithRoleState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 32, ir::ByteOrder::LITTLE,
                                                         _WithRole::YES, _SaveVal::NO>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldBa32BeWithRoleState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 32, ir::ByteOrder::BIG,
                                                         _WithRole::YES, _SaveVal::NO>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldBa64LeWithRoleState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 64, ir::ByteOrder::LITTLE,
                                                         _WithRole::YES, _SaveVal::NO>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldBa64BeWithRoleState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 64, ir::ByteOrder::BIG,
                                                         _WithRole::YES, _SaveVal::NO>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldBeSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 0, ir::ByteOrder::BIG,
                                                         _WithRole::NO, _SaveVal::YES>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldLeSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 0, ir::ByteOrder::LITTLE,
                                                         _WithRole::NO, _SaveVal::YES>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldBa8SaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 8, ir::ByteOrder::BIG,
                                                         _WithRole::NO, _SaveVal::YES>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldBa16LeSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 16, ir::ByteOrder::LITTLE,
                                                         _WithRole::NO, _SaveVal::YES>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldBa16BeSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 16, ir::ByteOrder::BIG,
                                                         _WithRole::NO, _SaveVal::YES>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldBa32LeSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 32, ir::ByteOrder::LITTLE,
                                                         _WithRole::NO, _SaveVal::YES>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldBa32BeSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 32, ir::ByteOrder::BIG,
                                                         _WithRole::NO, _SaveVal::YES>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldBa64LeSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 64, ir::ByteOrder::LITTLE,
                                                         _WithRole::NO, _SaveVal::YES>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUIntFieldBa64BeSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 64, ir::ByteOrder::BIG,
                                                         _WithRole::NO, _SaveVal::YES>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleReadFixedLenUIntFieldBeWithRoleSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 0, ir::ByteOrder::BIG,
                                                         _WithRole::YES, _SaveVal::YES>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleReadFixedLenUIntFieldLeWithRoleSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 0, ir::ByteOrder::LITTLE,
                                                         _WithRole::YES, _SaveVal::YES>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleReadFixedLenUIntFieldBa8WithRoleSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 8, ir::ByteOrder::BIG,
                                                         _WithRole::YES, _SaveVal::YES>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleReadFixedLenUIntFieldBa16LeWithRoleSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 16, ir::ByteOrder::LITTLE,
                                                         _WithRole::YES, _SaveVal::YES>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleReadFixedLenUIntFieldBa16BeWithRoleSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 16, ir::ByteOrder::BIG,
                                                         _WithRole::YES, _SaveVal::YES>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleReadFixedLenUIntFieldBa32LeWithRoleSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 32, ir::ByteOrder::LITTLE,
                                                         _WithRole::YES, _SaveVal::YES>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleReadFixedLenUIntFieldBa32BeWithRoleSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 32, ir::ByteOrder::BIG,
                                                         _WithRole::YES, _SaveVal::YES>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleReadFixedLenUIntFieldBa64LeWithRoleSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 64, ir::ByteOrder::LITTLE,
                                                         _WithRole::YES, _SaveVal::YES>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleReadFixedLenUIntFieldBa64BeWithRoleSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 64, ir::ByteOrder::BIG,
                                                         _WithRole::YES, _SaveVal::YES>(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSIntFieldBeState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 0, ir::ByteOrder::BIG,
                                                         _SaveVal::NO>(_mItems.fixedLenSIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSIntFieldLeState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 0, ir::ByteOrder::LITTLE,
                                                         _SaveVal::NO>(_mItems.fixedLenSIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSIntFieldBa8State()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 8, ir::ByteOrder::BIG,
                                                         _SaveVal::NO>(_mItems.fixedLenSIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSIntFieldBa16LeState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 16, ir::ByteOrder::LITTLE,
                                                         _SaveVal::NO>(_mItems.fixedLenSIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSIntFieldBa16BeState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 16, ir::ByteOrder::BIG,
                                                         _SaveVal::NO>(_mItems.fixedLenSIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSIntFieldBa32LeState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 32, ir::ByteOrder::LITTLE,
                                                         _SaveVal::NO>(_mItems.fixedLenSIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSIntFieldBa32BeState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 32, ir::ByteOrder::BIG,
                                                         _SaveVal::NO>(_mItems.fixedLenSIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSIntFieldBa64LeState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 64, ir::ByteOrder::LITTLE,
                                                         _SaveVal::NO>(_mItems.fixedLenSIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSIntFieldBa64BeState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 64, ir::ByteOrder::BIG,
                                                         _SaveVal::NO>(_mItems.fixedLenSIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSIntFieldBeSaveValState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 0, ir::ByteOrder::BIG,
                                                         _SaveVal::YES>(_mItems.fixedLenSIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSIntFieldLeSaveValState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 0, ir::ByteOrder::LITTLE,
                                                         _SaveVal::YES>(_mItems.fixedLenSIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSIntFieldBa8SaveValState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 8, ir::ByteOrder::BIG,
                                                         _SaveVal::YES>(_mItems.fixedLenSIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSIntFieldBa16LeSaveValState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 16, ir::ByteOrder::LITTLE,
                                                         _SaveVal::YES>(_mItems.fixedLenSIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSIntFieldBa16BeSaveValState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 16, ir::ByteOrder::BIG,
                                                         _SaveVal::YES>(_mItems.fixedLenSIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSIntFieldBa32LeSaveValState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 32, ir::ByteOrder::LITTLE,
                                                         _SaveVal::YES>(_mItems.fixedLenSIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSIntFieldBa32BeSaveValState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 32, ir::ByteOrder::BIG,
                                                         _SaveVal::YES>(_mItems.fixedLenSIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSIntFieldBa64LeSaveValState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 64, ir::ByteOrder::LITTLE,
                                                         _SaveVal::YES>(_mItems.fixedLenSIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSIntFieldBa64BeSaveValState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 64, ir::ByteOrder::BIG,
                                                         _SaveVal::YES>(_mItems.fixedLenSIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldBeState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 0, ir::ByteOrder::BIG,
                                                         _WithRole::NO, _SaveVal::NO>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldLeState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 0, ir::ByteOrder::LITTLE,
                                                         _WithRole::NO, _SaveVal::NO>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldBa8State()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 8, ir::ByteOrder::BIG,
                                                         _WithRole::NO, _SaveVal::NO>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldBa16LeState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 16, ir::ByteOrder::LITTLE,
                                                         _WithRole::NO, _SaveVal::NO>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldBa16BeState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 16, ir::ByteOrder::BIG,
                                                         _WithRole::NO, _SaveVal::NO>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldBa32LeState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 32, ir::ByteOrder::LITTLE,
                                                         _WithRole::NO, _SaveVal::NO>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldBa32BeState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 32, ir::ByteOrder::BIG,
                                                         _WithRole::NO, _SaveVal::NO>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldBa64LeState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 64, ir::ByteOrder::LITTLE,
                                                         _WithRole::NO, _SaveVal::NO>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldBa64BeState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 64, ir::ByteOrder::BIG,
                                                         _WithRole::NO, _SaveVal::NO>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldBeWithRoleState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 0, ir::ByteOrder::BIG,
                                                         _WithRole::YES, _SaveVal::NO>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldLeWithRoleState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 0, ir::ByteOrder::LITTLE,
                                                         _WithRole::YES, _SaveVal::NO>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldBa8WithRoleState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 8, ir::ByteOrder::BIG,
                                                         _WithRole::YES, _SaveVal::NO>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldBa16LeWithRoleState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 16, ir::ByteOrder::LITTLE,
                                                         _WithRole::YES, _SaveVal::NO>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldBa16BeWithRoleState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 16, ir::ByteOrder::BIG,
                                                         _WithRole::YES, _SaveVal::NO>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldBa32LeWithRoleState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 32, ir::ByteOrder::LITTLE,
                                                         _WithRole::YES, _SaveVal::NO>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldBa32BeWithRoleState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 32, ir::ByteOrder::BIG,
                                                         _WithRole::YES, _SaveVal::NO>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldBa64LeWithRoleState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 64, ir::ByteOrder::LITTLE,
                                                         _WithRole::YES, _SaveVal::NO>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldBa64BeWithRoleState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 64, ir::ByteOrder::BIG,
                                                         _WithRole::YES, _SaveVal::NO>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldBeSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 0, ir::ByteOrder::BIG,
                                                         _WithRole::NO, _SaveVal::YES>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldLeSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 0, ir::ByteOrder::LITTLE,
                                                         _WithRole::NO, _SaveVal::YES>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldBa8SaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 8, ir::ByteOrder::BIG,
                                                         _WithRole::NO, _SaveVal::YES>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldBa16LeSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 16, ir::ByteOrder::LITTLE,
                                                         _WithRole::NO, _SaveVal::YES>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldBa16BeSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 16, ir::ByteOrder::BIG,
                                                         _WithRole::NO, _SaveVal::YES>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldBa32LeSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 32, ir::ByteOrder::LITTLE,
                                                         _WithRole::NO, _SaveVal::YES>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldBa32BeSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 32, ir::ByteOrder::BIG,
                                                         _WithRole::NO, _SaveVal::YES>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldBa64LeSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 64, ir::ByteOrder::LITTLE,
                                                         _WithRole::NO, _SaveVal::YES>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenUEnumFieldBa64BeSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 64, ir::ByteOrder::BIG,
                                                         _WithRole::NO, _SaveVal::YES>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleReadFixedLenUEnumFieldBeWithRoleSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 0, ir::ByteOrder::BIG,
                                                         _WithRole::YES, _SaveVal::YES>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleReadFixedLenUEnumFieldLeWithRoleSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 0, ir::ByteOrder::LITTLE,
                                                         _WithRole::YES, _SaveVal::YES>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleReadFixedLenUEnumFieldBa8WithRoleSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 8, ir::ByteOrder::BIG,
                                                         _WithRole::YES, _SaveVal::YES>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleReadFixedLenUEnumFieldBa16LeWithRoleSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 16, ir::ByteOrder::LITTLE,
                                                         _WithRole::YES, _SaveVal::YES>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleReadFixedLenUEnumFieldBa16BeWithRoleSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 16, ir::ByteOrder::BIG,
                                                         _WithRole::YES, _SaveVal::YES>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleReadFixedLenUEnumFieldBa32LeWithRoleSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 32, ir::ByteOrder::LITTLE,
                                                         _WithRole::YES, _SaveVal::YES>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleReadFixedLenUEnumFieldBa32BeWithRoleSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 32, ir::ByteOrder::BIG,
                                                         _WithRole::YES, _SaveVal::YES>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleReadFixedLenUEnumFieldBa64LeWithRoleSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 64, ir::ByteOrder::LITTLE,
                                                         _WithRole::YES, _SaveVal::YES>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleReadFixedLenUEnumFieldBa64BeWithRoleSaveValState()
{
    return this->_handleCommonReadFixedLenUIntFieldState<FixedLenUIntFc, 64, ir::ByteOrder::BIG,
                                                         _WithRole::YES, _SaveVal::YES>(
        _mItems.fixedLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSEnumFieldBeState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 0, ir::ByteOrder::BIG,
                                                         _SaveVal::NO>(_mItems.fixedLenSEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSEnumFieldLeState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 0, ir::ByteOrder::LITTLE,
                                                         _SaveVal::NO>(_mItems.fixedLenSEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSEnumFieldBa8State()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 8, ir::ByteOrder::BIG,
                                                         _SaveVal::NO>(_mItems.fixedLenSEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSEnumFieldBa16LeState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 16, ir::ByteOrder::LITTLE,
                                                         _SaveVal::NO>(_mItems.fixedLenSEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSEnumFieldBa16BeState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 16, ir::ByteOrder::BIG,
                                                         _SaveVal::NO>(_mItems.fixedLenSEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSEnumFieldBa32LeState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 32, ir::ByteOrder::LITTLE,
                                                         _SaveVal::NO>(_mItems.fixedLenSEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSEnumFieldBa32BeState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 32, ir::ByteOrder::BIG,
                                                         _SaveVal::NO>(_mItems.fixedLenSEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSEnumFieldBa64LeState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 64, ir::ByteOrder::LITTLE,
                                                         _SaveVal::NO>(_mItems.fixedLenSEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSEnumFieldBa64BeState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 64, ir::ByteOrder::BIG,
                                                         _SaveVal::NO>(_mItems.fixedLenSEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSEnumFieldBeSaveValState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 0, ir::ByteOrder::BIG,
                                                         _SaveVal::YES>(_mItems.fixedLenSEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSEnumFieldLeSaveValState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 0, ir::ByteOrder::LITTLE,
                                                         _SaveVal::YES>(_mItems.fixedLenSEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSEnumFieldBa8SaveValState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 8, ir::ByteOrder::BIG,
                                                         _SaveVal::YES>(_mItems.fixedLenSEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSEnumFieldBa16LeSaveValState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 16, ir::ByteOrder::LITTLE,
                                                         _SaveVal::YES>(_mItems.fixedLenSEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSEnumFieldBa16BeSaveValState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 16, ir::ByteOrder::BIG,
                                                         _SaveVal::YES>(_mItems.fixedLenSEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSEnumFieldBa32LeSaveValState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 32, ir::ByteOrder::LITTLE,
                                                         _SaveVal::YES>(_mItems.fixedLenSEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSEnumFieldBa32BeSaveValState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 32, ir::ByteOrder::BIG,
                                                         _SaveVal::YES>(_mItems.fixedLenSEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSEnumFieldBa64LeSaveValState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 64, ir::ByteOrder::LITTLE,
                                                         _SaveVal::YES>(_mItems.fixedLenSEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadFixedLenSEnumFieldBa64BeSaveValState()
{
    return this->_handleCommonReadFixedLenSIntFieldState<FixedLenSIntFc, 64, ir::ByteOrder::BIG,
                                                         _SaveVal::YES>(_mItems.fixedLenSEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadVarLenUIntFieldState()
{
    return this->_handleCommonReadVarLenUIntFieldState<VarLenUIntFc, _WithRole::NO, _SaveVal::NO>(
        _mItems.varLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadVarLenUIntFieldWithRoleState()
{
    return this->_handleCommonReadVarLenUIntFieldState<VarLenUIntFc, _WithRole::YES, _SaveVal::NO>(
        _mItems.varLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadVarLenUIntFieldSaveValState()
{
    return this->_handleCommonReadVarLenUIntFieldState<VarLenUIntFc, _WithRole::NO, _SaveVal::YES>(
        _mItems.varLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadVarLenUIntFieldWithRoleSaveValState()
{
    return this->_handleCommonReadVarLenUIntFieldState<VarLenUIntFc, _WithRole::YES, _SaveVal::YES>(
        _mItems.varLenUIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadVarLenSIntFieldState()
{
    return this->_handleCommonReadVarLenSIntFieldState<VarLenSIntFc, _SaveVal::NO>(
        _mItems.varLenSIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadVarLenSIntFieldSaveValState()
{
    return this->_handleCommonReadVarLenSIntFieldState<VarLenSIntFc, _SaveVal::YES>(
        _mItems.varLenSIntField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadVarLenUEnumFieldState()
{
    return this->_handleCommonReadVarLenUIntFieldState<VarLenUIntFc, _WithRole::NO, _SaveVal::NO>(
        _mItems.varLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadVarLenUEnumFieldWithRoleState()
{
    return this->_handleCommonReadVarLenUIntFieldState<VarLenUIntFc, _WithRole::YES, _SaveVal::NO>(
        _mItems.varLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadVarLenUEnumFieldSaveValState()
{
    return this->_handleCommonReadVarLenUIntFieldState<VarLenUIntFc, _WithRole::NO, _SaveVal::YES>(
        _mItems.varLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadVarLenUEnumFieldWithRoleSaveValState()
{
    return this->_handleCommonReadVarLenUIntFieldState<VarLenUIntFc, _WithRole::YES, _SaveVal::YES>(
        _mItems.varLenUEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadVarLenSEnumFieldState()
{
    return this->_handleCommonReadVarLenSIntFieldState<VarLenSIntFc, _SaveVal::NO>(
        _mItems.varLenSEnumField);
}

ItemSeqIter::_StateHandlingReaction ItemSeqIter::_handleReadVarLenSEnumFieldSaveValState()
{
    return this->_handleCommonReadVarLenSIntFieldState<VarLenSIntFc, _SaveVal::YES>(
        _mItems.varLenSEnumField);
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleReadFixedLenMetadataStreamUuidByteUIntFieldBa8State()
{
    return this->_handleCommonFixedLenMetadataStreamUuidByteUIntFieldBa8State(
        _mItems.fixedLenUIntField);
}

ItemSeqIter::_StateHandlingReaction
ItemSeqIter::_handleReadFixedLenMetadataStreamUuidByteUEnumFieldBa8State()
{
    return this->_handleCommonFixedLenMetadataStreamUuidByteUIntFieldBa8State(
        _mItems.fixedLenUEnumField);
}

} /* namespace src */
} /* namespace ctf */
