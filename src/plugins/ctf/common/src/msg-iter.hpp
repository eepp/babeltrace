/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 EfficiOS, Inc
 */

#ifndef CTF_COMMON_SRC_MSG_ITER_HPP
#define CTF_COMMON_SRC_MSG_ITER_HPP

#include <babeltrace2/babeltrace.h>
#include <queue>
#include <stack>

#include "cpp-common/bt2/message.hpp"

#include "item-seq/item-seq-iter.hpp"
#include "item-seq/item-visitor.hpp"
#include "item-seq/logging-item-visitor.hpp"

namespace ctf {
namespace src {

/* Various quirks that the message iterator can work around. */
struct Quirks
{
    bool lttngCrash = false;
    bool lttngEventAfterPacket = false;
    bool barectfEventBeforePacket = false;
};

class MsgIter;

namespace internal {

/* ItemSeqIter visitor that generates Babeltrace messages. */
struct MsgIterItemVisitor : public ItemVisitor
{
    friend class ctf::src::MsgIter;

    MsgIterItemVisitor(bt_self_message_iterator *selfMsgIter, ItemSeqIter& itemSeqIter,
                       LoggingItemVisitor& loggingVisitor, bt2::Stream stream, Quirks quirks,
                       const bt2_common::LogCfg& logCfg);

    void visit(const Item& item) override __attribute__((noreturn));

    void visit(const DefClkValItem& item) override;

    void visit(const PktBeginItem& item) override;
    void visit(const PktContentBeginItem& item) override;
    void visit(const PktInfoItem& item) override;
    void visit(const DataStreamInfoItem& item) override;
    void visit(const PktContentEndItem& item) override;
    void visit(const PktEndItem& item) override;
    void visit(const EventRecordInfoItem& item) override;
    void visit(const EventRecordBeginItem& item) override;
    void visit(const EventRecordEndItem& item) override;

    void visit(const ScopeBeginItem& item) override;
    void visit(const ScopeEndItem& item) override;

    void visit(const StructFieldBeginItem& item) override;
    void visit(const StructFieldEndItem& item) override;

    void visit(const VariantFieldBeginItem&) override;
    void visit(const VariantFieldEndItem& item) override;

    void visit(const StaticLenArrayFieldBeginItem& item) override;
    void visit(const DynLenArrayFieldBeginItem&) override;
    void visit(const ArrayFieldEndItem& item) override;

    void visit(const FixedLenUIntFieldItem& item) override;
    void visit(const FixedLenSIntFieldItem& item) override;
    void visit(const FixedLenUEnumFieldItem& item) override;
    void visit(const FixedLenSEnumFieldItem& item) override;

    void visit(const NullTerminatedStrFieldBeginItem& item) override;
    void visit(const NullTerminatedStrFieldEndItem& item) override;
    void visit(const StaticLenStrFieldBeginItem& item) override;
    void visit(const StaticLenStrFieldEndItem& item) override;
    void visit(const DynLenStrFieldBeginItem& item) override;
    void visit(const DynLenStrFieldEndItem& item) override;
    void visit(const StrFieldSubstrItem& item) override;

    void visit(const FixedLenFloatFieldItem& item) override;

    nonstd::optional<bt2::ConstMessage::Shared> releaseMessageIfReady();

private:
    /* Advance the current field index. */
    void _advanceField();

    /* Get the current field. */
    bt2::Field _currentField();

    /* Get the current field and advance the current field index. */
    bt2::Field _currentFieldAndAdvance();

    /* Return the current packet if there is one, else nullptr. */
    bt_packet *_currentPacket()
    {
        if (_mCurrentPacket) {
            return (*_mCurrentPacket)->libObjPtr();
        }

        return nullptr;
    }

    /* Set the current packet. */
    void _currentPacket(bt2::Packet::Shared packet)
    {
        BT_ASSERT_DBG(!this->_currentPacket());
        _mCurrentPacket.emplace(packet);
    }

    void _resetCurrentPacket()
    {
        BT_ASSERT_DBG(this->_currentPacket());
        _mCurrentPacket.reset();
    }

    void _emitDelayedPacketBeginning(nonstd::optional<unsigned long long> otherClkVal);
    void _emitPacketBeginningMsg(nonstd::optional<unsigned long long> clkVal);

    bt_self_message_iterator *_mSelfMsgIter;
    bt2::Stream _mLibStream;
    const Quirks _mQuirks;
    const bt2_common::LogCfg _mLogCfg;

    nonstd::optional<bt2::StructureField> _mCurRootScopeStructField;
    bool _mSkipUntilScopeEnd = false;

    /*
     * If non-nullptr, a message that we are building, that is not yet ready to
     * be returned.
     */
    nonstd::optional<bt2::Message::Shared> _mCurrentMessage;

    /*
     * If non-nullptr, the current packet. Set in the PktBeginItem handler,
     * cleared in the PktEndItem handler.
     */
    nonstd::optional<bt2::Packet::Shared> _mCurrentPacket;

    /*
     * Messages ready to be retrieved by the caller.  This is a queue instead of
     * a single because a single bt_message pointer because one item can
     * generate more than one message.
     */
    std::queue<bt2::ConstMessage::Shared> _mMessagesReady;

    /* Last seen packet sequence number. */
    nonstd::optional<unsigned long long> _mLastPacketSeqNum;

    nonstd::optional<unsigned long long> _mLastClkVal;

    /* Last seen discarded event counter value. */
    nonstd::optional<unsigned long long> _mLastDiscardedEventsSnap;

    /*
     * Clock snapshot of the beginning and end of the packet.  Set in the
     * PktInfoItem handler.  Cleared in the PktEndItem handler.
     */
    nonstd::optional<unsigned long long> _mPacketBeginDefClkVal;
    nonstd::optional<unsigned long long> _mPacketEndDefClkVal;

    /* Have we sent athe stream beginning message yet? */
    bool _mSentStreamBeginning = false;

    bool _mEmitDelayedPacketBeginning = false;

    bool _mSubStrSeenNullByte = false;

    struct StackFrame
    {
        StackFrame(bt2::StructureField structField) noexcept :
            _mFieldKind(_FieldKind::STRUCT), _mField(structField)
        {
        }

        StackFrame(bt2::VariantField variantField) noexcept :
            _mFieldKind(_FieldKind::VARIANT), _mField(variantField)
        {
        }

        StackFrame(bt2::ArrayField arrayField) noexcept :
            _mFieldKind(_FieldKind::ARRAY), _mField(arrayField)
        {
        }

        bt2::StructureField structureField() const noexcept
        {
            BT_ASSERT_DBG(_mFieldKind == _FieldKind::STRUCT);
            return _mField.structureField;
        }

        bt2::VariantField variantField() const noexcept
        {
            BT_ASSERT_DBG(_mFieldKind == _FieldKind::VARIANT);
            return _mField.variantField;
        }

        bt2::ArrayField arrayField() const noexcept
        {
            BT_ASSERT_DBG(_mFieldKind == _FieldKind::ARRAY);
            return _mField.arrayField;
        }

        unsigned long long _mSubFieldIndex() const noexcept
        {
            return _mSubFieldIdx;
        }

        void advanceField() noexcept
        {
            switch (_mFieldKind) {
            case _FieldKind::STRUCT:
            case _FieldKind::ARRAY:
                ++_mSubFieldIdx;
                break;
            case _FieldKind::VARIANT:
                break;
            }
        }

        bt2::Field currentField() noexcept
        {
            switch (_mFieldKind) {
            case _FieldKind::STRUCT:
                return _mField.structureField[_mSubFieldIdx];

            case _FieldKind::VARIANT:
                return _mField.variantField.selectedOptionField();

            case _FieldKind::ARRAY:
                return _mField.arrayField[_mSubFieldIdx];
            }

            bt_common_abort();
        }

        bt2::Field currentFieldAndAdvance() noexcept
        {
            switch (_mFieldKind) {
            case _FieldKind::STRUCT:
                return _mField.structureField[_mSubFieldIdx++];

            case _FieldKind::VARIANT:
                return _mField.variantField.selectedOptionField();

            case _FieldKind::ARRAY:
                return _mField.arrayField[_mSubFieldIdx++];
            }

            bt_common_abort();
        }

    private:
        enum class _FieldKind
        {
            STRUCT = 1,
            VARIANT,
            ARRAY,
        } _mFieldKind;

        union _Field
        {
            _Field()
            {
            }

            _Field(bt2::StructureField structureFieldParam)
            {
                new (&this->structureField) bt2::StructureField(structureFieldParam);
                static_assert(std::is_trivially_destructible<bt2::StructureField>::value,
                              "bt2::StructureField is trivially destructible");
            }

            _Field(bt2::VariantField variantFieldParam)
            {
                new (&this->variantField) bt2::VariantField(variantFieldParam);
                static_assert(std::is_trivially_destructible<bt2::VariantField>::value,
                              "bt2::VariantField is trivially destructible");
            }

            _Field(bt2::ArrayField arrayFieldParam)
            {
                new (&this->arrayField) bt2::ArrayField(arrayFieldParam);
                static_assert(std::is_trivially_destructible<bt2::ArrayField>::value,
                              "bt2::ArrayField is trivially destructible");
            }

            bt2::StructureField structureField;
            bt2::VariantField variantField;
            bt2::ArrayField arrayField;
        } _mField;

        unsigned long long _mSubFieldIdx = 0;
    };

    std::stack<StackFrame> _mStack;
};

} /* namespace internal */

/* CTF message iterator */
class MsgIter
{
public:
    MsgIter(bt_self_message_iterator *selfMsgIter, const ctf::src::TraceCls& tc, bt2::Stream stream,
            ctf::src::Medium::UP medium, Quirks quirks, const bt2_common::LogCfg logCfg);

    MsgIter(const MsgIter&) = delete;
    MsgIter& operator=(const MsgIter&) = delete;

    nonstd::optional<bt2::ConstMessage::Shared> next();

private:
    /* Current message iterator to create messages (weak) */
    bt_self_message_iterator *_mSelfMsgIter;

    const bt2_common::LogCfg _mLogCfg;

    bt2::Stream _mStream;
    ItemSeqIter _mItemSeqIter;
    LoggingItemVisitor _mLoggingVisitor;
    internal::MsgIterItemVisitor _mItemVisitor;
    bool _mDone = false;
};

}
}

#endif /* CTF_COMMON_SRC_MSG_ITER_HPP */
