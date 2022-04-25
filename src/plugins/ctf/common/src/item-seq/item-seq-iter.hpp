/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _CTF_SRC_ITEM_SEQ_ITEM_SEQ_ITER_HPP
#define _CTF_SRC_ITEM_SEQ_ITEM_SEQ_ITER_HPP

#include <cstdint>
#include <cstdlib>
#include <stdexcept>
#include <sstream>
#include <memory>
#include <vector>
#include <array>
#include <algorithm>
#include <numeric>
#include <limits>
#include <type_traits>

#include "common/assert.h"
#include "common/common.h"
#include "compat/bitfield.h"
#include "cpp-common/data-len.hpp"
#include "cpp-common/align.hpp"
#include "cpp-common/read-fixed-len-int.hpp"
#include "cpp-common/std-int.hpp"
#include "medium.hpp"
#include "item.hpp"

namespace ctf {
namespace src {

/*
 * Data stream decoding error.
 */
class DecodingError final : public bt2_common::Error
{
public:
    explicit DecodingError(std::string msg, const bt2_common::DataLen offset) :
        bt2_common::Error {std::move(msg)}, _mOffset {offset}
    {
    }

    /*
     * Offset, relative to the beginning of the item sequence (_not_ to
     * the beginning of a current packet), where this decoding error
     * occurred.
     */
    bt2_common::DataLen offset() const noexcept
    {
        return _mOffset;
    }

private:
    bt2_common::DataLen _mOffset;
};

class ItemSeqIter;

namespace internal {

/*
 * Return type of ReadFixedLenIntFunc::read() depending on `IsSignedV`.
 */
template <bool IsSignedV>
using ReadFixedLenIntFuncRetT =
    typename std::conditional<IsSignedV, long long, unsigned long long>::type;

/*
 * Provides the static read() method to read a fixed-length integer
 * having the byte order `ByteOrderV`, the signedness `IsSignedV`,
 * and the length `LenBitsV` from some buffer.
 *
 * `LenBitsV` must be one of:
 *
 * 0:
 *     Uses bt_bitfield_read_be() and bt_bitfield_read_le().
 *
 * 8, 16, 32, or 64:
 *     Uses bt2_common::readFixedLenIntBe() or
 *     bt2_common::readFixedLenIntLe().
 *
 *     The alignment of the field must be a multiple of 8.
 *
 * Declared here because explicit specialization in non-namespace scope
 * isn't allowed. Specializations are after the `ItemSeqIter` class
 * definition because they need to know it.
 */
template <ir::ByteOrder ByteOrderV, bool IsSignedV, std::size_t LenBitsV>
struct ReadFixedLenIntFunc;

/*
 * Provides the static val() method to get the value (of which the
 * signedness is `IsSignedV`) of a variable-length integer field from
 * some LEB128-decoded unsigned value of a given length.
 */
template <bool IsSignedV>
struct VarLenIntFieldVal;

template <>
struct VarLenIntFieldVal<false> final
{
    static unsigned long long val(const bt2_common::DataLen len,
                                  const unsigned long long v) noexcept
    {
        return v;
    }
};

template <>
struct VarLenIntFieldVal<true> final
{
    static unsigned long long val(const bt2_common::DataLen len, unsigned long long v) noexcept
    {
        using namespace bt2_common::literals::datalen;

        /* Sign-extend */
        const auto mask = 1ULL << (*len - 1);

        v = v & ((1ULL << *len) - 1);
        v = (v ^ mask) - mask;

        /* Return equivalent unsigned value */
        return v;
    }
};

} /* namespace internal */

/*
 * Item sequence iterator.
 *
 * An item sequence iterator can decode a sequence of packets using:
 *
 * • A medium, which provides binary stream data to the iterator.
 * • A trace class, which describes how to decode said data.
 *
 * The value of an item sequence iterator is an item. The item sequence
 * iterator doesn't actually create items as it advances: it has one
 * instance of each concrete item class and sets a pointer to one of
 * those as it advances (it's a single-pass input iterator).
 *
 * Seek a specific packet beginning with the seekPkt() method.
 *
 * Methods which make the iterator decode may throw `DecodingError`.
 *
 * NOTE: Currently, this isn't an STL-compliant iterator class: you
 * can't copy an instance and you can't get an end iterator, because
 * there's no item sequence (container) class (you need to use the
 * isEnded() method). Also, the typical STL type aliases such as `value`
 * and `reference` aren't part of the class.
 *
 * This API and its implementation are inspired by the yactfr
 * (<https://github.com/eepp/yactfr>) element sequence iterator API,
 * conveniently written by the same author.
 *
 * Expected item sequence
 * ══════════════════════
 * Here's what you can expect when you iterate an item sequence with
 * such an iterator.
 *
 * In the following descriptions, consider this language:
 *
 * `A B`:
 *     Item of type A followed by item of type B (two iterations).
 *
 * `A | B`:
 *     Item of type A _or_ item of type B (single iteration).
 *
 * `A *`:
 *     Item of type A occuring zero or more times (zero or more
 *     iterations).
 *
 * `A ?`:
 *    Item of type A occuring zero or one time (zero or one iteration).
 *
 * `A{N}`:
 *     Item of type A occuring N times (N iterations).
 *
 * `ScopeBeginItem<SCOPE>`:
 *     Item of type `ScopeBeginItem` with specific scope SCOPE.
 *
 * `( ... )`:
 *     Group of items of the given types or other groups.
 *
 * `[ ... ]`:
 *     Group of optional items of the given types or other groups.
 *
 * When a name is written in UPPERCASE, then it's a named group of items
 * having specific types. This is used to make the descriptions below
 * easier to read and to allow recursion.
 *
 * FIELD group
 * ───────────
 *     (
 *       (
 *         (
 *           FixedLenUIntFieldItem |
 *           FixedLenUEnumFieldItem |
 *           VarLenUIntFieldItem |
 *           VarLenUEnumFieldItem
 *         )
 *         DefClkValItem ?
 *       ) |
 *       FixedLenBitArrayFieldItem |
 *       FixedLenBoolFieldItem |
 *       FixedLenSIntFieldItem |
 *       FixedLenSEnumFieldItem |
 *       FixedLenFloatFieldItem |
 *       VarLenSIntFieldItem |
 *       VarLenSEnumFieldItem |
 *       (
 *         NullTerminatedStrFieldBeginItem
 *         StrFieldSubstrItem StrFieldSubstrItem *
 *         NullTerminatedStrFieldEndItem
 *       ) |
 *       (
 *         StaticLenArrayFieldBeginItem
 *         FIELD *
 *         StaticLenArrayFieldEndItem
 *       ) |
 *       (
 *         StaticLenArrayFieldBeginItem
 *         (FixedLenUIntFieldItem | FixedLenUEnumFieldItem){16}
 *         MetadataStreamUuidItem
 *         StaticLenArrayFieldEndItem
 *       ) |
 *       (
 *         DynLenArrayFieldBeginItem
 *         FIELD *
 *         DynLenArrayFieldEndItem
 *       ) |
 *       (
 *         StaticLenStrFieldBeginItem
 *         StrFieldSubstrItem *
 *         StaticLenStrFieldEndItem
 *       ) |
 *       (
 *         DynLenStrFieldBeginItem
 *         StrFieldSubstrItem *
 *         DynLenStrFieldEndItem
 *       ) |
 *       (
 *         StaticLenBlobFieldBeginItem
 *         BlobFieldSectionItem *
 *         MetadataStreamUuidItem ?
 *         StaticLenBlobFieldEndItem
 *       ) |
 *       (
 *         DynLenBlobFieldBeginItem
 *         BlobFieldSectionItem *
 *         DynLenBlobFieldEndItem
 *       ) |
 *       (
 *         StructFieldBeginItem
 *         FIELD *
 *         StructFieldEndItem
 *       ) |
 *       (
 *         VariantFieldWithUIntSelBeginItem
 *         FIELD
 *         VariantFieldWithUIntSelEndItem
 *       ) |
 *       (
 *         VariantFieldWithSIntSelBeginItem
 *         FIELD
 *         VariantFieldWithSIntSelEndItem
 *       ) |
 *       (
 *         OptionalFieldWithBoolSelBeginItem
 *         FIELD ?
 *         OptionalFieldWithBoolSelEndItem
 *       ) |
 *       (
 *         OptionalFieldWithUIntSelBeginItem
 *         FIELD ?
 *         OptionalFieldWithUIntSelEndItem
 *       ) |
 *       (
 *         OptionalFieldWithSIntSelBeginItem
 *         FIELD ?
 *         OptionalFieldWithSIntSelEndItem
 *       )
 *     )
 *
 * Note that:
 *
 * • A `DefClkValItem` item may only follow an unsigned integer field
 *   item when it's within the `FieldLocScope::PKT_CTX` or
 *   `FieldLocScope::EVENT_RECORD_HEADER` scope.
 *
 * • A `MetadataStreamUuidItem` item may only precede a
 *   `StaticLenArrayFieldEndItem` or a `StaticLenBlobFieldEndItem` item
 *   when it's within the `FieldLocScope::PKT_HEADER` scope.
 *
 * EVENT-RECORD group
 * ──────────────────
 *     (
 *       EventRecordBeginItem
 *       [
 *         ScopeBeginItem<EVENT_RECORD_HEADER>
 *         StructFieldBeginItem FIELD * StructFieldEndItem
 *         ScopeEndItem<EVENT_RECORD_HEADER>
 *       ]
 *       EventRecordInfoItem
 *       [
 *         ScopeBeginItem<EVENT_RECORD_COMMON_CTX>
 *         StructFieldBeginItem FIELD * StructFieldEndItem
 *         ScopeEndItem<EVENT_RECORD_COMMON_CTX>
 *       ]
 *       [
 *         ScopeBeginItem<EVENT_RECORD_SPEC_CTX>
 *         StructFieldBeginItem FIELD * StructFieldEndItem
 *         ScopeEndItem<EVENT_RECORD_SPEC_CTX>
 *       ]
 *       [
 *         ScopeBeginItem<EVENT_RECORD_PAYLOAD>
 *         StructFieldBeginItem FIELD * StructFieldEndItem
 *         ScopeEndItem<EVENT_RECORD_PAYLOAD>
 *       ]
 *       EventRecordEndItem
 *     )
 *
 * Note how an `EventRecordInfoItem` always exists, whether or not
 * there's an event record header field.
 *
 * PACKET group
 * ────────────
 *     (
 *       PktBeginItem PktContentBeginItem
 *       [
 *         ScopeBeginItem<PKT_HEADER>
 *         StructFieldBeginItem
 *         (
 *           (
 *             (FixedLenUIntFieldItem | FixedLenUEnumFieldItem)
 *             PktMagicNumberItem
 *           ) |
 *           StructFieldBeginItem FIELD * StructFieldEndItem
 *         ) *
 *         StructFieldEndItem
 *         ScopeEndItem<PKT_HEADER>
 *       ]
 *       DataStreamInfoItem
 *       [
 *         ScopeBeginItem<PKT_CONTEXT>
 *         StructFieldBeginItem FIELD * StructFieldEndItem
 *         ScopeEndItem<PKT_CONTEXT>
 *       ]
 *       PktInfoItem
 *       EVENT-RECORD *
 *       PktContentEndItem PktEndItem
 *     )
 *
 * Note how a `DataStreamInfoItem` always exists, whether or not there's
 * a packet header field, and how a `PktInfoItem` always exists, whether
 * or not there's a packet context field.
 *
 * Item sequence
 * ─────────────
 * The whole item sequence is just a sequence of zero or more packets:
 *
 *     PACKET *
 *
 * Padding exclusion
 * ═════════════════
 * The purpose of an item sequence iterator is to extract _data_ from
 * data streams. Considering this, an item sequence iterator doesn't
 * provide padding data. In other words, this API always _skips_ padding
 * bits so that the following field is aligned according to its
 * metadata.
 *
 * The guarantees of offset() are as follows, depending on the class of
 * the current item:
 *
 * `PktBeginItem`:
 *     The offset is the beginning of a packet, _excluding_ any prior
 *     padding following the previous packet content, if any.
 *
 * `PktEndItem`:
 *     The offset is the end of the packet, that is, following any
 *     padding following its content (the difference between the offset
 *     of this item and the offset at the prior `PktContentEndItem`, if
 *     any).
 *
 *     It's the same as it will be at the next `PktBeginItem`.
 *
 * `PktContentBeginItem`:
 *     The offset is the same as it was at the last `PktBeginItem`.
 *
 * `PktContentEndItem`:
 *     The offset is the same as it was at the last `ScopeEndItem`.
 *
 * `EventRecordBeginItem`:
 *     The offset is the beginning of an event record.
 *
 *     It's the same as it will be at the next `ScopeBeginItem`.
 *
 * `EventRecordEndItem`:
 *     The offset is the end of an event record.
 *
 *     It's the same as it was at the last `ScopeEndItem`.
 *
 * `ScopeBeginItem`:
 *     The offset is the same as it will be at the next
 *     `StructFieldBeginItem`.
 *
 * `ScopeEndItem`:
 *     The offset is the same as it was at the last
 *     `StructFieldEndItem`.
 *
 * `NullTerminatedStrFieldBeginItem`:
 * `StructFieldBeginItem`:
 * `NonNullTerminatedStrFieldBeginItem`:
 * `ArrayFieldBeginItem`:
 * `BlobFieldBeginItem`:
 * `VariantFieldBeginItem`:
 * `OptionalFieldBeginItem`:
 *     The offset is the beginning of the container field, that is, it's
 *     aligned according to the alignment of the container field class
 *     (with relation to the beginning of the packet).
 *
 * Other `EndItem`:
 *     Depending on the type of the previous item instance I:
 *
 *     `FixedLenBitArrayFieldItem`:
 *     `StrFieldSubstrItem`:
 *     `BlobFieldSectionItem`:
 *     `VarLenIntFieldItem`:
 *         The offset of I plus its length.
 *
 *     `EndItem`:
 *         The offset of I.
 *
 * Medium guarantees
 * ═════════════════
 * When you iterate an item sequence with operator++(), it's
 * _guaranteed_ that the requested offsets, when calling Medium::buf(),
 * increase monotonically. However, it's possible that two consecutive
 * returned buffers contain overlapping data, for example:
 *
 *     ▓▓▓▓▓▓▓▓▓▓▓▓▓▓
 *                ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
 *                              ▓▓▓▓▓▓▓
 *                                   ▓▓▓▓▓▓▓▓▓▓▓▓▓
 *                                             ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
 *
 * The length of overlapping data is always less than ten bytes.
 *
 * Implementation
 * ══════════════
 * An item sequence iterator is a state machine, its current state being
 * `_mState`.
 *
 * When you call operator++(), the iterator handles the current state
 * until the reaction is to stop (`_StateHandlingReaction::STOP`).
 * Stopping means that either there's a current item (the user may use
 * operator*()) or the iterator is ended (isEnded() returns `true`).
 *
 * The `_mItems` structure contains one instance of each concrete
 * item class. `_mCurItem` points to one of those instances. This is
 * why it's a single-pass input iterator: there's no dynamic item
 * allocation during the iteration process.
 *
 * _prepareToReadField() transforms a given field class into a field
 * reading state based on what's called its deep type. For fixed-length
 * and variable-length field classes, this deep type incorporates
 * important decoding information, for example:
 *
 * • Byte order.
 * • Length if it's a "standard" fixed-length bit array.
 * • Integer signedness.
 * • Whether or not the field has a role.
 * • Whether or not the value of the field has to be saved.
 *
 * Having a single `switch` statement in _prepareToReadField() to select
 * the next state makes it easier/possible for the compiler to optimize
 * as most common decisions are encoded in there.
 *
 * For example, if it's known that the next field to read is a
 * little-endian, byte-aligned 32-bit unsigned integer field of which
 * the iterator needs to save the value, then its deep type is
 * `FcDeepType::FIXED_LEN_UINT_BA_32_LE_SAVE_VAL` which means the state
 * `_State::READ_FIXED_LEN_UINT_FIELD_BA_32_LE_SAVE_VAL`, so that
 * _handleState() will jump to
 * _handleReadFixedLenUIntFieldBa32LeSaveValState() directly. The latter
 * method does exactly what's needed to perform such a field reading
 * operation efficiently (using bt2_common::readFixedLenIntLe()) and
 * saves the value without superfluous branches.
 *
 * Speaking about value saving, this is the strategy to decode
 * dynamic-length, optional, and variant fields (called dependend
 * fields) here. A field class FC of which the deep type contains
 * `SAVE_VAL` contains value saving indexes I (valSavingIndexes()
 * method). When decoding an instance of FC, the iterator saves the
 * value to `_mSavedVals` at the indexes I through _saveVal(). When
 * decoding a dependend field, its class contains an index in
 * `_mSavedVals` to retrieve a saved value (length or selector). The
 * state handler retrieves the value through _savedVal(). _savedVal()
 * casts the saved value (of type `unsigned long long` within
 * `_mSavedVals`) to a compatible type (`bool` or another integral
 * type).
 *
 * All the state handlers have the name _handle*State(), although there
 * are common state handling helpers which start with `_handleCommon`.
 *
 * State transitions
 * ─────────────────
 * Here's a Graphviz DOT source which shows the state transitions:
 *
 *     digraph {
 *         node [
 *             fontname = "monospace"
 *             fontsize = 12
 *             shape = box
 *             style = "rounded, filled"
 *         ]
 *
 *         edge [
 *             fontname = "sans-serif"
 *             fontsize = 8
 *             fontcolor = "#16a085"
 *         ]
 *
 *         read_pkt_header_struct_field [
 *             label = "Read structure field"
 *             fillcolor = "#8e44ad"
 *             fontcolor = "white"
 *             width = 3
 *         ]
 *
 *         read_pkt_ctx_struct_field [
 *             label = "Read structure field"
 *             fillcolor = "#8e44ad"
 *             fontcolor = "white"
 *             width = 3
 *         ]
 *
 *         read_event_record_header_struct_field [
 *             label = "Read structure field"
 *             fillcolor = "#8e44ad"
 *             fontcolor = "white"
 *             width = 3
 *         ]
 *
 *         read_event_record_common_ctx_struct_field [
 *             label = "Read structure field"
 *             fillcolor = "#8e44ad"
 *             fontcolor = "white"
 *             width = 3
 *         ]
 *
 *         read_event_record_spec_ctx_struct_field [
 *             label = "Read structure field"
 *             fillcolor = "#8e44ad"
 *             fontcolor = "white"
 *             width = 3
 *         ]
 *
 *         read_event_record_payload_struct_field [
 *             label = "Read structure field"
 *             fillcolor = "#8e44ad"
 *             fontcolor = "white"
 *             width = 3
 *         ]
 *
 *         INIT [fillcolor = "#27ae60", fontcolor = white]
 *         End [fillcolor = "#c0392b", fontcolor = white]
 *         TRY_BEGIN_READ_PKT [fillcolor = "#d35400", fontcolor = white]
 *         BEGIN_READ_PKT_CONTENT [fillcolor = "#d35400", fontcolor = white]
 *         TRY_BEGIN_READ_EVENT_RECORD [fillcolor = "#d35400", fontcolor = white]
 *         TRY_BEGIN_READ_PKT_HEADER_SCOPE [fillcolor = "#f39c12", fontcolor = white]
 *         TRY_BEGIN_READ_PKT_CTX_SCOPE [fillcolor = "#f39c12", fontcolor = white]
 *         TRY_BEGIN_READ_EVENT_RECORD_HEADER_SCOPE [fillcolor = "#f39c12", fontcolor = white]
 *         TRY_BEGIN_READ_EVENT_RECORD_COMMON_CTX_SCOPE [fillcolor = "#f39c12", fontcolor = white]
 *         TRY_BEGIN_READ_EVENT_RECORD_SPEC_CTX_SCOPE [fillcolor = "#f39c12", fontcolor = white]
 *         TRY_BEGIN_READ_EVENT_RECORD_PAYLOAD_SCOPE [fillcolor = "#f39c12", fontcolor = white]
 *         END_READ_PKT_HEADER_SCOPE [fillcolor = "#34495e", fontcolor = white]
 *         END_READ_PKT_CTX_SCOPE [fillcolor = "#34495e", fontcolor = white]
 *         END_READ_EVENT_RECORD_HEADER_SCOPE [fillcolor = "#34495e", fontcolor = white]
 *         END_READ_EVENT_RECORD_COMMON_CTX_SCOPE [fillcolor = "#34495e", fontcolor = white]
 *         END_READ_EVENT_RECORD_SPEC_CTX_SCOPE [fillcolor = "#34495e", fontcolor = white]
 *         END_READ_EVENT_RECORD_PAYLOAD_SCOPE [fillcolor = "#34495e", fontcolor = white]
 *         END_READ_EVENT_RECORD [fillcolor = "#2c3e50", fontcolor = white]
 *         END_READ_PKT_CONTENT [fillcolor = "#2c3e50", fontcolor = white]
 *         END_READ_PKT [fillcolor = "#2c3e50", fontcolor = white]
 *         SET_DATA_STREAM_INFO_ITEM [fillcolor = "#2980b9", fontcolor = white]
 *         SET_PKT_INFO_ITEM [fillcolor = "#2980b9", fontcolor = white]
 *         SET_EVENT_RECORD_INFO_ITEM [fillcolor = "#2980b9", fontcolor = white]
 *         SKIP_PADDING [fillcolor = "#ecf0f1", fontcolor = black]
 *
 *         INIT -> TRY_BEGIN_READ_PKT
 *         TRY_BEGIN_READ_PKT -> End [label = "No more data"]
 *         TRY_BEGIN_READ_PKT -> BEGIN_READ_PKT_CONTENT
 *         BEGIN_READ_PKT_CONTENT -> TRY_BEGIN_READ_PKT_HEADER_SCOPE
 *         TRY_BEGIN_READ_PKT_HEADER_SCOPE -> SET_DATA_STREAM_INFO_ITEM [label = "No field"]
 *         TRY_BEGIN_READ_PKT_HEADER_SCOPE -> read_pkt_header_struct_field
 *         read_pkt_header_struct_field -> END_READ_PKT_HEADER_SCOPE
 *         END_READ_PKT_HEADER_SCOPE -> SET_DATA_STREAM_INFO_ITEM
 *         SET_DATA_STREAM_INFO_ITEM -> TRY_BEGIN_READ_PKT_CTX_SCOPE
 *         SET_DATA_STREAM_INFO_ITEM -> SET_PKT_INFO_ITEM [label = "No data\nstream class"]
 *         TRY_BEGIN_READ_PKT_CTX_SCOPE -> SET_PKT_INFO_ITEM [label = "No field"]
 *         TRY_BEGIN_READ_PKT_CTX_SCOPE -> read_pkt_ctx_struct_field
 *         read_pkt_ctx_struct_field -> END_READ_PKT_CTX_SCOPE
 *         END_READ_PKT_CTX_SCOPE -> SET_PKT_INFO_ITEM
 *         SET_PKT_INFO_ITEM -> TRY_BEGIN_READ_EVENT_RECORD
 *         TRY_BEGIN_READ_EVENT_RECORD -> END_READ_PKT_CONTENT [label = "No more data"]
 *         TRY_BEGIN_READ_EVENT_RECORD -> TRY_BEGIN_READ_EVENT_RECORD_HEADER_SCOPE
 *         TRY_BEGIN_READ_EVENT_RECORD_HEADER_SCOPE -> SET_EVENT_RECORD_INFO_ITEM [label = "No field"]
 *         TRY_BEGIN_READ_EVENT_RECORD_HEADER_SCOPE -> read_event_record_header_struct_field
 *         read_event_record_header_struct_field -> END_READ_EVENT_RECORD_HEADER_SCOPE
 *         END_READ_EVENT_RECORD_HEADER_SCOPE -> SET_EVENT_RECORD_INFO_ITEM
 *         SET_EVENT_RECORD_INFO_ITEM -> TRY_BEGIN_READ_EVENT_RECORD_COMMON_CTX_SCOPE
 *         TRY_BEGIN_READ_EVENT_RECORD_COMMON_CTX_SCOPE -> END_READ_EVENT_RECORD [label = "No field,\nno event record class"]
 *         TRY_BEGIN_READ_EVENT_RECORD_COMMON_CTX_SCOPE -> TRY_BEGIN_READ_EVENT_RECORD_SPEC_CTX_SCOPE [label = "No field"]
 *         TRY_BEGIN_READ_EVENT_RECORD_COMMON_CTX_SCOPE -> read_event_record_common_ctx_struct_field
 *         read_event_record_common_ctx_struct_field -> END_READ_EVENT_RECORD_COMMON_CTX_SCOPE
 *         END_READ_EVENT_RECORD_COMMON_CTX_SCOPE -> END_READ_EVENT_RECORD [label = "No event record class"]
 *         END_READ_EVENT_RECORD_COMMON_CTX_SCOPE -> TRY_BEGIN_READ_EVENT_RECORD_SPEC_CTX_SCOPE
 *         TRY_BEGIN_READ_EVENT_RECORD_SPEC_CTX_SCOPE -> TRY_BEGIN_READ_EVENT_RECORD_PAYLOAD_SCOPE [label = "No field"]
 *         TRY_BEGIN_READ_EVENT_RECORD_SPEC_CTX_SCOPE -> read_event_record_spec_ctx_struct_field
 *         read_event_record_spec_ctx_struct_field -> END_READ_EVENT_RECORD_SPEC_CTX_SCOPE
 *         END_READ_EVENT_RECORD_SPEC_CTX_SCOPE -> TRY_BEGIN_READ_EVENT_RECORD_PAYLOAD_SCOPE
 *         TRY_BEGIN_READ_EVENT_RECORD_PAYLOAD_SCOPE -> END_READ_EVENT_RECORD [label = "No field"]
 *         TRY_BEGIN_READ_EVENT_RECORD_PAYLOAD_SCOPE -> read_event_record_payload_struct_field
 *         read_event_record_payload_struct_field -> END_READ_EVENT_RECORD_PAYLOAD_SCOPE
 *         END_READ_EVENT_RECORD_PAYLOAD_SCOPE -> END_READ_EVENT_RECORD
 *         END_READ_EVENT_RECORD -> TRY_BEGIN_READ_EVENT_RECORD
 *         END_READ_PKT_CONTENT -> END_READ_PKT [label="No padding"]
 *         END_READ_PKT_CONTENT -> SKIP_PADDING
 *         SKIP_PADDING -> SKIP_PADDING
 *         SKIP_PADDING -> END_READ_PKT
 *         END_READ_PKT -> TRY_BEGIN_READ_PKT
 *     }
 *
 * Buffer and offsets
 * ──────────────────
 * The "decoding head" of a an item sequence iterator is a position
 * within some buffer to decode the next field.
 *
 * An item sequence iterator works with four offsets:
 *
 * `_mBufOffsetInCurPkt`:
 *     The offset of the beginning of the buffer (`_mBuf`) within the
 *     current packet.
 *
 * `_mCurPktOffsetInItemSeq`:
 *     The offset of the current packet within the whole item sequence.
 *
 * `_mHeadOffsetInCurPkt`:
 *     The offset of the decoding head within the current packet.
 *
 *     This is the only member which the iterator updates systematically
 *     when it reads data. It's relative to the beginning of the packet
 *     because CTF (all versions) says that the alignment requirement
 *     of any field is relative to the beginning of its containing
 *     packet.
 *
 * Note that `_mCurItemOffsetInItemSeq`, the offset of the current item
 * within the whole item sequence, is not strictly needed for the
 * decoding operation. This is what the user-visible offset() method
 * returns. We can't compute it on demand, within the offset() method,
 * because once an iterator finishes reading a variable-length integer
 * field VF, its decoding head (`_mHeadOffsetInCurPkt`) is _after_ VF,
 * but offset() returns the offset at the _beginning_ of an item.
 *
 * The following illustration shows the meaning of the significant
 * decoding members in relation to a packet and a current buffer:
 *
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║                                          Decoding head                    ║
 * ║                                          ▼                                ║
 * ║ Packet: ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒ ║
 * ║ Buffer: ┊                         ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓          ┊ ║
 * ║         ┊                         ┊      ┊                   ┊          ┊ ║
 * ║         ┣┅┅ _mBufOffsetInCurPkt ┅┅┫      ┊                   ┊          ┊ ║
 * ║         ┣┅┅┅┅┅ _mHeadOffsetInCurPkt ┅┅┅┅┅┫                   ┊          ┊ ║
 * ║         ┊                         ┣┅┅┅┅┅┅ _mBuf.size() ┅┅┅┅┅┅┫          ┊ ║
 * ║         ┣┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅ _mCurPktExpectedLens.total ┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┫ ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 */
class ItemSeqIter final
{
    template <ir::ByteOrder, bool, std::size_t>
    friend struct internal::ReadFixedLenIntFunc;

public:
    /*
     * Creates an item sequence iterator using the medium `medium` and
     * the trace class `traceCls`.
     *
     * May throw whatever Medium::buf() may throw as well as
     * `DecodingError`.
     */
    explicit ItemSeqIter(Medium::UP medium, const TraceCls& traceCls);

    /*
     * Creates an item sequence iterator using the medium `medium` and
     * the trace class `traceCls`, initially seeking the medium to
     * `pktOffset`.
     *
     * May throw whatever Medium::buf() may throw as well as
     * `DecodingError`.
     */
    explicit ItemSeqIter(Medium::UP medium, const TraceCls& traceCls,
                         bt2_common::DataLen pktOffset);

    /*
     * Make the intention explicit here, but the medium unique pointer
     * isn't copyable anyway.
     */
    ItemSeqIter(const ItemSeqIter&) = delete;
    ItemSeqIter& operator=(const ItemSeqIter&) = delete;

    /*
     * Makes the underlying medium seek to `pktOffset` and resets the
     * state to decode a packet.
     *
     * May throw whatever Medium::buf() may throw as well as
     * `DecodingError`.
     */
    void seekPkt(bt2_common::DataLen pktOffset);

    /*
     * Advances the iterator to the next item, possibly ending it (check
     * with isEnded()).
     *
     * This iterator must not be ended (isEnded() returns `false`).
     *
     * May throw whatever Medium::buf() may throw as well as
     * `DecodingError`.
     */
    ItemSeqIter& operator++()
    {
        BT_ASSERT_DBG(!_mIsEnded);
        while (this->_handleState() == _StateHandlingReaction::CONTINUE)
            ;
        return *this;
    }

    /*
     * Whether or not this iterator is ended.
     *
     * When an iterator is ended, you may not call operator++().
     */
    bool isEnded() const noexcept
    {
        return _mIsEnded;
    }

    /*
     * Returns the current item of this iterator.
     *
     * This iterator must not be ended (isEnded() returns `false`).
     */
    const Item& operator*() const noexcept
    {
        BT_ASSERT_DBG(!this->isEnded());
        return *_mCurItem;
    }

    const Item *operator->() const noexcept
    {
        BT_ASSERT_DBG(!this->isEnded());
        return _mCurItem;
    }

    /*
     * Current offset of this iterator relative to the beginning of the
     * item sequence (_not_ to the beginning of some current packet).
     */
    bt2_common::DataLen offset() const noexcept
    {
        return _mCurItemOffsetInItemSeq;
    }

private:
    /*
     * State.
     */
    enum class _State
    {
        /* Begin reading a dynamic-length array field */
        BEGIN_READ_DYN_LEN_ARRAY_FIELD,

        /* Begin reading a dynamic-length BLOB field */
        BEGIN_READ_DYN_LEN_BLOB_FIELD,

        /* Begin reading a dynamic-length string field */
        BEGIN_READ_DYN_LEN_STR_FIELD,

        /* Begin reading a null-terminated string field */
        BEGIN_READ_NULL_TERMINATED_STR_FIELD,

        /* Begin reading an optional field with a boolean selector */
        BEGIN_READ_OPTIONAL_FIELD_WITH_BOOL_SEL,

        /* Begin reading an optional field with a signed integer selector */
        BEGIN_READ_OPTIONAL_FIELD_WITH_SINT_SEL,

        /* Begin reading an optional field with an unsigned integer selector */
        BEGIN_READ_OPTIONAL_FIELD_WITH_UINT_SEL,

        /* Begin reading the content of a packet */
        BEGIN_READ_PKT_CONTENT,

        /* Begin reading a static-length array field */
        BEGIN_READ_STATIC_LEN_ARRAY_FIELD,

        /*
         * Begin reading a static-length array field which contains the
         * metadata stream UUID (16 fixed-length unsigned integer fields).
         */
        BEGIN_READ_STATIC_LEN_ARRAY_FIELD_METADATA_STREAM_UUID,

        /* Begin reading a static-length BLOB field */
        BEGIN_READ_STATIC_LEN_BLOB_FIELD,

        /*
         * Begin reading a static-length BLOB field which contains the
         * metadata stream UUID (16 bytes).
         */
        BEGIN_READ_STATIC_LEN_BLOB_FIELD_METADATA_STREAM_UUID,

        /* Begin reading a static-length string field */
        BEGIN_READ_STATIC_LEN_STR_FIELD,

        /* Begin reading a structure field */
        BEGIN_READ_STRUCT_FIELD,

        /* Begin reading a variant field with a signed integer selector */
        BEGIN_READ_VARIANT_FIELD_WITH_SINT_SEL,

        /* Begin reading a variant field with an unsigned integer selector */
        BEGIN_READ_VARIANT_FIELD_WITH_UINT_SEL,

        /* End reading a dynamic-length array field */
        END_READ_DYN_LEN_ARRAY_FIELD,

        /* End reading a dynamic-length BLOB field */
        END_READ_DYN_LEN_BLOB_FIELD,

        /* End reading a dynamic-length string field */
        END_READ_DYN_LEN_STR_FIELD,

        /* End reading an event record */
        END_READ_EVENT_RECORD,

        /* End reading a common event record context scope */
        END_READ_EVENT_RECORD_COMMON_CTX_SCOPE,

        /* End reading an event record header scope */
        END_READ_EVENT_RECORD_HEADER_SCOPE,

        /* End reading an event record payload scope */
        END_READ_EVENT_RECORD_PAYLOAD_SCOPE,

        /* End reading a specific event record context scope */
        END_READ_EVENT_RECORD_SPEC_CTX_SCOPE,

        /* End reading a null-terminated string field */
        END_READ_NULL_TERMINATED_STR_FIELD,

        /* Begin reading an optional field with a boolean selector */
        END_READ_OPTIONAL_FIELD_WITH_BOOL_SEL,

        /* End reading an optional field with a signed integer selector */
        END_READ_OPTIONAL_FIELD_WITH_SINT_SEL,

        /* End reading an optional field with an unsigned integer selector */
        END_READ_OPTIONAL_FIELD_WITH_UINT_SEL,

        /* End reading a packet */
        END_READ_PKT,

        /* End reading the content of a packet */
        END_READ_PKT_CONTENT,

        /* End reading a packet context scope */
        END_READ_PKT_CTX_SCOPE,

        /* End reading a packet header scope */
        END_READ_PKT_HEADER_SCOPE,

        /* End reading a static-length array field */
        END_READ_STATIC_LEN_ARRAY_FIELD,

        /* End reading a static-length BLOB field */
        END_READ_STATIC_LEN_BLOB_FIELD,

        /* End reading a static-length string field */
        END_READ_STATIC_LEN_STR_FIELD,

        /* End reading a structure field */
        END_READ_STRUCT_FIELD,

        /* End reading a variant field with a signed integer selector */
        END_READ_VARIANT_FIELD_WITH_SINT_SEL,

        /* End reading a variant field with an unsigned integer selector */
        END_READ_VARIANT_FIELD_WITH_UINT_SEL,

        /* Initial state */
        INIT,

        /* Read a BLOB field section */
        READ_BLOB_FIELD_SECTION,

        /*
         * Read a byte-aligned, 16-bit big-endian fixed-length bit array
         * field.
         */
        READ_FIXED_LEN_BIT_ARRAY_FIELD_BA_16_BE,

        /*
         * Read a byte-aligned, 16-bit little-endian fixed-length bit
         * array field.
         */
        READ_FIXED_LEN_BIT_ARRAY_FIELD_BA_16_LE,

        /*
         * Read a byte-aligned, 32-bit big-endian fixed-length bit array
         * field.
         */
        READ_FIXED_LEN_BIT_ARRAY_FIELD_BA_32_BE,

        /*
         * Read a byte-aligned, 32-bit little-endian fixed-length bit
         * array field.
         */
        READ_FIXED_LEN_BIT_ARRAY_FIELD_BA_32_LE,

        /*
         * Read a byte-aligned, 64-bit big-endian fixed-length bit array
         * field.
         */
        READ_FIXED_LEN_BIT_ARRAY_FIELD_BA_64_BE,

        /*
         * Read a byte-aligned, 64-bit little-endian fixed-length bit
         * array field.
         */
        READ_FIXED_LEN_BIT_ARRAY_FIELD_BA_64_LE,

        /*
         * Read a byte-aligned, 8-bit little-endian fixed-length bit
         * array field.
         */
        READ_FIXED_LEN_BIT_ARRAY_FIELD_BA_8,

        /*
         * Read a big-endian fixed-length bit array field.
         */
        READ_FIXED_LEN_BIT_ARRAY_FIELD_BE,

        /*
         * Read a little-endian fixed-length bit array field.
         */
        READ_FIXED_LEN_BIT_ARRAY_FIELD_LE,

        /*
         * Read a byte-aligned, 16-bit big-endian fixed-length boolean
         * field.
         */
        READ_FIXED_LEN_BOOL_FIELD_BA_16_BE,

        /*
         * Read a byte-aligned, 16-bit big-endian fixed-length boolean
         * field and save its value.
         */
        READ_FIXED_LEN_BOOL_FIELD_BA_16_BE_SAVE_VAL,

        /*
         * Read a byte-aligned, 16-bit little-endian fixed-length
         * boolean field.
         */
        READ_FIXED_LEN_BOOL_FIELD_BA_16_LE,

        /*
         * Read a byte-aligned, 16-bit little-endian fixed-length
         * boolean field and save its value.
         */
        READ_FIXED_LEN_BOOL_FIELD_BA_16_LE_SAVE_VAL,

        /*
         * Read a byte-aligned, 32-bit big-endian fixed-length boolean
         * field.
         */
        READ_FIXED_LEN_BOOL_FIELD_BA_32_BE,

        /*
         * Read a byte-aligned, 32-bit big-endian fixed-length boolean
         * field and save its value.
         */
        READ_FIXED_LEN_BOOL_FIELD_BA_32_BE_SAVE_VAL,

        /*
         * Read a byte-aligned, 32-bit little-endian fixed-length
         * boolean field.
         */
        READ_FIXED_LEN_BOOL_FIELD_BA_32_LE,

        /*
         * Read a byte-aligned, 32-bit little-endian fixed-length
         * boolean field and save its value.
         */
        READ_FIXED_LEN_BOOL_FIELD_BA_32_LE_SAVE_VAL,

        /*
         * Read a byte-aligned, 64-bit big-endian fixed-length boolean
         * field.
         */
        READ_FIXED_LEN_BOOL_FIELD_BA_64_BE,

        /*
         * Read a byte-aligned, 64-bit big-endian fixed-length boolean
         * field and save its value.
         */
        READ_FIXED_LEN_BOOL_FIELD_BA_64_BE_SAVE_VAL,

        /*
         * Read a byte-aligned, 64-bit little-endian fixed-length
         * boolean field.
         */
        READ_FIXED_LEN_BOOL_FIELD_BA_64_LE,

        /*
         * Read a byte-aligned, 64-bit little-endian fixed-length
         * boolean field and save its value.
         */
        READ_FIXED_LEN_BOOL_FIELD_BA_64_LE_SAVE_VAL,

        /*
         * Read a byte-aligned, 8-bit little-endian fixed-length boolean
         * field.
         */
        READ_FIXED_LEN_BOOL_FIELD_BA_8,

        /*
         * Read a byte-aligned, 8-bit little-endian fixed-length boolean
         * field and save its value.
         */
        READ_FIXED_LEN_BOOL_FIELD_BA_8_SAVE_VAL,

        /*
         * Read a big-endian fixed-length boolean field.
         */
        READ_FIXED_LEN_BOOL_FIELD_BE,

        /*
         * Read a big-endian fixed-length boolean field and save its
         * value.
         */
        READ_FIXED_LEN_BOOL_FIELD_BE_SAVE_VAL,

        /*
         * Read a little-endian fixed-length boolean field.
         */
        READ_FIXED_LEN_BOOL_FIELD_LE,

        /*
         * Read a little-endian fixed-length boolean field and save its
         * value.
         */
        READ_FIXED_LEN_BOOL_FIELD_LE_SAVE_VAL,

        /*
         * Read a 32-bit big-endian fixed-length floating-point number
         * field.
         */
        READ_FIXED_LEN_FLOAT_FIELD_32_BE,

        /*
         * Read a 32-bit little-endian fixed-length floating-point
         * number field.
         */
        READ_FIXED_LEN_FLOAT_FIELD_32_LE,

        /*
         * Read a 64-bit big-endian fixed-length floating-point number
         * field.
         */
        READ_FIXED_LEN_FLOAT_FIELD_64_BE,

        /*
         * Read a 64-bit little-endian fixed-length floating-point
         * number field.
         */
        READ_FIXED_LEN_FLOAT_FIELD_64_LE,

        /*
         * Read a byte-aligned, 32-bit big-endian fixed-length
         * floating-point number field.
         */
        READ_FIXED_LEN_FLOAT_FIELD_BA_32_BE,

        /*
         * Read a byte-aligned, 32-bit little-endian fixed-length
         * floating-point number field.
         */
        READ_FIXED_LEN_FLOAT_FIELD_BA_32_LE,

        /*
         * Read a byte-aligned, 64-bit big-endian fixed-length
         * floating-point number field.
         */
        READ_FIXED_LEN_FLOAT_FIELD_BA_64_BE,

        /*
         * Read a byte-aligned, 64-bit little-endian fixed-length
         * floating-point number field.
         */
        READ_FIXED_LEN_FLOAT_FIELD_BA_64_LE,

        /*
         * Read a byte-aligned, 16-bit big-endian fixed-length signed
         * enumeration field.
         */
        READ_FIXED_LEN_SENUM_FIELD_BA_16_BE,

        /*
         * Read a byte-aligned, 16-bit big-endian fixed-length signed
         * enumeration field and save its value.
         */
        READ_FIXED_LEN_SENUM_FIELD_BA_16_BE_SAVE_VAL,

        /*
         * Read a byte-aligned, 16-bit little-endian fixed-length signed
         * enumeration field.
         */
        READ_FIXED_LEN_SENUM_FIELD_BA_16_LE,

        /*
         * Read a byte-aligned, 16-bit little-endian fixed-length signed
         * enumeration field and save its value.
         */
        READ_FIXED_LEN_SENUM_FIELD_BA_16_LE_SAVE_VAL,

        /*
         * Read a byte-aligned, 32-bit big-endian fixed-length signed
         * enumeration field.
         */
        READ_FIXED_LEN_SENUM_FIELD_BA_32_BE,

        /*
         * Read a byte-aligned, 32-bit big-endian fixed-length signed
         * enumeration field and save its value.
         */
        READ_FIXED_LEN_SENUM_FIELD_BA_32_BE_SAVE_VAL,

        /*
         * Read a byte-aligned, 32-bit little-endian fixed-length signed
         * enumeration field.
         */
        READ_FIXED_LEN_SENUM_FIELD_BA_32_LE,

        /*
         * Read a byte-aligned, 32-bit little-endian fixed-length signed
         * enumeration field and save its value.
         */
        READ_FIXED_LEN_SENUM_FIELD_BA_32_LE_SAVE_VAL,

        /*
         * Read a byte-aligned, 64-bit big-endian fixed-length signed
         * enumeration field.
         */
        READ_FIXED_LEN_SENUM_FIELD_BA_64_BE,

        /*
         * Read a byte-aligned, 64-bit big-endian fixed-length signed
         * enumeration field and save its value.
         */
        READ_FIXED_LEN_SENUM_FIELD_BA_64_BE_SAVE_VAL,

        /*
         * Read a byte-aligned, 64-bit little-endian fixed-length signed
         * enumeration field.
         */
        READ_FIXED_LEN_SENUM_FIELD_BA_64_LE,

        /*
         * Read a byte-aligned, 64-bit little-endian fixed-length signed
         * enumeration field and save its value.
         */
        READ_FIXED_LEN_SENUM_FIELD_BA_64_LE_SAVE_VAL,

        /*
         * Read a byte-aligned, 8-bit little-endian fixed-length signed
         * enumeration field.
         */
        READ_FIXED_LEN_SENUM_FIELD_BA_8,

        /*
         * Read a byte-aligned, 8-bit little-endian fixed-length signed
         * enumeration field and save its value.
         */
        READ_FIXED_LEN_SENUM_FIELD_BA_8_SAVE_VAL,

        /*
         * Read a big-endian fixed-length signed enumeration field.
         */
        READ_FIXED_LEN_SENUM_FIELD_BE,

        /*
         * Read a big-endian fixed-length signed enumeration field and
         * save its value.
         */
        READ_FIXED_LEN_SENUM_FIELD_BE_SAVE_VAL,

        /*
         * Read a little-endian fixed-length signed enumeration field.
         */
        READ_FIXED_LEN_SENUM_FIELD_LE,

        /*
         * Read a little-endian fixed-length signed enumeration field
         * and save its value.
         */
        READ_FIXED_LEN_SENUM_FIELD_LE_SAVE_VAL,

        /*
         * Read a byte-aligned, 16-bit big-endian fixed-length signed
         * integer field.
         */
        READ_FIXED_LEN_SINT_FIELD_BA_16_BE,

        /*
         * Read a byte-aligned, 16-bit big-endian fixed-length signed
         * integer field and save its value.
         */
        READ_FIXED_LEN_SINT_FIELD_BA_16_BE_SAVE_VAL,

        /*
         * Read a byte-aligned, 16-bit little-endian fixed-length signed
         * integer field.
         */
        READ_FIXED_LEN_SINT_FIELD_BA_16_LE,

        /*
         * Read a byte-aligned, 16-bit little-endian fixed-length signed
         * integer field and save its value.
         */
        READ_FIXED_LEN_SINT_FIELD_BA_16_LE_SAVE_VAL,

        /*
         * Read a byte-aligned, 32-bit big-endian fixed-length signed
         * integer field.
         */
        READ_FIXED_LEN_SINT_FIELD_BA_32_BE,

        /*
         * Read a byte-aligned, 32-bit big-endian fixed-length signed
         * integer field and save its value.
         */
        READ_FIXED_LEN_SINT_FIELD_BA_32_BE_SAVE_VAL,

        /*
         * Read a byte-aligned, 32-bit little-endian fixed-length signed
         * integer field.
         */
        READ_FIXED_LEN_SINT_FIELD_BA_32_LE,

        /*
         * Read a byte-aligned, 32-bit little-endian fixed-length signed
         * integer field and save its value.
         */
        READ_FIXED_LEN_SINT_FIELD_BA_32_LE_SAVE_VAL,

        /*
         * Read a byte-aligned, 64-bit big-endian fixed-length signed
         * integer field.
         */
        READ_FIXED_LEN_SINT_FIELD_BA_64_BE,

        /*
         * Read a byte-aligned, 64-bit big-endian fixed-length signed
         * integer field and save its value.
         */
        READ_FIXED_LEN_SINT_FIELD_BA_64_BE_SAVE_VAL,

        /*
         * Read a byte-aligned, 64-bit little-endian fixed-length signed
         * integer field.
         */
        READ_FIXED_LEN_SINT_FIELD_BA_64_LE,

        /*
         * Read a byte-aligned, 64-bit little-endian fixed-length signed
         * integer field and save its value.
         */
        READ_FIXED_LEN_SINT_FIELD_BA_64_LE_SAVE_VAL,

        /*
         * Read a byte-aligned, 8-bit little-endian fixed-length signed
         * integer field.
         */
        READ_FIXED_LEN_SINT_FIELD_BA_8,

        /*
         * Read a byte-aligned, 8-bit little-endian fixed-length signed
         * integer field and save its value.
         */
        READ_FIXED_LEN_SINT_FIELD_BA_8_SAVE_VAL,

        /*
         * Read a big-endian fixed-length signed integer field.
         */
        READ_FIXED_LEN_SINT_FIELD_BE,

        /*
         * Read a big-endian fixed-length signed integer field and save
         * its value.
         */
        READ_FIXED_LEN_SINT_FIELD_BE_SAVE_VAL,

        /*
         * Read a little-endian fixed-length signed integer field.
         */
        READ_FIXED_LEN_SINT_FIELD_LE,

        /*
         * Read a little-endian fixed-length signed integer field and
         * save its value.
         */
        READ_FIXED_LEN_SINT_FIELD_LE_SAVE_VAL,

        /*
         * Read a byte-aligned, 8-bit little-endian fixed-length
         * unsigned enumeration field.
         */
        READ_FIXED_LEN_METADATA_STREAM_UUID_BYTE_UENUM_FIELD_BA_8,

        /*
         * Read a byte-aligned, 8-bit little-endian fixed-length
         * unsigned integer field.
         */
        READ_FIXED_LEN_METADATA_STREAM_UUID_BYTE_UINT_FIELD_BA_8,

        /*
         * Read a byte-aligned, 16-bit big-endian fixed-length unsigned
         * enumeration field.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_16_BE,

        /*
         * Read a byte-aligned, 16-bit big-endian fixed-length unsigned
         * enumeration field and save its value.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_16_BE_SAVE_VAL,

        /*
         * Read a byte-aligned, 16-bit big-endian fixed-length unsigned
         * enumeration field having at least one role.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_16_BE_WITH_ROLE,

        /*
         * Read a byte-aligned, 16-bit big-endian fixed-length unsigned
         * enumeration field having at least one role and save its
         * value.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_16_BE_WITH_ROLE_SAVE_VAL,

        /*
         * Read a byte-aligned, 16-bit little-endian fixed-length
         * unsigned enumeration field.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_16_LE,

        /*
         * Read a byte-aligned, 16-bit little-endian fixed-length
         * unsigned enumeration field and save its value.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_16_LE_SAVE_VAL,

        /*
         * Read a byte-aligned, 16-bit little-endian fixed-length
         * unsigned enumeration field having at least one role.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_16_LE_WITH_ROLE,

        /*
         * Read a byte-aligned, 16-bit little-endian fixed-length
         * unsigned enumeration field having at least one role and save
         * its value.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_16_LE_WITH_ROLE_SAVE_VAL,

        /*
         * Read a byte-aligned, 32-bit big-endian fixed-length unsigned
         * enumeration field.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_32_BE,

        /*
         * Read a byte-aligned, 32-bit big-endian fixed-length unsigned
         * enumeration field and save its value.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_32_BE_SAVE_VAL,

        /*
         * Read a byte-aligned, 32-bit big-endian fixed-length unsigned
         * enumeration field having at least one role.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_32_BE_WITH_ROLE,

        /*
         * Read a byte-aligned, 32-bit big-endian fixed-length unsigned
         * enumeration field having at least one role and save its
         * value.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_32_BE_WITH_ROLE_SAVE_VAL,

        /*
         * Read a byte-aligned, 32-bit little-endian fixed-length
         * unsigned enumeration field.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_32_LE,

        /*
         * Read a byte-aligned, 32-bit little-endian fixed-length
         * unsigned enumeration field and save its value.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_32_LE_SAVE_VAL,

        /*
         * Read a byte-aligned, 32-bit little-endian fixed-length
         * unsigned enumeration field having at least one role.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_32_LE_WITH_ROLE,

        /*
         * Read a byte-aligned, 32-bit little-endian fixed-length
         * unsigned enumeration field having at least one role and save
         * its value.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_32_LE_WITH_ROLE_SAVE_VAL,

        /*
         * Read a byte-aligned, 64-bit big-endian fixed-length unsigned
         * enumeration field.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_64_BE,

        /*
         * Read a byte-aligned, 64-bit big-endian fixed-length unsigned
         * enumeration field and save its value.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_64_BE_SAVE_VAL,

        /*
         * Read a byte-aligned, 64-bit big-endian fixed-length unsigned
         * enumeration field having at least one role.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_64_BE_WITH_ROLE,

        /*
         * Read a byte-aligned, 64-bit big-endian fixed-length unsigned
         * enumeration field having at least one role and save its
         * value.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_64_BE_WITH_ROLE_SAVE_VAL,

        /*
         * Read a byte-aligned, 64-bit little-endian fixed-length
         * unsigned enumeration field.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_64_LE,

        /*
         * Read a byte-aligned, 64-bit little-endian fixed-length
         * unsigned enumeration field and save its value.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_64_LE_SAVE_VAL,

        /*
         * Read a byte-aligned, 64-bit little-endian fixed-length
         * unsigned enumeration field having at least one role.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_64_LE_WITH_ROLE,

        /*
         * Read a byte-aligned, 64-bit little-endian fixed-length
         * unsigned enumeration field having at least one role and save
         * its value.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_64_LE_WITH_ROLE_SAVE_VAL,

        /*
         * Read a byte-aligned, 8-bit little-endian fixed-length
         * unsigned enumeration field.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_8,

        /*
         * Read a byte-aligned, 8-bit little-endian fixed-length
         * unsigned enumeration field and save its value.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_8_SAVE_VAL,

        /*
         * Read a byte-aligned, 8-bit little-endian fixed-length
         * unsigned enumeration field having at least one role.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_8_WITH_ROLE,

        /*
         * Read a byte-aligned, 8-bit little-endian fixed-length
         * unsigned enumeration field having at least one role and save
         * its value.
         */
        READ_FIXED_LEN_UENUM_FIELD_BA_8_WITH_ROLE_SAVE_VAL,

        /*
         * Read a big-endian fixed-length unsigned enumeration field.
         */
        READ_FIXED_LEN_UENUM_FIELD_BE,

        /*
         * Read a big-endian fixed-length unsigned enumeration field and
         * save its value.
         */
        READ_FIXED_LEN_UENUM_FIELD_BE_SAVE_VAL,

        /*
         * Read a big-endian fixed-length unsigned enumeration field
         * having at least one role.
         */
        READ_FIXED_LEN_UENUM_FIELD_BE_WITH_ROLE,

        /*
         * Read a big-endian fixed-length unsigned enumeration field
         * having at least one role and save its value.
         */
        READ_FIXED_LEN_UENUM_FIELD_BE_WITH_ROLE_SAVE_VAL,

        /*
         * Read a little-endian fixed-length unsigned enumeration field.
         */
        READ_FIXED_LEN_UENUM_FIELD_LE,

        /*
         * Read a little-endian fixed-length unsigned enumeration field
         * and save its value.
         */
        READ_FIXED_LEN_UENUM_FIELD_LE_SAVE_VAL,

        /*
         * Read a little-endian fixed-length unsigned enumeration field
         * having at least one role.
         */
        READ_FIXED_LEN_UENUM_FIELD_LE_WITH_ROLE,

        /*
         * Read a little-endian fixed-length unsigned enumeration field
         * having at least one role and save its value.
         */
        READ_FIXED_LEN_UENUM_FIELD_LE_WITH_ROLE_SAVE_VAL,

        /*
         * Read a byte-aligned, 16-bit big-endian fixed-length unsigned
         * integer field.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_16_BE,

        /*
         * Read a byte-aligned, 16-bit big-endian fixed-length unsigned
         * integer field and save its value.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_16_BE_SAVE_VAL,

        /*
         * Read a byte-aligned, 16-bit big-endian fixed-length unsigned
         * integer field having at least one role.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_16_BE_WITH_ROLE,

        /*
         * Read a byte-aligned, 16-bit big-endian fixed-length unsigned
         * integer field having at least one role and save its value.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_16_BE_WITH_ROLE_SAVE_VAL,

        /*
         * Read a byte-aligned, 16-bit little-endian fixed-length
         * unsigned integer field.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_16_LE,

        /*
         * Read a byte-aligned, 16-bit little-endian fixed-length
         * unsigned integer field and save its value.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_16_LE_SAVE_VAL,

        /*
         * Read a byte-aligned, 16-bit little-endian fixed-length
         * unsigned integer field having at least one role.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_16_LE_WITH_ROLE,

        /*
         * Read a byte-aligned, 16-bit little-endian fixed-length
         * unsigned integer field having at least one role and save its
         * value.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_16_LE_WITH_ROLE_SAVE_VAL,

        /*
         * Read a byte-aligned, 32-bit big-endian fixed-length unsigned
         * integer field.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_32_BE,

        /*
         * Read a byte-aligned, 32-bit big-endian fixed-length unsigned
         * integer field and save its value.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_32_BE_SAVE_VAL,

        /*
         * Read a byte-aligned, 32-bit big-endian fixed-length unsigned
         * integer field having at least one role.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_32_BE_WITH_ROLE,

        /*
         * Read a byte-aligned, 32-bit big-endian fixed-length unsigned
         * integer field having at least one role and save its value.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_32_BE_WITH_ROLE_SAVE_VAL,

        /*
         * Read a byte-aligned, 32-bit little-endian fixed-length
         * unsigned integer field.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_32_LE,

        /*
         * Read a byte-aligned, 32-bit little-endian fixed-length
         * unsigned integer field and save its value.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_32_LE_SAVE_VAL,

        /*
         * Read a byte-aligned, 32-bit little-endian fixed-length
         * unsigned integer field having at least one role.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_32_LE_WITH_ROLE,

        /*
         * Read a byte-aligned, 32-bit little-endian fixed-length
         * unsigned integer field having at least one role and save its
         * value.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_32_LE_WITH_ROLE_SAVE_VAL,

        /*
         * Read a byte-aligned, 64-bit big-endian fixed-length unsigned
         * integer field.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_64_BE,

        /*
         * Read a byte-aligned, 64-bit big-endian fixed-length unsigned
         * integer field and save its value.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_64_BE_SAVE_VAL,

        /*
         * Read a byte-aligned, 64-bit big-endian fixed-length unsigned
         * integer field having at least one role.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_64_BE_WITH_ROLE,

        /*
         * Read a byte-aligned, 64-bit big-endian fixed-length unsigned
         * integer field having at least one role and save its value.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_64_BE_WITH_ROLE_SAVE_VAL,

        /*
         * Read a byte-aligned, 64-bit little-endian fixed-length
         * unsigned integer field.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_64_LE,

        /*
         * Read a byte-aligned, 64-bit little-endian fixed-length
         * unsigned integer field and save its value.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_64_LE_SAVE_VAL,

        /*
         * Read a byte-aligned, 64-bit little-endian fixed-length
         * unsigned integer field having at least one role.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_64_LE_WITH_ROLE,

        /*
         * Read a byte-aligned, 64-bit little-endian fixed-length
         * unsigned integer field having at least one role and save its
         * value.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_64_LE_WITH_ROLE_SAVE_VAL,

        /*
         * Read a byte-aligned, 8-bit little-endian fixed-length
         * unsigned integer field.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_8,

        /*
         * Read a byte-aligned, 8-bit little-endian fixed-length
         * unsigned integer field and save its value.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_8_SAVE_VAL,

        /*
         * Read a byte-aligned, 8-bit little-endian fixed-length
         * unsigned integer field having at least one role.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_8_WITH_ROLE,

        /*
         * Read a byte-aligned, 8-bit little-endian fixed-length
         * unsigned integer field having at least one role and save its
         * value.
         */
        READ_FIXED_LEN_UINT_FIELD_BA_8_WITH_ROLE_SAVE_VAL,

        /*
         * Read a big-endian fixed-length unsigned integer field.
         */
        READ_FIXED_LEN_UINT_FIELD_BE,

        /*
         * Read a big-endian fixed-length unsigned integer field and
         * save its value.
         */
        READ_FIXED_LEN_UINT_FIELD_BE_SAVE_VAL,

        /*
         * Read a big-endian fixed-length unsigned integer field having
         * at least one role.
         */
        READ_FIXED_LEN_UINT_FIELD_BE_WITH_ROLE,

        /*
         * Read a big-endian fixed-length unsigned integer field having
         * at least one role and save its value.
         */
        READ_FIXED_LEN_UINT_FIELD_BE_WITH_ROLE_SAVE_VAL,

        /*
         * Read a little-endian fixed-length unsigned integer field.
         */
        READ_FIXED_LEN_UINT_FIELD_LE,

        /*
         * Read a little-endian fixed-length unsigned integer field and
         * save its value.
         */
        READ_FIXED_LEN_UINT_FIELD_LE_SAVE_VAL,

        /*
         * Read a little-endian fixed-length unsigned integer field
         * having at least one role.
         */
        READ_FIXED_LEN_UINT_FIELD_LE_WITH_ROLE,

        /*
         * Read a little-endian fixed-length unsigned integer field
         * having at least one role and save its value.
         */
        READ_FIXED_LEN_UINT_FIELD_LE_WITH_ROLE_SAVE_VAL,

        /* Read a substring */
        READ_SUBSTR,

        /* Read a null-terminated substring */
        READ_SUBSTR_UNTIL_NULL_CHAR,

        /* Read a metadata stream UUID BLOB field section */
        READ_METADATA_STREAM_UUID_BLOB_FIELD_SECTION,

        /* Read a UUID BLOB section */
        READ_UUID_BLOB_SECTION,

        /* Read a UUID byte */
        READ_UUID_BYTE,

        /* Read a variable-length signed enumeration field */
        READ_VAR_LEN_SENUM_FIELD,

        /*
         * Read a variable-length signed enumeration field and save
         * its value.
         */
        READ_VAR_LEN_SENUM_FIELD_SAVE_VAL,

        /* Read a variable-length signed integer field */
        READ_VAR_LEN_SINT_FIELD,

        /* Read a variable-length signed integer field and save its value */
        READ_VAR_LEN_SINT_FIELD_SAVE_VAL,

        /* Read a variable-length unsigned enumeration field */
        READ_VAR_LEN_UENUM_FIELD,

        /*
         * Read a variable-length unsigned enumeration field and save
         * its value.
         */
        READ_VAR_LEN_UENUM_FIELD_SAVE_VAL,

        /*
         * Read a variable-length unsigned enumeration field having at least
         * one role.
         */
        READ_VAR_LEN_UENUM_FIELD_WITH_ROLE,

        /*
         * Read a variable-length unsigned enumeration field having at
         * least one role and save its value.
         */
        READ_VAR_LEN_UENUM_FIELD_WITH_ROLE_SAVE_VAL,

        /* Read a variable-length unsigned enumeration field */
        READ_VAR_LEN_UINT_FIELD,

        /*
         * Read a variable-length unsigned integer field and save its
         * value.
         */
        READ_VAR_LEN_UINT_FIELD_SAVE_VAL,

        /*
         * Read a variable-length unsigned integer field having at least
         * one role.
         */
        READ_VAR_LEN_UINT_FIELD_WITH_ROLE,

        /*
         * Read a variable-length unsigned integer field having at least
         * one role and save its value.
         */
        READ_VAR_LEN_UINT_FIELD_WITH_ROLE_SAVE_VAL,

        /* Set the data stream info item */
        SET_DATA_STREAM_INFO_ITEM,

        /* Set the event record info item */
        SET_EVENT_RECORD_INFO_ITEM,

        /* Set the packet info item */
        SET_PKT_INFO_ITEM,

        /* Set the packet magic number item */
        SET_PKT_MAGIC_NUMBER_ITEM,

        /* Set the default clock value item */
        SET_DEF_CLK_VAL_ITEM,

        /* Set the metadata stream UUID item */
        SET_METADATA_STREAM_UUID_ITEM,

        /* Skip some packet content padding */
        SKIP_CONTENT_PADDING,

        /* Skip some padding after the packet content */
        SKIP_PADDING,

        /* Try beginning reading an event record */
        TRY_BEGIN_READ_EVENT_RECORD,

        /* Try beginning reading a common event record context scope */
        TRY_BEGIN_READ_EVENT_RECORD_COMMON_CTX_SCOPE,

        /* Try beginning reading an event record header scope */
        TRY_BEGIN_READ_EVENT_RECORD_HEADER_SCOPE,

        /* Try beginning reading an event record payload scope */
        TRY_BEGIN_READ_EVENT_RECORD_PAYLOAD_SCOPE,

        /* Try beginning reading a specific event record context scope */
        TRY_BEGIN_READ_EVENT_RECORD_SPEC_CTX_SCOPE,

        /* Try beginning reading a packet */
        TRY_BEGIN_READ_PKT,

        /* Try beginning reading a packet context scope */
        TRY_BEGIN_READ_PKT_CTX_SCOPE,

        /* Try beginning reading a packet header scope */
        TRY_BEGIN_READ_PKT_HEADER_SCOPE,
    };

    /*
     * Reaction of a state handling method.
     */
    enum class _StateHandlingReaction
    {
        /* Continue executing the state machine */
        CONTINUE,

        /*
         * Stop the state machine, returning control to the user.
         *
         * This reaction means one of:
         *
         * • There's a current item (the user may use operator*()).
         * • The iterator is ended (isEnded() returns `true`).
         */
        STOP,
    };

    /*
     * Single frame of the stack.
     *
     * A stack frame holds:
     *
     * • The previous state (to be restored).
     * • A base field class (optional).
     * • A current length, if applicable.
     * • A number of remaining elements, if applicable.
     *
     * The iterator needs such a stack because fields may contain other
     * fields. The meaning of the current length and number of remaining
     * elements depend on the base field class.
     */
    struct _StackFrame final
    {
        explicit _StackFrame(_State restoringState) noexcept;
        explicit _StackFrame(_State restoringState, const Fc& fc) noexcept;

        /* State to restore when removing this frame */
        _State restoringState;

        /* Class of containing field */
        const Fc *fc = nullptr;

        /*
         * Index of current "element" to decode.
         *
         * The meaning of this field depends on the type of `fc`:
         *
         * `Fc::Type::STRUCT`:
         *     Member index.
         *
         * `Fc::Type::STATIC_LEN_ARRAY`:
         * `Fc::Type::DYN_LEN_ARRAY`:
         *     Element index.
         *
         * `Fc::Type::OPTIONAL_WITH_BOOL_SEL`:
         * `Fc::Type::OPTIONAL_WITH_UINT_SEL`:
         * `Fc::Type::OPTIONAL_WITH_SINT_SEL`:
         * `Fc::Type::VARIANT_WITH_UINT_SEL`:
         * `Fc::Type::VARIANT_WITH_SINT_SEL`:
         *     1 means we're done.
         *
         * `FcType::NULL_TERMINATED_STR`:
         * `FcType::STATIC_LEN_BLOB`:
         * `FcType::DYN_LEN_BLOB`:
         *     Byte index.
         *
         * Other:
         *     Meaningless.
         */
        std::size_t elemIndex = 0;

        /*
         * Length of containing field.
         *
         * The meaning of this field depends on the type of `fc`:
         *
         * `Fc::Type::STRUCT`:
         *     Member count.
         *
         * `Fc::Type::STATIC_LEN_ARRAY`:
         * `Fc::Type::DYN_LEN_ARRAY`:
         *     Element count.
         *
         * `FcType::NULL_TERMINATED_STR`:
         * `FcType::STATIC_LEN_BLOB`:
         * `FcType::DYN_LEN_BLOB`:
         *     Byte count.
         *
         * `Fc::Type::OPTIONAL_WITH_BOOL_SEL`:
         * `Fc::Type::OPTIONAL_WITH_UINT_SEL`:
         * `Fc::Type::OPTIONAL_WITH_SINT_SEL`:
         * `Fc::Type::VARIANT_WITH_UINT_SEL`:
         * `Fc::Type::VARIANT_WITH_SINT_SEL`:
         *     Always 1.
         *
         * Other:
         *     Meaningless.
         */
        std::size_t len = 0;
    };

    /*
     * Updates the current default clock value (`_mDefClkVal`) from the
     * value `val` having the length `len`.
     */
    void _updateDefClkVal(const unsigned long long val, bt2_common::DataLen len) noexcept;

    /*
     * Resets some members of this iterator to prepare to decode a new
     * packet.
     */
    void _resetForNewPkt();

    /*
     * Requests a new buffer from the medium, setting the corresponding
     * members accordingly on success.
     */
    void _newBuf(bt2_common::DataLen offsetInItemSeq, bt2_common::DataLen minSize);

    /*
     * Length of remaining content in the current packet.
     *
     * If `_mCurPktExpectedLens.content` is `this->_infDataLen()`,
     * then this method never returns zero (in practice).
     */
    bt2_common::DataLen _remainingPktContentLen() const noexcept
    {
        return _mCurPktExpectedLens.content - _mHeadOffsetInCurPkt;
    }

    /*
     * Offset of the decoding head within the whole item sequence.
     */
    bt2_common::DataLen _headOffsetInItemSeq() const noexcept
    {
        return _mCurPktOffsetInItemSeq + _mHeadOffsetInCurPkt;
    }

    /*
     * Pushes a frame onto the stack, without a field class, so that
     * _restoreState() restores `restoringState`.
     */
    void _stackPush(const _State restoringState)
    {
        _mStack.push_back(_StackFrame {restoringState});
    }

    /*
     * Pushes a frame onto the stack, without a field class, so that
     * _restoreState() restores the current state.
     */
    void _stackPush()
    {
        this->_stackPush(_mState);
    }

    /*
     * Pushes a frame onto the stack, `fc` being the class of some
     * containing field, so that _restoreState() restores
     * `restoringState`.
     */
    void _stackPush(const _State restoringState, const Fc& fc)
    {
        _mStack.push_back(_StackFrame {restoringState, fc});
    }

    /*
     * Pushes a frame onto the stack, `fc` being the class of some
     * containing field, so that _restoreState() restores the current
     * state.
     */
    void _stackPush(const Fc& fc)
    {
        this->_stackPush(_mState, fc);
    }

    /*
     * Pops a frame from the stack without changing the current state
     * (use _restoreState() before calling this method to do so).
     */
    void _stackPop()
    {
        BT_ASSERT_DBG(!_mStack.empty());
        _mStack.pop_back();
    }

    /*
     * Top frame of the stack.
     */
    _StackFrame& _stackTop() noexcept
    {
        BT_ASSERT_DBG(!_mStack.empty());
        return _mStack.back();
    }

    /*
     * Restores the current state from the top frame of the stack.
     */
    void _restoreState() noexcept
    {
        this->_state(this->_stackTop().restoringState);
    }

    /*
     * Saves the value `val` to the saved value vector at the indexes
     * `indexes`.
     */
    template <typename ValT>
    void _saveVal(const ValSavingIndexes& indexes, const ValT val) noexcept
    {
        for (const auto index : indexes) {
            BT_ASSERT_DBG(index < _mSavedVals.size());
            _mSavedVals[index] = static_cast<unsigned long long>(val);
        }
    }

    /*
     * Returns the saved value of type `ValT` from the saved value
     * vector at index `index`.
     */
    template <typename ValT>
    ValT _savedVal(const std::size_t index) const noexcept
    {
        BT_ASSERT_DBG(index < _mSavedVals.size());
        return static_cast<ValT>(_mSavedVals[index]);
    }

    /*
     * Returns the saved unsigned integer value from the saved value
     * vector at index `fc.savedDepValIndex()`.
     */
    template <typename FcT>
    unsigned long long _savedUIntVal(const FcT& fc) const noexcept
    {
        BT_ASSERT_DBG(fc.savedDepValIndex());
        return this->_savedVal<unsigned long long>(*fc.savedDepValIndex());
    }

    /*
     * Updates the user-visible members: current item and offset
     * relative to the item sequence beginning.
     */
    void _updateForUser(const Item& item, const bt2_common::DataLen offset) noexcept
    {
        _mCurItem = &item;
        _mCurItemOffsetInItemSeq = offset;
    }

    /*
     * Like the other _updateForUser(), but using _headOffsetInItemSeq()
     * for the offset.
     */
    void _updateForUser(const Item& item) noexcept
    {
        this->_updateForUser(item, this->_headOffsetInItemSeq());
    }

    /*
     * Throws a decoding error having the message `msg` and the offset
     * returned by _headOffsetInItemSeq().
     */
    [[noreturn]] void _throwDecodingError(std::string msg) const
    {
        throw DecodingError {std::move(msg), this->_headOffsetInItemSeq()};
    }

    /*
     * Throws a decoding error having the message `ss.str()` and the
     * offset returned by _headOffsetInItemSeq().
     */
    [[noreturn]] void _throwDecodingError(const std::ostringstream& ss) const
    {
        this->_throwDecodingError(ss.str());
    }

    /*
     * Aligns the decoding head to `align` bits.
     *
     * This method may throw whatever _tryHaveData() may throw.
     */
    void _alignHead(const unsigned long long align)
    {
        /*
         * Compute new decoding head offset and how many bits we need to
         * skip to align.
         */
        const auto newHeadOffsetBits =
            bt2_common::DataLen::fromBits(bt2_common::align(*_mHeadOffsetInCurPkt, align));
        const auto lenToSkip = newHeadOffsetBits - _mHeadOffsetInCurPkt;

        /* Already aligned? */
        if (lenToSkip == bt2_common::DataLen::fromBits(0)) {
            /* Yes */
            return;
        }

        /*
         * Validate that we're not skipping more than the packet content
         * that's left.
         */
        if (lenToSkip > this->_remainingPktContentLen()) {
            std::ostringstream ss;

            ss << *lenToSkip << " bits of packet content required at this point, but only "
               << *this->_remainingPktContentLen() << " bits of packet content remain.";
            this->_throwDecodingError(ss);
        }

        /*
         * Set the state so as to skip content padding, but also try to
         * skip all of it immediately.
         */
        _mRemainingLenToSkip = lenToSkip;
        _mPostSkipPaddingState = _mState;
        this->_state(_State::SKIP_CONTENT_PADDING);
        this->_skipPadding<true>();
    }

    /*
     * Aligns the decoding head to `fc.align()` bits.
     *
     * This method may throw whatever _tryHaveData() may throw.
     */
    void _alignHead(const Fc& fc)
    {
        this->_alignHead(fc.align());
    }

    /*
     * Skips `_mRemainingLenToSkip` bits of padding data.
     *
     * `IsContentDataV` indicates whether or not the padding data to
     * skip is packet content data (as opposed to padding data _after_
     * the packet content).
     *
     * This method may throw whatever _tryHaveData() may throw.
     */
    template <bool IsContentDataV>
    void _skipPadding()
    {
        using namespace bt2_common::literals::datalen;

        /* Require at least one bit of data */
        if (IsContentDataV) {
            this->_requireContentData(1_bits);
        } else {
            this->_requireData(1_bits);
        }

        /*
         * How many bits to skip is the minimum between what's left
         * in the buffer and what remains to skip.
         */
        const auto lenToSkip = std::min(_mRemainingLenToSkip, this->_remainingBufLen());

        /* Skip, marking the padding bits as consumed */
        _mRemainingLenToSkip -= lenToSkip;
        this->_consumeAvailData(lenToSkip);

        /* Done? */
        if (_mRemainingLenToSkip == 0_bits) {
            /* Yes! */
            this->_state(_mPostSkipPaddingState);
        }
    }

    /*
     * Tries to have `len` bits (maximum: 64 bits) of data, returning
     * false if not possible.
     *
     * This method may still throw `bt2_common::TryAgain`, but it won't
     * throw `NoData`.
     */
    bool _tryHaveData(const bt2_common::DataLen len)
    {
        BT_ASSERT_DBG(len <= bt2_common::DataLen::fromBits(64));

        if (len <= this->_remainingBufLen()) {
            /* We already have enough */
            return true;
        }

        /*
         * In the initializations below:
         *
         * • `_mHeadOffsetInCurPkt.bytes()` is a flooring operation.
         *
         * • Adding seven bits to `len` and the extra bit count of
         *   `_mHeadOffsetInCurPkt`, and then using DataLen::fromBytes()
         *   is a way to perform a ceiling operation.
         *
         *   For example, if `*_mHeadOffsetInCurPkt` is 1963 and `*len`
         *   is 75, then `*reqSize` is 80 (10 bytes), that is,
         *   mathematically (result in bytes):
         *
         *       floor((75 + 7 + (1963 % 8)) / 8)
         */
        const auto reqOffsetInElemSeq = bt2_common::DataLen::fromBytes(
            _mCurPktOffsetInItemSeq.bytes() + _mHeadOffsetInCurPkt.bytes());
        const auto reqSize = bt2_common::DataLen::fromBytes(
            bt2_common::DataLen::fromBits(*len + 7 + _mHeadOffsetInCurPkt.extraBitCount()).bytes());

        try {
            this->_newBuf(reqOffsetInElemSeq, reqSize);
        } catch (const NoData&) {
            return false;
        }

        return true;
    }

    /*
     * Requires `len` bits of data, throwing if not possible.
     */
    void _requireData(const bt2_common::DataLen len)
    {
        if (!this->_tryHaveData(len)) {
            std::ostringstream ss;

            ss << *len << " bits of data required at this point.";
            this->_throwDecodingError(ss);
        }
    }

    /*
     * Requires `len` bits of content data, throwing if not possible.
     */
    void _requireContentData(const bt2_common::DataLen len)
    {
        if (len > this->_remainingPktContentLen()) {
            /* Going past the packet content */
            std::ostringstream ss;

            ss << *len << " bits of packet content required at this point, but only "
               << *this->_remainingPktContentLen() << " bits of packet content remain.";
            this->_throwDecodingError(ss);
        }

        this->_requireData(len);
    }

    /*
     * Buffer at the decoding head position.
     *
     * This returns a pointer to the "byte we're in", so that the return
     * value is always the same for a given value of
     * `_mHeadOffsetInCurPkt.bytes()`, that is, whatever the value of
     * `_mHeadOffsetInCurPkt.extraBitCount()`.
     */
    const std::uint8_t *_bufAtHead() const noexcept
    {
        return _mBuf.addr() + (_mHeadOffsetInCurPkt - _mBufOffsetInCurPkt).bytes();
    }

    /*
     * Length of remaining data in the current buffer.
     */
    bt2_common::DataLen _remainingBufLen() const noexcept
    {
        return (_mBufOffsetInCurPkt + _mBuf.size()) - _mHeadOffsetInCurPkt;
    }

    /*
     * Marks `len` bits as consumed.
     */
    void _consumeAvailData(const bt2_common::DataLen len) noexcept
    {
        BT_ASSERT_DBG(len <= this->_remainingBufLen());
        _mHeadOffsetInCurPkt += len;
    }

    /*
     * Sets the field class pointer member of the item `item` to `fc`.
     */
    template <typename ItemT>
    static void _setFieldItemFc(ItemT& item, const Fc& fc) noexcept
    {
        item._mCls = &fc;
    }

    /*
     * Calls _setFieldItemFc() and then _updateForUser().
     *
     * Almost all "read field" state handlers eventually call this.
     */
    template <typename ItemT>
    void _setFieldItemFcAndUpdateForUser(ItemT& item, const Fc& fc) noexcept
    {
        this->_setFieldItemFc(item, fc);
        this->_updateForUser(item);
    }

    /*
     * Sets the state to `tryBeginReadState`.
     *
     * If `fc` is `nullptr`, this method returns immediately.
     *
     * Otherwise, this method prepares to read the scope `scope` of
     * which the structure field class is `fc`, setting the state to
     * restore afterwards to `endReadState`.
     */
    void _prepareToTryReadScope(const _State tryBeginReadState, const _State endReadState,
                                const ir::FieldLocScope scope, const StructFc * const fc)
    {
        /* Next: try beginning to read scope */
        this->_state(tryBeginReadState);

        /*
         * Set scope and scope field class, even if it's `nullptr`,
         * because the handler of `tryBeginReadState` checks
         * `_mCurScope.fc`.
         */
        _mCurScope.scope = scope;
        _mCurScope.fc = fc;

        /*
         * If field class doesn't exist, then return immediately, not
         * pushing anything onto the stack.
         */
        if (!fc) {
            return;
        }

        /*
         * At this point we know we need to read a scope structure
         * field. Add a stack frame so that the restoring state is
         * `endReadState`.
         */
        this->_stackPush(endReadState);

        /*
         * Setting this to one will make _prepareToReadNextField() call
         * _restoreState(), effectively restoring the state
         * `endReadState` without ever needing `this->_stackTop().fc`.
         *
         * This makes it possible for _handleEndReadStructFieldState()
         * to simply call _prepareToReadNextField() unconditionally.
         */
        this->_stackTop().len = 1;
    }

    /*
     * Sets the state to `state` and updates the stack to read an
     * instance of the container field class `fc`, restoring the
     * state `restoringState` afterwards.
     */
    void _prepareToReadContainerField(const _State state, const _State restoringState, const Fc& fc)
    {
        this->_stackPush(restoringState, fc);
        this->_state(state);
    }

    /*
     * Sets the state and updates the stack to read an instance of the
     * structure field class `fc`.
     */
    void _prepareToReadStructField(const StructFc& fc)
    {
        this->_prepareToReadContainerField(_State::BEGIN_READ_STRUCT_FIELD,
                                           _State::END_READ_STRUCT_FIELD, fc);
    }

    /*
     * Sets the state to `state` and updates `_mCurScalarFc` to read an
     * instance of the scalar field class `fc`.
     */
    void _prepareToReadScalarField(const _State state, const Fc& fc) noexcept
    {
        _mCurScalarFc = &fc;
        this->_state(state);
    }

    /*
     * Sets the state, possibly updates the current scalar field class
     * (`_mCurScalarFc`), and possibly updates the stack to read an
     * instance of `fc`.
     */
    void _prepareToReadField(const Fc& fc)
    {
        switch (fc.deepType()) {
        case FcDeepType::FIXED_LEN_BIT_ARRAY_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BIT_ARRAY_FIELD_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_BIT_ARRAY_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BIT_ARRAY_FIELD_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_BIT_ARRAY_BA_8:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BIT_ARRAY_FIELD_BA_8, fc);
            break;
        case FcDeepType::FIXED_LEN_BIT_ARRAY_BA_16_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BIT_ARRAY_FIELD_BA_16_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_BIT_ARRAY_BA_16_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BIT_ARRAY_FIELD_BA_16_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_BIT_ARRAY_BA_32_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BIT_ARRAY_FIELD_BA_32_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_BIT_ARRAY_BA_32_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BIT_ARRAY_FIELD_BA_32_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_BIT_ARRAY_BA_64_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BIT_ARRAY_FIELD_BA_64_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_BIT_ARRAY_BA_64_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BIT_ARRAY_FIELD_BA_64_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_BOOL_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BOOL_FIELD_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_BOOL_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BOOL_FIELD_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_BOOL_BA_8:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BOOL_FIELD_BA_8, fc);
            break;
        case FcDeepType::FIXED_LEN_BOOL_BA_16_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BOOL_FIELD_BA_16_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_BOOL_BA_16_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BOOL_FIELD_BA_16_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_BOOL_BA_32_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BOOL_FIELD_BA_32_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_BOOL_BA_32_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BOOL_FIELD_BA_32_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_BOOL_BA_64_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BOOL_FIELD_BA_64_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_BOOL_BA_64_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BOOL_FIELD_BA_64_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_BOOL_BE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BOOL_FIELD_BE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_BOOL_LE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BOOL_FIELD_LE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_BOOL_BA_8_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BOOL_FIELD_BA_8_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_BOOL_BA_16_LE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BOOL_FIELD_BA_16_LE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_BOOL_BA_16_BE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BOOL_FIELD_BA_16_BE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_BOOL_BA_32_LE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BOOL_FIELD_BA_32_LE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_BOOL_BA_32_BE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BOOL_FIELD_BA_32_BE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_BOOL_BA_64_LE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BOOL_FIELD_BA_64_LE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_BOOL_BA_64_BE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_BOOL_FIELD_BA_64_BE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_FLOAT_32_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_FLOAT_FIELD_32_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_FLOAT_32_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_FLOAT_FIELD_32_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_FLOAT_64_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_FLOAT_FIELD_64_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_FLOAT_64_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_FLOAT_FIELD_64_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_FLOAT_BA_32_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_FLOAT_FIELD_BA_32_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_FLOAT_BA_32_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_FLOAT_FIELD_BA_32_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_FLOAT_BA_64_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_FLOAT_FIELD_BA_64_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_FLOAT_BA_64_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_FLOAT_FIELD_BA_64_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_8:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_BA_8, fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_16_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_BA_16_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_16_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_BA_16_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_32_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_BA_32_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_32_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_BA_32_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_64_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_BA_64_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_64_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_BA_64_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BE_WITH_ROLE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_BE_WITH_ROLE, fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_LE_WITH_ROLE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_LE_WITH_ROLE, fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_8_WITH_ROLE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_BA_8_WITH_ROLE, fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_16_LE_WITH_ROLE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_BA_16_LE_WITH_ROLE,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_16_BE_WITH_ROLE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_BA_16_BE_WITH_ROLE,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_32_LE_WITH_ROLE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_BA_32_LE_WITH_ROLE,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_32_BE_WITH_ROLE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_BA_32_BE_WITH_ROLE,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_64_LE_WITH_ROLE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_BA_64_LE_WITH_ROLE,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_64_BE_WITH_ROLE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_BA_64_BE_WITH_ROLE,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_BE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_LE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_LE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_8_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_BA_8_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_16_LE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_BA_16_LE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_16_BE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_BA_16_BE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_32_LE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_BA_32_LE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_32_BE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_BA_32_BE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_64_LE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_BA_64_LE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_64_BE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_BA_64_BE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BE_WITH_ROLE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_BE_WITH_ROLE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_LE_WITH_ROLE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UINT_FIELD_LE_WITH_ROLE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_8_WITH_ROLE_SAVE_VAL:
            this->_prepareToReadScalarField(
                _State::READ_FIXED_LEN_UINT_FIELD_BA_8_WITH_ROLE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_16_LE_WITH_ROLE_SAVE_VAL:
            this->_prepareToReadScalarField(
                _State::READ_FIXED_LEN_UINT_FIELD_BA_16_LE_WITH_ROLE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_16_BE_WITH_ROLE_SAVE_VAL:
            this->_prepareToReadScalarField(
                _State::READ_FIXED_LEN_UINT_FIELD_BA_16_BE_WITH_ROLE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_32_LE_WITH_ROLE_SAVE_VAL:
            this->_prepareToReadScalarField(
                _State::READ_FIXED_LEN_UINT_FIELD_BA_32_LE_WITH_ROLE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_32_BE_WITH_ROLE_SAVE_VAL:
            this->_prepareToReadScalarField(
                _State::READ_FIXED_LEN_UINT_FIELD_BA_32_BE_WITH_ROLE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_64_LE_WITH_ROLE_SAVE_VAL:
            this->_prepareToReadScalarField(
                _State::READ_FIXED_LEN_UINT_FIELD_BA_64_LE_WITH_ROLE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_UINT_BA_64_BE_WITH_ROLE_SAVE_VAL:
            this->_prepareToReadScalarField(
                _State::READ_FIXED_LEN_UINT_FIELD_BA_64_BE_WITH_ROLE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_SINT_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SINT_FIELD_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_SINT_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SINT_FIELD_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_SINT_BA_8:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SINT_FIELD_BA_8, fc);
            break;
        case FcDeepType::FIXED_LEN_SINT_BA_16_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SINT_FIELD_BA_16_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_SINT_BA_16_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SINT_FIELD_BA_16_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_SINT_BA_32_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SINT_FIELD_BA_32_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_SINT_BA_32_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SINT_FIELD_BA_32_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_SINT_BA_64_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SINT_FIELD_BA_64_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_SINT_BA_64_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SINT_FIELD_BA_64_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_SINT_BE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SINT_FIELD_BE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_SINT_LE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SINT_FIELD_LE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_SINT_BA_8_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SINT_FIELD_BA_8_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_SINT_BA_16_LE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SINT_FIELD_BA_16_LE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_SINT_BA_16_BE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SINT_FIELD_BA_16_BE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_SINT_BA_32_LE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SINT_FIELD_BA_32_LE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_SINT_BA_32_BE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SINT_FIELD_BA_32_BE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_SINT_BA_64_LE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SINT_FIELD_BA_64_LE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_SINT_BA_64_BE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SINT_FIELD_BA_64_BE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_8:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_BA_8, fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_16_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_BA_16_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_16_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_BA_16_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_32_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_BA_32_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_32_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_BA_32_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_64_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_BA_64_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_64_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_BA_64_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BE_WITH_ROLE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_BE_WITH_ROLE, fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_LE_WITH_ROLE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_LE_WITH_ROLE, fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_8_WITH_ROLE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_BA_8_WITH_ROLE, fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_16_LE_WITH_ROLE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_BA_16_LE_WITH_ROLE,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_16_BE_WITH_ROLE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_BA_16_BE_WITH_ROLE,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_32_LE_WITH_ROLE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_BA_32_LE_WITH_ROLE,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_32_BE_WITH_ROLE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_BA_32_BE_WITH_ROLE,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_64_LE_WITH_ROLE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_BA_64_LE_WITH_ROLE,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_64_BE_WITH_ROLE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_BA_64_BE_WITH_ROLE,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_BE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_LE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_LE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_8_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_BA_8_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_16_LE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_BA_16_LE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_16_BE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_BA_16_BE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_32_LE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_BA_32_LE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_32_BE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_BA_32_BE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_64_LE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_BA_64_LE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_64_BE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_UENUM_FIELD_BA_64_BE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BE_WITH_ROLE_SAVE_VAL:
            this->_prepareToReadScalarField(
                _State::READ_FIXED_LEN_UENUM_FIELD_BE_WITH_ROLE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_LE_WITH_ROLE_SAVE_VAL:
            this->_prepareToReadScalarField(
                _State::READ_FIXED_LEN_UENUM_FIELD_LE_WITH_ROLE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_8_WITH_ROLE_SAVE_VAL:
            this->_prepareToReadScalarField(
                _State::READ_FIXED_LEN_UENUM_FIELD_BA_8_WITH_ROLE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_16_LE_WITH_ROLE_SAVE_VAL:
            this->_prepareToReadScalarField(
                _State::READ_FIXED_LEN_UENUM_FIELD_BA_16_LE_WITH_ROLE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_16_BE_WITH_ROLE_SAVE_VAL:
            this->_prepareToReadScalarField(
                _State::READ_FIXED_LEN_UENUM_FIELD_BA_16_BE_WITH_ROLE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_32_LE_WITH_ROLE_SAVE_VAL:
            this->_prepareToReadScalarField(
                _State::READ_FIXED_LEN_UENUM_FIELD_BA_32_LE_WITH_ROLE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_32_BE_WITH_ROLE_SAVE_VAL:
            this->_prepareToReadScalarField(
                _State::READ_FIXED_LEN_UENUM_FIELD_BA_32_BE_WITH_ROLE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_64_LE_WITH_ROLE_SAVE_VAL:
            this->_prepareToReadScalarField(
                _State::READ_FIXED_LEN_UENUM_FIELD_BA_64_LE_WITH_ROLE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_UENUM_BA_64_BE_WITH_ROLE_SAVE_VAL:
            this->_prepareToReadScalarField(
                _State::READ_FIXED_LEN_UENUM_FIELD_BA_64_BE_WITH_ROLE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_SENUM_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SENUM_FIELD_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_SENUM_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SENUM_FIELD_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_SENUM_BA_8:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SENUM_FIELD_BA_8, fc);
            break;
        case FcDeepType::FIXED_LEN_SENUM_BA_16_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SENUM_FIELD_BA_16_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_SENUM_BA_16_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SENUM_FIELD_BA_16_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_SENUM_BA_32_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SENUM_FIELD_BA_32_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_SENUM_BA_32_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SENUM_FIELD_BA_32_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_SENUM_BA_64_LE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SENUM_FIELD_BA_64_LE, fc);
            break;
        case FcDeepType::FIXED_LEN_SENUM_BA_64_BE:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SENUM_FIELD_BA_64_BE, fc);
            break;
        case FcDeepType::FIXED_LEN_SENUM_BE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SENUM_FIELD_BE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_SENUM_LE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SENUM_FIELD_LE_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_SENUM_BA_8_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SENUM_FIELD_BA_8_SAVE_VAL, fc);
            break;
        case FcDeepType::FIXED_LEN_SENUM_BA_16_LE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SENUM_FIELD_BA_16_LE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_SENUM_BA_16_BE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SENUM_FIELD_BA_16_BE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_SENUM_BA_32_LE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SENUM_FIELD_BA_32_LE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_SENUM_BA_32_BE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SENUM_FIELD_BA_32_BE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_SENUM_BA_64_LE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SENUM_FIELD_BA_64_LE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::FIXED_LEN_SENUM_BA_64_BE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_FIXED_LEN_SENUM_FIELD_BA_64_BE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::VAR_LEN_UINT:
            this->_prepareToReadScalarField(_State::READ_VAR_LEN_UINT_FIELD, fc);
            break;
        case FcDeepType::VAR_LEN_UINT_WITH_ROLE:
            this->_prepareToReadScalarField(_State::READ_VAR_LEN_UINT_FIELD_WITH_ROLE, fc);
            break;
        case FcDeepType::VAR_LEN_UINT_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_VAR_LEN_UINT_FIELD_SAVE_VAL, fc);
            break;
        case FcDeepType::VAR_LEN_UINT_WITH_ROLE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_VAR_LEN_UINT_FIELD_WITH_ROLE_SAVE_VAL, fc);
            break;
        case FcDeepType::VAR_LEN_SINT:
            this->_prepareToReadScalarField(_State::READ_VAR_LEN_SINT_FIELD, fc);
            break;
        case FcDeepType::VAR_LEN_SINT_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_VAR_LEN_SINT_FIELD_SAVE_VAL, fc);
            break;
        case FcDeepType::VAR_LEN_UENUM:
            this->_prepareToReadScalarField(_State::READ_VAR_LEN_UENUM_FIELD, fc);
            break;
        case FcDeepType::VAR_LEN_UENUM_WITH_ROLE:
            this->_prepareToReadScalarField(_State::READ_VAR_LEN_UENUM_FIELD_WITH_ROLE, fc);
            break;
        case FcDeepType::VAR_LEN_UENUM_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_VAR_LEN_UENUM_FIELD_SAVE_VAL, fc);
            break;
        case FcDeepType::VAR_LEN_UENUM_WITH_ROLE_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_VAR_LEN_UENUM_FIELD_WITH_ROLE_SAVE_VAL,
                                            fc);
            break;
        case FcDeepType::VAR_LEN_SENUM:
            this->_prepareToReadScalarField(_State::READ_VAR_LEN_SENUM_FIELD, fc);
            break;
        case FcDeepType::VAR_LEN_SENUM_SAVE_VAL:
            this->_prepareToReadScalarField(_State::READ_VAR_LEN_SENUM_FIELD_SAVE_VAL, fc);
            break;
        case FcDeepType::NULL_TERMINATED_STR:
            this->_prepareToReadContainerField(_State::BEGIN_READ_NULL_TERMINATED_STR_FIELD,
                                               _State::END_READ_NULL_TERMINATED_STR_FIELD, fc);
            break;
        case FcDeepType::STATIC_LEN_STR:
            this->_prepareToReadContainerField(_State::BEGIN_READ_STATIC_LEN_STR_FIELD,
                                               _State::END_READ_STATIC_LEN_STR_FIELD, fc);
            break;
        case FcDeepType::DYN_LEN_STR:
            this->_prepareToReadContainerField(_State::BEGIN_READ_DYN_LEN_STR_FIELD,
                                               _State::END_READ_DYN_LEN_STR_FIELD, fc);
            break;
        case FcDeepType::STATIC_LEN_BLOB:
            this->_prepareToReadContainerField(_State::BEGIN_READ_STATIC_LEN_BLOB_FIELD,
                                               _State::END_READ_STATIC_LEN_BLOB_FIELD, fc);
            break;
        case FcDeepType::STATIC_LEN_BLOB_WITH_METADATA_STREAM_UUID_ROLE:
            this->_prepareToReadContainerField(
                _State::BEGIN_READ_STATIC_LEN_BLOB_FIELD_METADATA_STREAM_UUID,
                _State::END_READ_STATIC_LEN_BLOB_FIELD, fc);
            break;
        case FcDeepType::DYN_LEN_BLOB:
            this->_prepareToReadContainerField(_State::BEGIN_READ_DYN_LEN_BLOB_FIELD,
                                               _State::END_READ_DYN_LEN_BLOB_FIELD, fc);
            break;
        case FcDeepType::STRUCT:
            this->_prepareToReadStructField(fc.asStruct());
            break;
        case FcDeepType::STATIC_LEN_ARRAY:
            this->_prepareToReadContainerField(_State::BEGIN_READ_STATIC_LEN_ARRAY_FIELD,
                                               _State::END_READ_STATIC_LEN_ARRAY_FIELD, fc);
            break;
        case FcDeepType::STATIC_LEN_ARRAY_WITH_METADATA_STREAM_UUID_ROLE:
            this->_prepareToReadContainerField(
                _State::BEGIN_READ_STATIC_LEN_ARRAY_FIELD_METADATA_STREAM_UUID,
                _State::END_READ_STATIC_LEN_ARRAY_FIELD, fc);
            break;
        case FcDeepType::DYN_LEN_ARRAY:
            this->_prepareToReadContainerField(_State::BEGIN_READ_DYN_LEN_ARRAY_FIELD,
                                               _State::END_READ_DYN_LEN_ARRAY_FIELD, fc);
            break;
        case FcDeepType::OPTIONAL_WITH_BOOL_SEL:
            this->_prepareToReadContainerField(_State::BEGIN_READ_OPTIONAL_FIELD_WITH_BOOL_SEL,
                                               _State::END_READ_OPTIONAL_FIELD_WITH_BOOL_SEL, fc);
            break;
        case FcDeepType::OPTIONAL_WITH_UINT_SEL:
            this->_prepareToReadContainerField(_State::BEGIN_READ_OPTIONAL_FIELD_WITH_UINT_SEL,
                                               _State::END_READ_OPTIONAL_FIELD_WITH_UINT_SEL, fc);
            break;
        case FcDeepType::OPTIONAL_WITH_SINT_SEL:
            this->_prepareToReadContainerField(_State::BEGIN_READ_OPTIONAL_FIELD_WITH_SINT_SEL,
                                               _State::END_READ_OPTIONAL_FIELD_WITH_SINT_SEL, fc);
            break;
        case FcDeepType::VARIANT_WITH_UINT_SEL:
            this->_prepareToReadContainerField(_State::BEGIN_READ_VARIANT_FIELD_WITH_UINT_SEL,
                                               _State::END_READ_VARIANT_FIELD_WITH_UINT_SEL, fc);
            break;
        case FcDeepType::VARIANT_WITH_SINT_SEL:
            this->_prepareToReadContainerField(_State::BEGIN_READ_VARIANT_FIELD_WITH_SINT_SEL,
                                               _State::END_READ_VARIANT_FIELD_WITH_SINT_SEL, fc);
            break;
        default:
            bt_common_abort();
        }
    }

    /*
     * Sets the state and possibly updates the stack to read the next
     * field.
     */
    void _prepareToReadNextField()
    {
        auto& top = this->_stackTop();

        /* Next */
        ++top.elemIndex;

        if (top.elemIndex == top.len) {
            /*
             * Restore previous state.
             *
             * We don't call _stackPop() at this point because the
             * handler of the restored state typically needs
             * `this->_stackTop().fc` to update its item for the user.
             */
            this->_restoreState();
        } else {
            /* Find the class of the field to read next */
            BT_ASSERT_DBG(top.fc);

            if (top.fc->isStruct()) {
                this->_prepareToReadField(top.fc->asStruct()[top.elemIndex].fc());
            } else if (top.fc->isArray()) {
                this->_prepareToReadField(top.fc->asArray().elemFc());
            } else {
                /*
                 * `top.elemIndex == top.len` is always true for other
                 * compound (optional and variant) field class types.
                 */
                bt_common_abort();
            }
        }
    }

    /*
     * Sets the current state to `state`.
     */
    void _state(const _State state) noexcept
    {
        _mState = state;
    }

    /*
     * Handles the current state.
     */
    _StateHandlingReaction _handleState()
    {
        switch (_mState) {
        case _State::INIT:
            return this->_handleInitState();
        case _State::TRY_BEGIN_READ_PKT:
            return this->_handleTryBeginReadPktState();
        case _State::BEGIN_READ_PKT_CONTENT:
            return this->_handleBeginReadPktContentState();
        case _State::TRY_BEGIN_READ_PKT_HEADER_SCOPE:
            return this->_handleTryBeginReadPktHeaderScopeState();
        case _State::TRY_BEGIN_READ_PKT_CTX_SCOPE:
            return this->_handleTryBeginReadPktCtxScopeState();
        case _State::TRY_BEGIN_READ_EVENT_RECORD_HEADER_SCOPE:
            return this->_handleTryBeginReadEventRecordHeaderScopeState();
        case _State::TRY_BEGIN_READ_EVENT_RECORD_COMMON_CTX_SCOPE:
            return this->_handleTryBeginReadEventRecordCommonCtxScopeState();
        case _State::TRY_BEGIN_READ_EVENT_RECORD_SPEC_CTX_SCOPE:
            return this->_handleTryBeginReadEventRecordSpecCtxScopeState();
        case _State::TRY_BEGIN_READ_EVENT_RECORD_PAYLOAD_SCOPE:
            return this->_handleTryBeginReadEventRecordPayloadScopeState();
        case _State::END_READ_PKT_HEADER_SCOPE:
            return this->_handleEndReadPktHeaderScopeState();
        case _State::END_READ_PKT_CTX_SCOPE:
            return this->_handleEndReadPktCtxScopeState();
        case _State::END_READ_EVENT_RECORD_HEADER_SCOPE:
            return this->_handleEndReadEventRecordHeaderScopeState();
        case _State::END_READ_EVENT_RECORD_COMMON_CTX_SCOPE:
            return this->_handleEndReadEventRecordCommonCtxScopeState();
        case _State::END_READ_EVENT_RECORD_SPEC_CTX_SCOPE:
            return this->_handleEndReadEventRecordSpecCtxScopeState();
        case _State::END_READ_EVENT_RECORD_PAYLOAD_SCOPE:
            return this->_handleEndReadEventRecordPayloadScopeState();
        case _State::TRY_BEGIN_READ_EVENT_RECORD:
            return this->_handleTryBeginReadEventRecordState();
        case _State::END_READ_EVENT_RECORD:
            return this->_handleEndReadEventRecordState();
        case _State::BEGIN_READ_STRUCT_FIELD:
            return this->_handleBeginReadStructFieldState();
        case _State::END_READ_STRUCT_FIELD:
            return this->_handleEndReadStructFieldState();
        case _State::BEGIN_READ_STATIC_LEN_ARRAY_FIELD:
            return this->_handleBeginReadStaticLenArrayFieldState();
        case _State::BEGIN_READ_STATIC_LEN_ARRAY_FIELD_METADATA_STREAM_UUID:
            return this->_handleBeginReadStaticLenArrayFieldMetadataStreamUuidState();
        case _State::SET_METADATA_STREAM_UUID_ITEM:
            return this->_handleSetMetadataStreamUuidItemState();
        case _State::END_READ_STATIC_LEN_ARRAY_FIELD:
            return this->_handleEndReadStaticLenArrayFieldState();
        case _State::BEGIN_READ_DYN_LEN_ARRAY_FIELD:
            return this->_handleBeginReadDynLenArrayFieldState();
        case _State::END_READ_DYN_LEN_ARRAY_FIELD:
            return this->_handleEndReadDynLenArrayFieldState();
        case _State::BEGIN_READ_NULL_TERMINATED_STR_FIELD:
            return this->_handleBeginReadNullTerminatedStrFieldState();
        case _State::END_READ_NULL_TERMINATED_STR_FIELD:
            return this->_handleEndReadNullTerminatedStrFieldState();
        case _State::READ_SUBSTR_UNTIL_NULL_CHAR:
            return this->_handleReadSubstrUntilNullCharState();
        case _State::BEGIN_READ_STATIC_LEN_STR_FIELD:
            return this->_handleBeginReadStaticLenStrFieldState();
        case _State::END_READ_STATIC_LEN_STR_FIELD:
            return this->_handleEndReadStaticLenStrFieldState();
        case _State::BEGIN_READ_DYN_LEN_STR_FIELD:
            return this->_handleBeginReadDynLenStrFieldState();
        case _State::END_READ_DYN_LEN_STR_FIELD:
            return this->_handleEndReadDynLenStrFieldState();
        case _State::READ_SUBSTR:
            return this->_handleReadSubstrState();
        case _State::BEGIN_READ_STATIC_LEN_BLOB_FIELD:
            return this->_handleBeginReadStaticLenBlobFieldState();
        case _State::BEGIN_READ_STATIC_LEN_BLOB_FIELD_METADATA_STREAM_UUID:
            return this->_handleBeginReadStaticLenBlobFieldMetadataStreamUuidState();
        case _State::END_READ_STATIC_LEN_BLOB_FIELD:
            return this->_handleEndReadStaticLenBlobFieldState();
        case _State::BEGIN_READ_DYN_LEN_BLOB_FIELD:
            return this->_handleBeginReadDynLenBlobFieldState();
        case _State::END_READ_DYN_LEN_BLOB_FIELD:
            return this->_handleEndReadDynLenBlobFieldState();
        case _State::READ_BLOB_FIELD_SECTION:
            return this->_handleReadBlobFieldSectionState();
        case _State::READ_METADATA_STREAM_UUID_BLOB_FIELD_SECTION:
            return this->_handleReadMetadataStreamUuidBlobFieldSectionState();
        case _State::BEGIN_READ_VARIANT_FIELD_WITH_UINT_SEL:
            return this->_handleBeginReadVariantFieldWithUIntSelState();
        case _State::END_READ_VARIANT_FIELD_WITH_UINT_SEL:
            return this->_handleEndReadVariantFieldWithUIntSelState();
        case _State::BEGIN_READ_VARIANT_FIELD_WITH_SINT_SEL:
            return this->_handleBeginReadVariantFieldWithSIntSelState();
        case _State::END_READ_VARIANT_FIELD_WITH_SINT_SEL:
            return this->_handleEndReadVariantFieldWithSIntSelState();
        case _State::BEGIN_READ_OPTIONAL_FIELD_WITH_BOOL_SEL:
            return this->_handleBeginReadOptionalFieldWithBoolSelState();
        case _State::END_READ_OPTIONAL_FIELD_WITH_BOOL_SEL:
            return this->_handleEndReadOptionalFieldWithBoolSelState();
        case _State::BEGIN_READ_OPTIONAL_FIELD_WITH_UINT_SEL:
            return this->_handleBeginReadOptionalFieldWithUIntSelState();
        case _State::END_READ_OPTIONAL_FIELD_WITH_UINT_SEL:
            return this->_handleEndReadOptionalFieldWithUIntSelState();
        case _State::BEGIN_READ_OPTIONAL_FIELD_WITH_SINT_SEL:
            return this->_handleBeginReadOptionalFieldWithSIntSelState();
        case _State::END_READ_OPTIONAL_FIELD_WITH_SINT_SEL:
            return this->_handleEndReadOptionalFieldWithSIntSelState();
        case _State::READ_FIXED_LEN_BIT_ARRAY_FIELD_BE:
            return this->_handleReadFixedLenBitArrayFieldBeState();
        case _State::READ_FIXED_LEN_BIT_ARRAY_FIELD_LE:
            return this->_handleReadFixedLenBitArrayFieldLeState();
        case _State::READ_FIXED_LEN_BIT_ARRAY_FIELD_BA_8:
            return this->_handleReadFixedLenBitArrayFieldBa8State();
        case _State::READ_FIXED_LEN_BIT_ARRAY_FIELD_BA_16_LE:
            return this->_handleReadFixedLenBitArrayFieldBa16LeState();
        case _State::READ_FIXED_LEN_BIT_ARRAY_FIELD_BA_16_BE:
            return this->_handleReadFixedLenBitArrayFieldBa16BeState();
        case _State::READ_FIXED_LEN_BIT_ARRAY_FIELD_BA_32_LE:
            return this->_handleReadFixedLenBitArrayFieldBa32LeState();
        case _State::READ_FIXED_LEN_BIT_ARRAY_FIELD_BA_32_BE:
            return this->_handleReadFixedLenBitArrayFieldBa32BeState();
        case _State::READ_FIXED_LEN_BIT_ARRAY_FIELD_BA_64_LE:
            return this->_handleReadFixedLenBitArrayFieldBa64LeState();
        case _State::READ_FIXED_LEN_BIT_ARRAY_FIELD_BA_64_BE:
            return this->_handleReadFixedLenBitArrayFieldBa64BeState();
        case _State::READ_FIXED_LEN_BOOL_FIELD_BE:
            return this->_handleReadFixedLenBoolFieldBeState();
        case _State::READ_FIXED_LEN_BOOL_FIELD_LE:
            return this->_handleReadFixedLenBoolFieldLeState();
        case _State::READ_FIXED_LEN_BOOL_FIELD_BA_8:
            return this->_handleReadFixedLenBoolFieldBa8State();
        case _State::READ_FIXED_LEN_BOOL_FIELD_BA_16_LE:
            return this->_handleReadFixedLenBoolFieldBa16LeState();
        case _State::READ_FIXED_LEN_BOOL_FIELD_BA_16_BE:
            return this->_handleReadFixedLenBoolFieldBa16BeState();
        case _State::READ_FIXED_LEN_BOOL_FIELD_BA_32_LE:
            return this->_handleReadFixedLenBoolFieldBa32LeState();
        case _State::READ_FIXED_LEN_BOOL_FIELD_BA_32_BE:
            return this->_handleReadFixedLenBoolFieldBa32BeState();
        case _State::READ_FIXED_LEN_BOOL_FIELD_BA_64_LE:
            return this->_handleReadFixedLenBoolFieldBa64LeState();
        case _State::READ_FIXED_LEN_BOOL_FIELD_BA_64_BE:
            return this->_handleReadFixedLenBoolFieldBa64BeState();
        case _State::READ_FIXED_LEN_BOOL_FIELD_BE_SAVE_VAL:
            return this->_handleReadFixedLenBoolFieldBeSaveValState();
        case _State::READ_FIXED_LEN_BOOL_FIELD_LE_SAVE_VAL:
            return this->_handleReadFixedLenBoolFieldLeSaveValState();
        case _State::READ_FIXED_LEN_BOOL_FIELD_BA_8_SAVE_VAL:
            return this->_handleReadFixedLenBoolFieldBa8SaveValState();
        case _State::READ_FIXED_LEN_BOOL_FIELD_BA_16_LE_SAVE_VAL:
            return this->_handleReadFixedLenBoolFieldBa16LeSaveValState();
        case _State::READ_FIXED_LEN_BOOL_FIELD_BA_16_BE_SAVE_VAL:
            return this->_handleReadFixedLenBoolFieldBa16BeSaveValState();
        case _State::READ_FIXED_LEN_BOOL_FIELD_BA_32_LE_SAVE_VAL:
            return this->_handleReadFixedLenBoolFieldBa32LeSaveValState();
        case _State::READ_FIXED_LEN_BOOL_FIELD_BA_32_BE_SAVE_VAL:
            return this->_handleReadFixedLenBoolFieldBa32BeSaveValState();
        case _State::READ_FIXED_LEN_BOOL_FIELD_BA_64_LE_SAVE_VAL:
            return this->_handleReadFixedLenBoolFieldBa64LeSaveValState();
        case _State::READ_FIXED_LEN_BOOL_FIELD_BA_64_BE_SAVE_VAL:
            return this->_handleReadFixedLenBoolFieldBa64BeSaveValState();
        case _State::READ_FIXED_LEN_FLOAT_FIELD_32_BE:
            return this->_handleReadFixedLenFloatField32BeState();
        case _State::READ_FIXED_LEN_FLOAT_FIELD_32_LE:
            return this->_handleReadFixedLenFloatField32LeState();
        case _State::READ_FIXED_LEN_FLOAT_FIELD_64_BE:
            return this->_handleReadFixedLenFloatField64BeState();
        case _State::READ_FIXED_LEN_FLOAT_FIELD_64_LE:
            return this->_handleReadFixedLenFloatField64LeState();
        case _State::READ_FIXED_LEN_FLOAT_FIELD_BA_32_LE:
            return this->_handleReadFixedLenFloatFieldBa32LeState();
        case _State::READ_FIXED_LEN_FLOAT_FIELD_BA_32_BE:
            return this->_handleReadFixedLenFloatFieldBa32BeState();
        case _State::READ_FIXED_LEN_FLOAT_FIELD_BA_64_LE:
            return this->_handleReadFixedLenFloatFieldBa64LeState();
        case _State::READ_FIXED_LEN_FLOAT_FIELD_BA_64_BE:
            return this->_handleReadFixedLenFloatFieldBa64BeState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BE:
            return this->_handleReadFixedLenUIntFieldBeState();
        case _State::READ_FIXED_LEN_UINT_FIELD_LE:
            return this->_handleReadFixedLenUIntFieldLeState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_8:
            return this->_handleReadFixedLenUIntFieldBa8State();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_16_LE:
            return this->_handleReadFixedLenUIntFieldBa16LeState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_16_BE:
            return this->_handleReadFixedLenUIntFieldBa16BeState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_32_LE:
            return this->_handleReadFixedLenUIntFieldBa32LeState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_32_BE:
            return this->_handleReadFixedLenUIntFieldBa32BeState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_64_LE:
            return this->_handleReadFixedLenUIntFieldBa64LeState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_64_BE:
            return this->_handleReadFixedLenUIntFieldBa64BeState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BE_WITH_ROLE:
            return this->_handleReadFixedLenUIntFieldBeWithRoleState();
        case _State::READ_FIXED_LEN_UINT_FIELD_LE_WITH_ROLE:
            return this->_handleReadFixedLenUIntFieldLeWithRoleState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_8_WITH_ROLE:
            return this->_handleReadFixedLenUIntFieldBa8WithRoleState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_16_LE_WITH_ROLE:
            return this->_handleReadFixedLenUIntFieldBa16LeWithRoleState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_16_BE_WITH_ROLE:
            return this->_handleReadFixedLenUIntFieldBa16BeWithRoleState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_32_LE_WITH_ROLE:
            return this->_handleReadFixedLenUIntFieldBa32LeWithRoleState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_32_BE_WITH_ROLE:
            return this->_handleReadFixedLenUIntFieldBa32BeWithRoleState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_64_LE_WITH_ROLE:
            return this->_handleReadFixedLenUIntFieldBa64LeWithRoleState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_64_BE_WITH_ROLE:
            return this->_handleReadFixedLenUIntFieldBa64BeWithRoleState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BE_SAVE_VAL:
            return this->_handleReadFixedLenUIntFieldBeSaveValState();
        case _State::READ_FIXED_LEN_UINT_FIELD_LE_SAVE_VAL:
            return this->_handleReadFixedLenUIntFieldLeSaveValState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_8_SAVE_VAL:
            return this->_handleReadFixedLenUIntFieldBa8SaveValState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_16_LE_SAVE_VAL:
            return this->_handleReadFixedLenUIntFieldBa16LeSaveValState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_16_BE_SAVE_VAL:
            return this->_handleReadFixedLenUIntFieldBa16BeSaveValState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_32_LE_SAVE_VAL:
            return this->_handleReadFixedLenUIntFieldBa32LeSaveValState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_32_BE_SAVE_VAL:
            return this->_handleReadFixedLenUIntFieldBa32BeSaveValState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_64_LE_SAVE_VAL:
            return this->_handleReadFixedLenUIntFieldBa64LeSaveValState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_64_BE_SAVE_VAL:
            return this->_handleReadFixedLenUIntFieldBa64BeSaveValState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BE_WITH_ROLE_SAVE_VAL:
            return this->_handleReadFixedLenUIntFieldBeWithRoleSaveValState();
        case _State::READ_FIXED_LEN_UINT_FIELD_LE_WITH_ROLE_SAVE_VAL:
            return this->_handleReadFixedLenUIntFieldLeWithRoleSaveValState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_8_WITH_ROLE_SAVE_VAL:
            return this->_handleReadFixedLenUIntFieldBa8WithRoleSaveValState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_16_LE_WITH_ROLE_SAVE_VAL:
            return this->_handleReadFixedLenUIntFieldBa16LeWithRoleSaveValState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_16_BE_WITH_ROLE_SAVE_VAL:
            return this->_handleReadFixedLenUIntFieldBa16BeWithRoleSaveValState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_32_LE_WITH_ROLE_SAVE_VAL:
            return this->_handleReadFixedLenUIntFieldBa32LeWithRoleSaveValState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_32_BE_WITH_ROLE_SAVE_VAL:
            return this->_handleReadFixedLenUIntFieldBa32BeWithRoleSaveValState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_64_LE_WITH_ROLE_SAVE_VAL:
            return this->_handleReadFixedLenUIntFieldBa64LeWithRoleSaveValState();
        case _State::READ_FIXED_LEN_UINT_FIELD_BA_64_BE_WITH_ROLE_SAVE_VAL:
            return this->_handleReadFixedLenUIntFieldBa64BeWithRoleSaveValState();
        case _State::READ_FIXED_LEN_SINT_FIELD_BE:
            return this->_handleReadFixedLenSIntFieldBeState();
        case _State::READ_FIXED_LEN_SINT_FIELD_LE:
            return this->_handleReadFixedLenSIntFieldLeState();
        case _State::READ_FIXED_LEN_SINT_FIELD_BA_8:
            return this->_handleReadFixedLenSIntFieldBa8State();
        case _State::READ_FIXED_LEN_SINT_FIELD_BA_16_LE:
            return this->_handleReadFixedLenSIntFieldBa16LeState();
        case _State::READ_FIXED_LEN_SINT_FIELD_BA_16_BE:
            return this->_handleReadFixedLenSIntFieldBa16BeState();
        case _State::READ_FIXED_LEN_SINT_FIELD_BA_32_LE:
            return this->_handleReadFixedLenSIntFieldBa32LeState();
        case _State::READ_FIXED_LEN_SINT_FIELD_BA_32_BE:
            return this->_handleReadFixedLenSIntFieldBa32BeState();
        case _State::READ_FIXED_LEN_SINT_FIELD_BA_64_LE:
            return this->_handleReadFixedLenSIntFieldBa64LeState();
        case _State::READ_FIXED_LEN_SINT_FIELD_BA_64_BE:
            return this->_handleReadFixedLenSIntFieldBa64BeState();
        case _State::READ_FIXED_LEN_SINT_FIELD_BE_SAVE_VAL:
            return this->_handleReadFixedLenSIntFieldBeSaveValState();
        case _State::READ_FIXED_LEN_SINT_FIELD_LE_SAVE_VAL:
            return this->_handleReadFixedLenSIntFieldLeSaveValState();
        case _State::READ_FIXED_LEN_SINT_FIELD_BA_8_SAVE_VAL:
            return this->_handleReadFixedLenSIntFieldBa8SaveValState();
        case _State::READ_FIXED_LEN_SINT_FIELD_BA_16_LE_SAVE_VAL:
            return this->_handleReadFixedLenSIntFieldBa16LeSaveValState();
        case _State::READ_FIXED_LEN_SINT_FIELD_BA_16_BE_SAVE_VAL:
            return this->_handleReadFixedLenSIntFieldBa16BeSaveValState();
        case _State::READ_FIXED_LEN_SINT_FIELD_BA_32_LE_SAVE_VAL:
            return this->_handleReadFixedLenSIntFieldBa32LeSaveValState();
        case _State::READ_FIXED_LEN_SINT_FIELD_BA_32_BE_SAVE_VAL:
            return this->_handleReadFixedLenSIntFieldBa32BeSaveValState();
        case _State::READ_FIXED_LEN_SINT_FIELD_BA_64_LE_SAVE_VAL:
            return this->_handleReadFixedLenSIntFieldBa64LeSaveValState();
        case _State::READ_FIXED_LEN_SINT_FIELD_BA_64_BE_SAVE_VAL:
            return this->_handleReadFixedLenSIntFieldBa64BeSaveValState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BE:
            return this->_handleReadFixedLenUEnumFieldBeState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_LE:
            return this->_handleReadFixedLenUEnumFieldLeState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_8:
            return this->_handleReadFixedLenUEnumFieldBa8State();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_16_LE:
            return this->_handleReadFixedLenUEnumFieldBa16LeState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_16_BE:
            return this->_handleReadFixedLenUEnumFieldBa16BeState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_32_LE:
            return this->_handleReadFixedLenUEnumFieldBa32LeState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_32_BE:
            return this->_handleReadFixedLenUEnumFieldBa32BeState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_64_LE:
            return this->_handleReadFixedLenUEnumFieldBa64LeState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_64_BE:
            return this->_handleReadFixedLenUEnumFieldBa64BeState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BE_WITH_ROLE:
            return this->_handleReadFixedLenUEnumFieldBeWithRoleState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_LE_WITH_ROLE:
            return this->_handleReadFixedLenUEnumFieldLeWithRoleState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_8_WITH_ROLE:
            return this->_handleReadFixedLenUEnumFieldBa8WithRoleState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_16_LE_WITH_ROLE:
            return this->_handleReadFixedLenUEnumFieldBa16LeWithRoleState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_16_BE_WITH_ROLE:
            return this->_handleReadFixedLenUEnumFieldBa16BeWithRoleState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_32_LE_WITH_ROLE:
            return this->_handleReadFixedLenUEnumFieldBa32LeWithRoleState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_32_BE_WITH_ROLE:
            return this->_handleReadFixedLenUEnumFieldBa32BeWithRoleState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_64_LE_WITH_ROLE:
            return this->_handleReadFixedLenUEnumFieldBa64LeWithRoleState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_64_BE_WITH_ROLE:
            return this->_handleReadFixedLenUEnumFieldBa64BeWithRoleState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BE_SAVE_VAL:
            return this->_handleReadFixedLenUEnumFieldBeSaveValState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_LE_SAVE_VAL:
            return this->_handleReadFixedLenUEnumFieldLeSaveValState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_8_SAVE_VAL:
            return this->_handleReadFixedLenUEnumFieldBa8SaveValState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_16_LE_SAVE_VAL:
            return this->_handleReadFixedLenUEnumFieldBa16LeSaveValState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_16_BE_SAVE_VAL:
            return this->_handleReadFixedLenUEnumFieldBa16BeSaveValState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_32_LE_SAVE_VAL:
            return this->_handleReadFixedLenUEnumFieldBa32LeSaveValState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_32_BE_SAVE_VAL:
            return this->_handleReadFixedLenUEnumFieldBa32BeSaveValState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_64_LE_SAVE_VAL:
            return this->_handleReadFixedLenUEnumFieldBa64LeSaveValState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_64_BE_SAVE_VAL:
            return this->_handleReadFixedLenUEnumFieldBa64BeSaveValState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BE_WITH_ROLE_SAVE_VAL:
            return this->_handleReadFixedLenUEnumFieldBeWithRoleSaveValState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_LE_WITH_ROLE_SAVE_VAL:
            return this->_handleReadFixedLenUEnumFieldLeWithRoleSaveValState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_8_WITH_ROLE_SAVE_VAL:
            return this->_handleReadFixedLenUEnumFieldBa8WithRoleSaveValState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_16_LE_WITH_ROLE_SAVE_VAL:
            return this->_handleReadFixedLenUEnumFieldBa16LeWithRoleSaveValState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_16_BE_WITH_ROLE_SAVE_VAL:
            return this->_handleReadFixedLenUEnumFieldBa16BeWithRoleSaveValState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_32_LE_WITH_ROLE_SAVE_VAL:
            return this->_handleReadFixedLenUEnumFieldBa32LeWithRoleSaveValState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_32_BE_WITH_ROLE_SAVE_VAL:
            return this->_handleReadFixedLenUEnumFieldBa32BeWithRoleSaveValState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_64_LE_WITH_ROLE_SAVE_VAL:
            return this->_handleReadFixedLenUEnumFieldBa64LeWithRoleSaveValState();
        case _State::READ_FIXED_LEN_UENUM_FIELD_BA_64_BE_WITH_ROLE_SAVE_VAL:
            return this->_handleReadFixedLenUEnumFieldBa64BeWithRoleSaveValState();
        case _State::READ_FIXED_LEN_SENUM_FIELD_BE:
            return this->_handleReadFixedLenSEnumFieldBeState();
        case _State::READ_FIXED_LEN_SENUM_FIELD_LE:
            return this->_handleReadFixedLenSEnumFieldLeState();
        case _State::READ_FIXED_LEN_SENUM_FIELD_BA_8:
            return this->_handleReadFixedLenSEnumFieldBa8State();
        case _State::READ_FIXED_LEN_SENUM_FIELD_BA_16_LE:
            return this->_handleReadFixedLenSEnumFieldBa16LeState();
        case _State::READ_FIXED_LEN_SENUM_FIELD_BA_16_BE:
            return this->_handleReadFixedLenSEnumFieldBa16BeState();
        case _State::READ_FIXED_LEN_SENUM_FIELD_BA_32_LE:
            return this->_handleReadFixedLenSEnumFieldBa32LeState();
        case _State::READ_FIXED_LEN_SENUM_FIELD_BA_32_BE:
            return this->_handleReadFixedLenSEnumFieldBa32BeState();
        case _State::READ_FIXED_LEN_SENUM_FIELD_BA_64_LE:
            return this->_handleReadFixedLenSEnumFieldBa64LeState();
        case _State::READ_FIXED_LEN_SENUM_FIELD_BA_64_BE:
            return this->_handleReadFixedLenSEnumFieldBa64BeState();
        case _State::READ_FIXED_LEN_SENUM_FIELD_BE_SAVE_VAL:
            return this->_handleReadFixedLenSEnumFieldBeSaveValState();
        case _State::READ_FIXED_LEN_SENUM_FIELD_LE_SAVE_VAL:
            return this->_handleReadFixedLenSEnumFieldLeSaveValState();
        case _State::READ_FIXED_LEN_SENUM_FIELD_BA_8_SAVE_VAL:
            return this->_handleReadFixedLenSEnumFieldBa8SaveValState();
        case _State::READ_FIXED_LEN_SENUM_FIELD_BA_16_LE_SAVE_VAL:
            return this->_handleReadFixedLenSEnumFieldBa16LeSaveValState();
        case _State::READ_FIXED_LEN_SENUM_FIELD_BA_16_BE_SAVE_VAL:
            return this->_handleReadFixedLenSEnumFieldBa16BeSaveValState();
        case _State::READ_FIXED_LEN_SENUM_FIELD_BA_32_LE_SAVE_VAL:
            return this->_handleReadFixedLenSEnumFieldBa32LeSaveValState();
        case _State::READ_FIXED_LEN_SENUM_FIELD_BA_32_BE_SAVE_VAL:
            return this->_handleReadFixedLenSEnumFieldBa32BeSaveValState();
        case _State::READ_FIXED_LEN_SENUM_FIELD_BA_64_LE_SAVE_VAL:
            return this->_handleReadFixedLenSEnumFieldBa64LeSaveValState();
        case _State::READ_FIXED_LEN_SENUM_FIELD_BA_64_BE_SAVE_VAL:
            return this->_handleReadFixedLenSEnumFieldBa64BeSaveValState();
        case _State::READ_VAR_LEN_UINT_FIELD:
            return this->_handleReadVarLenUIntFieldState();
        case _State::READ_VAR_LEN_UINT_FIELD_WITH_ROLE:
            return this->_handleReadVarLenUIntFieldWithRoleState();
        case _State::READ_VAR_LEN_UINT_FIELD_SAVE_VAL:
            return this->_handleReadVarLenUIntFieldSaveValState();
        case _State::READ_VAR_LEN_UINT_FIELD_WITH_ROLE_SAVE_VAL:
            return this->_handleReadVarLenUIntFieldWithRoleSaveValState();
        case _State::READ_VAR_LEN_SINT_FIELD:
            return this->_handleReadVarLenSIntFieldState();
        case _State::READ_VAR_LEN_SINT_FIELD_SAVE_VAL:
            return this->_handleReadVarLenSIntFieldSaveValState();
        case _State::READ_VAR_LEN_UENUM_FIELD:
            return this->_handleReadVarLenUEnumFieldState();
        case _State::READ_VAR_LEN_UENUM_FIELD_WITH_ROLE:
            return this->_handleReadVarLenUEnumFieldWithRoleState();
        case _State::READ_VAR_LEN_UENUM_FIELD_SAVE_VAL:
            return this->_handleReadVarLenUEnumFieldSaveValState();
        case _State::READ_VAR_LEN_UENUM_FIELD_WITH_ROLE_SAVE_VAL:
            return this->_handleReadVarLenUEnumFieldWithRoleSaveValState();
        case _State::READ_VAR_LEN_SENUM_FIELD:
            return this->_handleReadVarLenSEnumFieldState();
        case _State::READ_VAR_LEN_SENUM_FIELD_SAVE_VAL:
            return this->_handleReadVarLenSEnumFieldSaveValState();
        case _State::READ_FIXED_LEN_METADATA_STREAM_UUID_BYTE_UINT_FIELD_BA_8:
            return this->_handleReadFixedLenMetadataStreamUuidByteUIntFieldBa8State();
        case _State::READ_FIXED_LEN_METADATA_STREAM_UUID_BYTE_UENUM_FIELD_BA_8:
            return this->_handleReadFixedLenMetadataStreamUuidByteUEnumFieldBa8State();
        case _State::SET_DATA_STREAM_INFO_ITEM:
            return this->_handleSetDataStreamInfoItemState();
        case _State::SET_PKT_INFO_ITEM:
            return this->_handleSetPktInfoItemState();
        case _State::SET_EVENT_RECORD_INFO_ITEM:
            return this->_handleSetEventRecordInfoItemState();
        case _State::SET_PKT_MAGIC_NUMBER_ITEM:
            return this->_handleSetPktMagicNumberItem();
        case _State::SET_DEF_CLK_VAL_ITEM:
            return this->_handleSetDefClkValItem();
        case _State::END_READ_PKT_CONTENT:
            return this->_handleEndReadPktContentState();
        case _State::END_READ_PKT:
            return this->_handleEndReadPktState();
        case _State::SKIP_PADDING:
            return this->_handleSkipPaddingState();
        case _State::SKIP_CONTENT_PADDING:
            return this->_handleSkipContentPaddingState();
        default:
            bt_common_abort();
        };
    };

    /* State handlers */
    _StateHandlingReaction _handleInitState();
    _StateHandlingReaction _handleSkipPaddingState();
    _StateHandlingReaction _handleSkipContentPaddingState();
    _StateHandlingReaction _handleTryBeginReadPktState();
    _StateHandlingReaction _handleEndReadPktState();
    _StateHandlingReaction _handleBeginReadPktContentState();
    _StateHandlingReaction _handleEndReadPktContentState();
    _StateHandlingReaction _handleSetPktMagicNumberItem();
    _StateHandlingReaction _handleSetDefClkValItem();
    _StateHandlingReaction _handleTryBeginReadPktHeaderScopeState();
    _StateHandlingReaction _handleTryBeginReadPktCtxScopeState();
    _StateHandlingReaction _handleTryBeginReadEventRecordHeaderScopeState();
    _StateHandlingReaction _handleTryBeginReadEventRecordCommonCtxScopeState();
    _StateHandlingReaction _handleTryBeginReadEventRecordSpecCtxScopeState();
    _StateHandlingReaction _handleTryBeginReadEventRecordPayloadScopeState();
    _StateHandlingReaction _handleEndReadPktHeaderScopeState();
    _StateHandlingReaction _handleEndReadPktCtxScopeState();
    _StateHandlingReaction _handleEndReadEventRecordHeaderScopeState();
    _StateHandlingReaction _handleEndReadEventRecordCommonCtxScopeState();
    _StateHandlingReaction _handleEndReadEventRecordSpecCtxScopeState();
    _StateHandlingReaction _handleEndReadEventRecordPayloadScopeState();
    _StateHandlingReaction _handleTryBeginReadEventRecordState();
    _StateHandlingReaction _handleEndReadEventRecordState();
    _StateHandlingReaction _handleSetDataStreamInfoItemState();
    _StateHandlingReaction _handleSetPktInfoItemState();
    _StateHandlingReaction _handleSetEventRecordInfoItemState();
    _StateHandlingReaction _handleBeginReadStructFieldState();
    _StateHandlingReaction _handleEndReadStructFieldState();
    _StateHandlingReaction _handleBeginReadStaticLenArrayFieldState();
    _StateHandlingReaction _handleBeginReadStaticLenArrayFieldMetadataStreamUuidState();
    _StateHandlingReaction _handleSetMetadataStreamUuidItemState();
    _StateHandlingReaction _handleEndReadStaticLenArrayFieldState();
    _StateHandlingReaction _handleBeginReadDynLenArrayFieldState();
    _StateHandlingReaction _handleEndReadDynLenArrayFieldState();
    _StateHandlingReaction _handleBeginReadNullTerminatedStrFieldState();
    _StateHandlingReaction _handleEndReadNullTerminatedStrFieldState();
    _StateHandlingReaction _handleReadSubstrUntilNullCharState();
    _StateHandlingReaction _handleBeginReadStaticLenStrFieldState();
    _StateHandlingReaction _handleEndReadStaticLenStrFieldState();
    _StateHandlingReaction _handleBeginReadDynLenStrFieldState();
    _StateHandlingReaction _handleEndReadDynLenStrFieldState();
    _StateHandlingReaction _handleReadSubstrState();
    _StateHandlingReaction _handleBeginReadStaticLenBlobFieldState();
    _StateHandlingReaction _handleBeginReadStaticLenBlobFieldMetadataStreamUuidState();
    _StateHandlingReaction _handleEndReadStaticLenBlobFieldState();
    _StateHandlingReaction _handleBeginReadDynLenBlobFieldState();
    _StateHandlingReaction _handleEndReadDynLenBlobFieldState();
    _StateHandlingReaction _handleReadBlobFieldSectionState();
    _StateHandlingReaction _handleReadMetadataStreamUuidBlobFieldSectionState();
    _StateHandlingReaction _handleBeginReadVariantFieldWithUIntSelState();
    _StateHandlingReaction _handleEndReadVariantFieldWithUIntSelState();
    _StateHandlingReaction _handleBeginReadVariantFieldWithSIntSelState();
    _StateHandlingReaction _handleEndReadVariantFieldWithSIntSelState();
    _StateHandlingReaction _handleBeginReadOptionalFieldWithBoolSelState();
    _StateHandlingReaction _handleEndReadOptionalFieldWithBoolSelState();
    _StateHandlingReaction _handleBeginReadOptionalFieldWithUIntSelState();
    _StateHandlingReaction _handleEndReadOptionalFieldWithUIntSelState();
    _StateHandlingReaction _handleBeginReadOptionalFieldWithSIntSelState();
    _StateHandlingReaction _handleEndReadOptionalFieldWithSIntSelState();
    _StateHandlingReaction _handleReadFixedLenBitArrayFieldBeState();
    _StateHandlingReaction _handleReadFixedLenBitArrayFieldLeState();
    _StateHandlingReaction _handleReadFixedLenBitArrayFieldBa8State();
    _StateHandlingReaction _handleReadFixedLenBitArrayFieldBa16LeState();
    _StateHandlingReaction _handleReadFixedLenBitArrayFieldBa16BeState();
    _StateHandlingReaction _handleReadFixedLenBitArrayFieldBa32LeState();
    _StateHandlingReaction _handleReadFixedLenBitArrayFieldBa32BeState();
    _StateHandlingReaction _handleReadFixedLenBitArrayFieldBa64LeState();
    _StateHandlingReaction _handleReadFixedLenBitArrayFieldBa64BeState();
    _StateHandlingReaction _handleReadFixedLenBoolFieldBeState();
    _StateHandlingReaction _handleReadFixedLenBoolFieldLeState();
    _StateHandlingReaction _handleReadFixedLenBoolFieldBa8State();
    _StateHandlingReaction _handleReadFixedLenBoolFieldBa16LeState();
    _StateHandlingReaction _handleReadFixedLenBoolFieldBa16BeState();
    _StateHandlingReaction _handleReadFixedLenBoolFieldBa32LeState();
    _StateHandlingReaction _handleReadFixedLenBoolFieldBa32BeState();
    _StateHandlingReaction _handleReadFixedLenBoolFieldBa64LeState();
    _StateHandlingReaction _handleReadFixedLenBoolFieldBa64BeState();
    _StateHandlingReaction _handleReadFixedLenBoolFieldBeSaveValState();
    _StateHandlingReaction _handleReadFixedLenBoolFieldLeSaveValState();
    _StateHandlingReaction _handleReadFixedLenBoolFieldBa8SaveValState();
    _StateHandlingReaction _handleReadFixedLenBoolFieldBa16LeSaveValState();
    _StateHandlingReaction _handleReadFixedLenBoolFieldBa16BeSaveValState();
    _StateHandlingReaction _handleReadFixedLenBoolFieldBa32LeSaveValState();
    _StateHandlingReaction _handleReadFixedLenBoolFieldBa32BeSaveValState();
    _StateHandlingReaction _handleReadFixedLenBoolFieldBa64LeSaveValState();
    _StateHandlingReaction _handleReadFixedLenBoolFieldBa64BeSaveValState();
    _StateHandlingReaction _handleReadFixedLenFloatField32BeState();
    _StateHandlingReaction _handleReadFixedLenFloatField32LeState();
    _StateHandlingReaction _handleReadFixedLenFloatField64BeState();
    _StateHandlingReaction _handleReadFixedLenFloatField64LeState();
    _StateHandlingReaction _handleReadFixedLenFloatFieldBa32LeState();
    _StateHandlingReaction _handleReadFixedLenFloatFieldBa32BeState();
    _StateHandlingReaction _handleReadFixedLenFloatFieldBa64LeState();
    _StateHandlingReaction _handleReadFixedLenFloatFieldBa64BeState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBeState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldLeState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa8State();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa16LeState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa16BeState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa32LeState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa32BeState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa64LeState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa64BeState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBeWithRoleState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldLeWithRoleState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa8WithRoleState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa16LeWithRoleState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa16BeWithRoleState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa32LeWithRoleState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa32BeWithRoleState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa64LeWithRoleState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa64BeWithRoleState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBeSaveValState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldLeSaveValState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa8SaveValState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa16LeSaveValState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa16BeSaveValState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa32LeSaveValState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa32BeSaveValState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa64LeSaveValState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa64BeSaveValState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBeWithRoleSaveValState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldLeWithRoleSaveValState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa8WithRoleSaveValState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa16LeWithRoleSaveValState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa16BeWithRoleSaveValState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa32LeWithRoleSaveValState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa32BeWithRoleSaveValState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa64LeWithRoleSaveValState();
    _StateHandlingReaction _handleReadFixedLenUIntFieldBa64BeWithRoleSaveValState();
    _StateHandlingReaction _handleReadFixedLenSIntFieldBeState();
    _StateHandlingReaction _handleReadFixedLenSIntFieldLeState();
    _StateHandlingReaction _handleReadFixedLenSIntFieldBa8State();
    _StateHandlingReaction _handleReadFixedLenSIntFieldBa16LeState();
    _StateHandlingReaction _handleReadFixedLenSIntFieldBa16BeState();
    _StateHandlingReaction _handleReadFixedLenSIntFieldBa32LeState();
    _StateHandlingReaction _handleReadFixedLenSIntFieldBa32BeState();
    _StateHandlingReaction _handleReadFixedLenSIntFieldBa64LeState();
    _StateHandlingReaction _handleReadFixedLenSIntFieldBa64BeState();
    _StateHandlingReaction _handleReadFixedLenSIntFieldBeSaveValState();
    _StateHandlingReaction _handleReadFixedLenSIntFieldLeSaveValState();
    _StateHandlingReaction _handleReadFixedLenSIntFieldBa8SaveValState();
    _StateHandlingReaction _handleReadFixedLenSIntFieldBa16LeSaveValState();
    _StateHandlingReaction _handleReadFixedLenSIntFieldBa16BeSaveValState();
    _StateHandlingReaction _handleReadFixedLenSIntFieldBa32LeSaveValState();
    _StateHandlingReaction _handleReadFixedLenSIntFieldBa32BeSaveValState();
    _StateHandlingReaction _handleReadFixedLenSIntFieldBa64LeSaveValState();
    _StateHandlingReaction _handleReadFixedLenSIntFieldBa64BeSaveValState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBeState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldLeState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa8State();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa16LeState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa16BeState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa32LeState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa32BeState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa64LeState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa64BeState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBeWithRoleState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldLeWithRoleState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa8WithRoleState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa16LeWithRoleState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa16BeWithRoleState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa32LeWithRoleState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa32BeWithRoleState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa64LeWithRoleState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa64BeWithRoleState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBeSaveValState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldLeSaveValState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa8SaveValState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa16LeSaveValState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa16BeSaveValState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa32LeSaveValState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa32BeSaveValState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa64LeSaveValState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa64BeSaveValState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBeWithRoleSaveValState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldLeWithRoleSaveValState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa8WithRoleSaveValState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa16LeWithRoleSaveValState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa16BeWithRoleSaveValState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa32LeWithRoleSaveValState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa32BeWithRoleSaveValState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa64LeWithRoleSaveValState();
    _StateHandlingReaction _handleReadFixedLenUEnumFieldBa64BeWithRoleSaveValState();
    _StateHandlingReaction _handleReadFixedLenSEnumFieldBeState();
    _StateHandlingReaction _handleReadFixedLenSEnumFieldLeState();
    _StateHandlingReaction _handleReadFixedLenSEnumFieldBa8State();
    _StateHandlingReaction _handleReadFixedLenSEnumFieldBa16LeState();
    _StateHandlingReaction _handleReadFixedLenSEnumFieldBa16BeState();
    _StateHandlingReaction _handleReadFixedLenSEnumFieldBa32LeState();
    _StateHandlingReaction _handleReadFixedLenSEnumFieldBa32BeState();
    _StateHandlingReaction _handleReadFixedLenSEnumFieldBa64LeState();
    _StateHandlingReaction _handleReadFixedLenSEnumFieldBa64BeState();
    _StateHandlingReaction _handleReadFixedLenSEnumFieldBeSaveValState();
    _StateHandlingReaction _handleReadFixedLenSEnumFieldLeSaveValState();
    _StateHandlingReaction _handleReadFixedLenSEnumFieldBa8SaveValState();
    _StateHandlingReaction _handleReadFixedLenSEnumFieldBa16LeSaveValState();
    _StateHandlingReaction _handleReadFixedLenSEnumFieldBa16BeSaveValState();
    _StateHandlingReaction _handleReadFixedLenSEnumFieldBa32LeSaveValState();
    _StateHandlingReaction _handleReadFixedLenSEnumFieldBa32BeSaveValState();
    _StateHandlingReaction _handleReadFixedLenSEnumFieldBa64LeSaveValState();
    _StateHandlingReaction _handleReadFixedLenSEnumFieldBa64BeSaveValState();
    _StateHandlingReaction _handleReadVarLenUIntFieldState();
    _StateHandlingReaction _handleReadVarLenUIntFieldWithRoleState();
    _StateHandlingReaction _handleReadVarLenUIntFieldSaveValState();
    _StateHandlingReaction _handleReadVarLenUIntFieldWithRoleSaveValState();
    _StateHandlingReaction _handleReadVarLenSIntFieldState();
    _StateHandlingReaction _handleReadVarLenSIntFieldSaveValState();
    _StateHandlingReaction _handleReadVarLenUEnumFieldState();
    _StateHandlingReaction _handleReadVarLenUEnumFieldWithRoleState();
    _StateHandlingReaction _handleReadVarLenUEnumFieldSaveValState();
    _StateHandlingReaction _handleReadVarLenUEnumFieldWithRoleSaveValState();
    _StateHandlingReaction _handleReadVarLenSEnumFieldState();
    _StateHandlingReaction _handleReadVarLenSEnumFieldSaveValState();
    _StateHandlingReaction _handleReadFixedLenMetadataStreamUuidByteUIntFieldBa8State();
    _StateHandlingReaction _handleReadFixedLenMetadataStreamUuidByteUEnumFieldBa8State();

    /* Helpers for state handlers */
    _StateHandlingReaction _handleCommonBeginReadScopeState(ir::FieldLocScope scope);
    _StateHandlingReaction _handleCommonEndReadScopeState(ir::FieldLocScope scope);
    void _handleCommonBeginReadStructFieldState();
    _StateHandlingReaction _handleCommonBeginReadArrayFieldState(unsigned long long len,
                                                                 const ArrayFc& arrayFc);
    _StateHandlingReaction _handleCommonBeginReadStrBlobFieldState(unsigned long long len,
                                                                   _State contentState,
                                                                   const Fc& fc);
    _StateHandlingReaction _handleCommonBeginReadStaticLenBlobFieldState(_State contentState);
    void _handleCommonAfterEventRecordCommonCtxScopeState();
    void _handleCommonAfterEventRecordSpecCtxScopeState();

    /*
     * Common compound field reading end state handler using `item`.
     */
    template <typename ItemT>
    _StateHandlingReaction _handleCommonEndReadCompoundFieldState(ItemT& item)
    {
        /* Update for user */
        BT_ASSERT_DBG(this->_stackTop().fc);
        this->_setFieldItemFcAndUpdateForUser(item, *this->_stackTop().fc);

        /* Current stack frame isn't needed anymore */
        this->_stackPop();

        /* Next: read next field */
        this->_prepareToReadNextField();
        return _StateHandlingReaction::STOP;
    }

    /*
     * Reads the next bytes, setting the beginning and end pointers to
     * `ByteT` of `item` to the result.
     *
     * This method doesn't modify the current state and number of stack
     * frames.
     */
    template <typename ByteT, typename ItemT>
    void _handleCommonReadBytesNoNextState(ItemT& item)
    {
        using namespace bt2_common::literals::datalen;

        BT_ASSERT_DBG(!_mHeadOffsetInCurPkt.hasExtraBits());

        auto& top = this->_stackTop();

        BT_ASSERT_DBG(top.elemIndex < top.len);

        /* Require at least one byte of packet content */
        this->_requireContentData(1_bytes);
        BT_ASSERT_DBG(this->_remainingBufLen() >= 1_bytes);

        /* Set beginning and end pointers */
        const auto begin = this->_bufAtHead();
        const auto end = begin + std::min(this->_remainingBufLen().bytes(),
                                          static_cast<unsigned long long>(top.len - top.elemIndex));

        /* Make sure the section is completely part of the packet content */
        const auto sectionLen = bt2_common::DataLen::fromBytes(end - begin);

        if (sectionLen > this->_remainingPktContentLen()) {
            std::ostringstream ss;

            ss << sectionLen.bytes() << " string field substring or BLOB field section bytes "
               << " required at this point, but only " << *this->_remainingPktContentLen()
               << " bits of packet content remain.";
            this->_throwDecodingError(ss);
        }

        /* Update for user */
        item._mBegin = reinterpret_cast<const ByteT *>(begin);
        item._mEnd = reinterpret_cast<const ByteT *>(end);
        BT_ASSERT_DBG(sectionLen >= 1_bytes);
        this->_updateForUser(item);

        /* Mark the section as consumed */
        this->_consumeAvailData(sectionLen);

        /* Update `top.elemIndex` */
        top.elemIndex += sectionLen.bytes();
        BT_ASSERT_DBG(top.elemIndex <= top.len);
    }

    /*
     * Reads the next bytes, setting the beginning and end pointers to
     * `ByteT` of `item` to the result.
     *
     * This method calls _restoreState() when there aren't any more
     * bytes to read.
     */
    template <typename ByteT, typename ItemT>
    _StateHandlingReaction _handleCommonReadBytesState(ItemT& item)
    {
        this->_handleCommonReadBytesNoNextState<ByteT>(item);

        if (this->_stackTop().elemIndex == this->_stackTop().len) {
            /* Next: end reading string/BLOB field */
            this->_restoreState();
        }

        return _StateHandlingReaction::STOP;
    }

    /*
     * Common variant field (of concrete class `VarFcT`) reading
     * beginning state handler using `item`.
     */
    template <typename VarFcT, typename ItemT>
    _StateHandlingReaction _handleCommonBeginReadVariantField(ItemT& item)
    {
        auto& varFc = static_cast<const VarFcT&>(*this->_stackTop().fc);

        /* A variant field always contains a single field */
        this->_stackTop().len = 1;

        /* Update for user */
        this->_setFieldItemFcAndUpdateForUser(item, varFc);

        /* Find selected option */
        BT_ASSERT_DBG(varFc.savedDepValIndex());
        item._mSelVal = this->_savedVal<typename VarFcT::SelVal>(*varFc.savedDepValIndex());

        const auto optIt = varFc.findOptBySelVal(item._mSelVal);

        if (optIt == varFc.end()) {
            std::ostringstream ss;

            ss << "No variant field option selected by the selector value " << item._mSelVal << '.';
            this->_throwDecodingError(ss);
        }

        item._mSelectedOptIndex = optIt - varFc.begin();

        /* Next: read the selected field */
        this->_prepareToReadField(optIt->fc());
        return _StateHandlingReaction::STOP;
    }

    /*
     * Common optional field (of concrete class `OptFcT`) reading
     * beginning state handler using `item`.
     */
    template <typename OptFcT, typename ItemT>
    _StateHandlingReaction _handleCommonBeginReadOptionalField(ItemT& item)
    {
        auto& optFc = static_cast<const OptFcT&>(*this->_stackTop().fc);

        /* Update for user */
        this->_setFieldItemFcAndUpdateForUser(item, optFc);

        /* Check whether or not the optional field is enabled */
        BT_ASSERT_DBG(optFc.savedDepValIndex());
        item._mSelVal = this->_savedVal<typename OptFcT::SelVal>(*optFc.savedDepValIndex());
        item._mIsEnabled = optFc.isEnabledBySelVal(item._mSelVal);

        if (item._mIsEnabled) {
            /* Next: read the real field */
            this->_stackTop().len = 1;
            this->_prepareToReadField(optFc.fc());
        } else {
            /*
             * Next: end reading optional field.
             *
             * The handler of the restored state needs
             * `this->_stackTop().fc` and therefore calls _stackPop()
             * itself.
             */
            this->_restoreState();
        }

        return _StateHandlingReaction::STOP;
    }

    static constexpr const char *_byteOrderStr(const ir::ByteOrder byteOrder) noexcept
    {
        return byteOrder == ir::ByteOrder::BIG ? "big-endian" : "little-endian";
    }

    /*
     * If `*iter._mHeadOffsetInCurPkt` is not a multiple of 8 and
     * `fc.byteOrder` and `iter._mLastFixedLenBitArrayFieldByteOrder`
     * aren't compatible, this method throws `DecodingError`.
     */
    static void _checkLastFixedLenBitArrayFieldByteOrder(const ItemSeqIter& iter,
                                                         const FixedLenBitArrayFc& fc)
    {
        if (iter._mHeadOffsetInCurPkt.hasExtraBits() && iter._mLastFixedLenBitArrayFieldByteOrder &&
            fc.byteOrder() != *iter._mLastFixedLenBitArrayFieldByteOrder) {
            /*
             * A fixed-length bit array field which doesn't start on a
             * byte boundary must have the same byte order as the
             * previous fixed-length bit array field.
             */
            std::ostringstream ss;

            ss << "Two contiguous fixed-length bit array fields which aren't "
               << "byte-aligned don't share the same byte order: "
               << ItemSeqIter::_byteOrderStr(*iter._mLastFixedLenBitArrayFieldByteOrder)
               << " followed with " << ItemSeqIter::_byteOrderStr(fc.byteOrder()) << '.';
            iter._throwDecodingError(ss);
        }
    }

    /*
     * Reads a fixed-length integer field.
     *
     * `LenBitsV` is either:
     *
     * 8, 16, 32, or 64:
     *     Length, in bits, of the integer field to field to read.
     *
     *     `fc.align()` must be greater than or equal to 8.
     *
     *     `fc.len()` must be equal to `LenBitsV`.
     *
     * 0:
     *     Use `fc.len()`.
     *
     * `ByteOrderV` is the byte order of the integer field to read. It
     * must be equal to `fc.byteOrder()`.
     *
     * Checks and updates `_mLastFixedLenBitArrayFieldByteOrder` if
     * needed.
     *
     * Marks the fixed-length integer field bits as consumed.
     *
     * Returns the decoded value, of type `unsigned long long` or `long
     * long`.
     */
    template <bool IsSignedV, std::size_t LenBitsV, ir::ByteOrder ByteOrderV>
    internal::ReadFixedLenIntFuncRetT<IsSignedV> _readFixedLenIntField(const FixedLenBitArrayFc& fc)
    {
        static_assert(LenBitsV == 0 || LenBitsV == 8 || LenBitsV == 16 || LenBitsV == 32 ||
                          LenBitsV == 64,
                      "`LenBitsV` is 0, 8, 16, 32, or 64.");

        BT_ASSERT_DBG(LenBitsV == 0 || *fc.len() == LenBitsV);
        BT_ASSERT_DBG(LenBitsV == 0 || fc.align() >= 8);
        BT_ASSERT_DBG((*fc.len() == 8 && fc.align() >= 8) || fc.byteOrder() == ByteOrderV);

        /* Align head for fixed-length bit array field */
        this->_alignHead(fc);

        /*
         * Require enough packet content to read the whole fixed-length
         * bit array field.
         */
        this->_requireContentData(fc.len());

        /* Read the field */
        const auto val =
            internal::ReadFixedLenIntFunc<ByteOrderV, IsSignedV, LenBitsV>::read(*this, fc);

        /* Set last fixed-length bit array field byte order */
        _mLastFixedLenBitArrayFieldByteOrder = fc.byteOrder();

        /* Mark the fixed-length bit array field as consumed */
        this->_consumeAvailData(fc.len());

        /* Return decoded value */
        return val;
    }

    /*
     * Common fixed-length integer field state handler using `item`.
     *
     * This method doesn't update the _value_ of `item`.
     *
     * The `IsSignedV`, `LenBitsV`, and `ByteOrderV` template parameters
     * are the same as for the _readFixedLenIntField() method template.
     *
     * Returns the decoded value, of type `unsigned long long` or `long
     * long`.
     */
    template <bool IsSignedV, std::size_t LenBitsV, ir::ByteOrder ByteOrderV, typename ItemT>
    internal::ReadFixedLenIntFuncRetT<IsSignedV> _handleCommonReadFixedLenIntFieldState(ItemT& item)
    {
        /* Read the fixed-length integer field */
        const auto val = this->_readFixedLenIntField<IsSignedV, LenBitsV, ByteOrderV>(
            _mCurScalarFc->asFixedLenBitArray());

        /* Update for user */
        this->_setFieldItemFcAndUpdateForUser(item, *_mCurScalarFc);

        /* Return decoded value */
        return val;
    }

    /*
     * Same as the one above, but also prepares to read the next field.
     */
    template <bool IsSignedV, std::size_t LenBitsV, ir::ByteOrder ByteOrderV, typename ItemT>
    internal::ReadFixedLenIntFuncRetT<IsSignedV>
    _handleCommonReadFixedLenIntFieldStateAndPrepareToReadNextField(ItemT& item)
    {
        const auto val =
            this->_handleCommonReadFixedLenIntFieldState<IsSignedV, LenBitsV, ByteOrderV>(item);

        /* Next: read next field */
        this->_prepareToReadNextField();

        /* Return decoded value */
        return val;
    }

    /*
     * Handles a single unsigned integer field role `role` using the
     * decoded unsigned integer value `val` having the length `len`.
     *
     * This method may change the current state to
     * `_State::SET_PKT_MAGIC_NUMBER_ITEM` or
     * `_State::SET_DEF_CLK_VAL_ITEM`.
     */
    void _handleUIntFieldRole(const ir::UIntFieldRole role, const bt2_common::DataLen len,
                              const unsigned long long val)
    {
        switch (role) {
        case ir::UIntFieldRole::PKT_MAGIC_NUMBER:
            /* Update for user */
            _mItems.pktMagicNumber._mVal = val;

            /* Next: set packet magic number item */
            this->_state(_State::SET_PKT_MAGIC_NUMBER_ITEM);
            break;
        case ir::UIntFieldRole::DATA_STREAM_CLS_ID:
        case ir::UIntFieldRole::EVENT_RECORD_CLS_ID:
            _mCurClsId = val;
            break;
        case ir::UIntFieldRole::DATA_STREAM_ID:
            _mItems.dataStreamInfo._mId = val;
            break;
        case ir::UIntFieldRole::PKT_TOTAL_LEN:
            _mCurPktExpectedLens.total = bt2_common::DataLen::fromBits(val);
            _mItems.pktInfo._mExpectedTotalLen = _mCurPktExpectedLens.total;
            break;
        case ir::UIntFieldRole::PKT_CONTENT_LEN:
            _mCurPktExpectedLens.content = bt2_common::DataLen::fromBits(val);
            _mItems.pktInfo._mExpectedContentLen = _mCurPktExpectedLens.content;
            break;
        case ir::UIntFieldRole::DEF_CLK_TS:
            /* Update clock value */
            this->_updateDefClkVal(val, len);

            /* Update for user */
            _mItems.defClkVal._mCycles = _mDefClkVal;

            /* Next: set default clock value item */
            this->_state(_State::SET_DEF_CLK_VAL_ITEM);
            break;
        case ir::UIntFieldRole::PKT_END_DEF_CLK_TS:
            _mItems.pktInfo._mEndDefClkVal = val;
            break;
        case ir::UIntFieldRole::DISC_EVENT_RECORD_COUNTER_SNAP:
            _mItems.pktInfo._mDiscErCounterSnap = val;
            break;
        case ir::UIntFieldRole::PKT_SEQ_NUM:
            _mItems.pktInfo._mSeqNum = val;
            break;
        default:
            bt_common_abort();
        }
    }

    /*
     * Returns the length of a current instance of `fc`.
     */
    bt2_common::DataLen _uIntFieldLen(const FixedLenBitArrayFc& fc) const noexcept
    {
        return fc.len();
    }

    /*
     * Returns the length of the current variable-length integer
     * instance.
     */
    bt2_common::DataLen _uIntFieldLen(const VarLenIntFc&) const noexcept
    {
        /* Variable-length integer field length is dynamic */
        return _mCurVarLenInt.len;
    }

    /*
     * Whether or not to save a decoded field value.
     */
    enum class _SaveVal
    {
        YES,
        NO,
    };

    /*
     * Whether or not a decoded field value has at least one role.
     */
    enum class _WithRole
    {
        YES,
        NO,
    };

    /*
     * Common unsigned integer field state handler, setting `item` from
     * `val`.
     *
     * `WithRoleV` indicates whether or not the unsigned integer field
     * has at least one role.
     *
     * `SaveValV` indicates whether or not to save the unsigned integer
     * field value.
     */
    template <typename FcT, _WithRole WithRoleV, _SaveVal SaveValV, typename ItemT>
    _StateHandlingReaction _handleCommonUIntFieldState(ItemT& item, const unsigned long long val)
    {
        BT_ASSERT_DBG(_mCurScalarFc);

        auto& intFc = static_cast<const FcT&>(*_mCurScalarFc);

        /*
         * May be a length/selector of some upcoming dynamic length,
         * optional, or variant field.
         */
        if (SaveValV == _SaveVal::YES) {
            this->_saveVal(intFc.valSavingIndexes(), val);
        }

        /* Role? */
        if (WithRoleV == _WithRole::YES) {
            /* Keep the current state to detect a change */
            const auto prevState = _mState;

            /* Handle each role */
            for (auto& role : intFc.roles()) {
                this->_handleUIntFieldRole(role, this->_uIntFieldLen(intFc), val);
            }

            /*
             * _handleUIntFieldRole() may change the state to
             * `_State::SET_PKT_MAGIC_NUMBER_ITEM` or
             * `_State::SET_DEF_CLK_VAL_ITEM`.
             */
            if (_mState == prevState) {
                /* State didn't change; next: read next field */
                this->_prepareToReadNextField();
            }
        } else {
            /* Next: read next field */
            this->_prepareToReadNextField();
        }

        return _StateHandlingReaction::STOP;
    }

    /*
     * Common fixed-length unsigned integer field state handler.
     *
     * The `LenBitsV`, `ByteOrderV`, and `ItemT` template parameters are
     * the same as for the _handleCommonReadFixedLenIntFieldState()
     * method template.
     *
     * `WithRoleV` indicates whether or not the unsigned integer
     * field has at least one role.
     *
     * `SaveValV` indicates whether or not to save the unsigned integer
     * field value.
     */
    template <typename FcT, std::size_t LenBitsV, ir::ByteOrder ByteOrderV, _WithRole WithRoleV,
              _SaveVal SaveValV, typename ItemT>
    _StateHandlingReaction _handleCommonReadFixedLenUIntFieldState(ItemT& item)
    {
        /* Decode the unsigned integer value */
        const auto val =
            this->_handleCommonReadFixedLenIntFieldState<false, LenBitsV, ByteOrderV>(item);

        /* Update for user */
        item._val(val);

        /* Handle role and value saving */
        return this->_handleCommonUIntFieldState<FcT, WithRoleV, SaveValV>(item, val);
    }

    /*
     * Common fixed-length signed integer field state handler.
     *
     * The `LenBitsV`, `ByteOrderV`, and `ItemT` template parameters are
     * the same as for the _handleCommonReadFixedLenIntFieldState()
     * method template.
     *
     * `SaveValV` indicates whether or not to save the signed integer
     * field value.
     */
    template <typename FcT, std::size_t LenBitsV, ir::ByteOrder ByteOrderV, _SaveVal SaveValV,
              typename ItemT>
    _StateHandlingReaction _handleCommonReadFixedLenSIntFieldState(ItemT& item)
    {
        /* Decode the signed integer value */
        const auto val =
            this->_handleCommonReadFixedLenIntFieldStateAndPrepareToReadNextField<true, LenBitsV,
                                                                                  ByteOrderV>(item);

        /* Update for user */
        item._val(val);

        /* May be a selector of some upcoming optional/variant field */
        if (SaveValV == _SaveVal::YES) {
            this->_saveVal(static_cast<const FcT&>(*_mCurScalarFc).valSavingIndexes(), val);
        }

        return _StateHandlingReaction::STOP;
    }

    /*
     * Common fixed-length boolean field state handler.
     *
     * The `LenBitsV`, `ByteOrderV`, and `ItemT` template parameters are
     * the same as for the _handleCommonReadFixedLenIntFieldState()
     * method template.
     *
     * `SaveValV` indicates whether or not to save the boolean field
     * value.
     */
    template <std::size_t LenBitsV, ir::ByteOrder ByteOrderV, _SaveVal SaveValV, typename ItemT>
    _StateHandlingReaction _handleCommonReadFixedLenBoolFieldState(ItemT& item)
    {
        /* Decode the boolean value as an unsigned integer */
        const auto val =
            this->_handleCommonReadFixedLenIntFieldStateAndPrepareToReadNextField<false, LenBitsV,
                                                                                  ByteOrderV>(item);

        /* Update for user */
        item._val(val);

        /* May be a selector of some upcoming optional field */
        if (SaveValV == _SaveVal::YES) {
            this->_saveVal(_mCurScalarFc->asFixedLenBool().valSavingIndexes(), val);
        }

        return _StateHandlingReaction::STOP;
    }

    /*
     * Common fixed-length floating-point number field state handler.
     *
     * The `LenBitsV` and `ByteOrderV` template parameters are the same
     * as for the _handleCommonReadFixedLenIntFieldState() method
     * template.
     *
     * `FloatT` must be either `float` or `double`.
     */
    template <std::size_t LenBitsV, ir::ByteOrder ByteOrderV, typename FloatT>
    _StateHandlingReaction _handleCommonReadFixedLenFloatFieldState()
    {
        static_assert(std::is_same<FloatT, float>::value || std::is_same<FloatT, double>::value,
                      "`FloatT` is `float` or `double`.");

        /* Decode the floating-point number value as an unsigned integer */
        const auto val = this->_handleCommonReadFixedLenIntFieldStateAndPrepareToReadNextField<
            false, LenBitsV, ByteOrderV>(_mItems.fixedLenFloatField);

        /* Update for user */
        {
            /* Check IEEE-754 binary compatibility */
            using UIntT = typename std::conditional<std::is_same<FloatT, float>::value,
                                                    std::uint32_t, std::uint64_t>::type;

            static_assert(std::numeric_limits<FloatT>::is_iec559,
                          "`FloatT` fulfills the requirements of IEC 559.");
            static_assert(sizeof(FloatT) == sizeof(UIntT),
                          "Size of `FloatT` and of its equivalent integral type match in union.");
            static_assert(
                std::alignment_of<FloatT>::value == std::alignment_of<UIntT>::value,
                "Alignment of `FloatT` and of its equivalent integral type match in union.");

            /* Convert unsigned integer value to floating-point number value */
            union
            {
                FloatT f;
                UIntT u;
            } u;

            u.u = static_cast<UIntT>(val);

            /* Update for user */
            _mItems.fixedLenFloatField._val(static_cast<double>(u.f));
        }

        return _StateHandlingReaction::STOP;
    }

    /*
     * Common fixed-length bit array field state handler.
     *
     * The `LenBitsV`, `ByteOrderV`, and `ItemT` template parameters are
     * the same as for the _handleCommonReadFixedLenIntFieldState()
     * method template.
     */
    template <std::size_t LenBitsV, ir::ByteOrder ByteOrderV, typename ItemT>
    _StateHandlingReaction _handleCommonReadFixedLenBitArrayFieldState(ItemT& item)
    {
        /* Read bit array value as an unsigned integer */
        const auto val =
            this->_handleCommonReadFixedLenIntFieldStateAndPrepareToReadNextField<false, LenBitsV,
                                                                                  ByteOrderV>(item);

        /* Update for user */
        item._val(val);

        return _StateHandlingReaction::STOP;
    }

    /*
     * Common fixed-length metadata stream UUID byte unsigned integer
     * field state handler updating `item`.
     *
     * When there aren't any more fields to read, this method sets the
     * current state to `_State::SET_METADATA_STREAM_UUID_ITEM`.
     */
    template <typename ItemT>
    _StateHandlingReaction _handleCommonFixedLenMetadataStreamUuidByteUIntFieldBa8State(ItemT& item)
    {
        /* Read byte as an unsigned integer */
        const auto val =
            this->_handleCommonReadFixedLenIntFieldState<false, 8, ir::ByteOrder::BIG>(item);

        /* Update for user */
        item._val(val);

        /* Set metadata stream UUID byte */
        auto& top = this->_stackTop();

        _mCurMetadataStreamUuid[top.elemIndex] = static_cast<std::uint8_t>(val);

        /* Next byte */
        ++top.elemIndex;

        /*
         * Next step depends on whether or not we're done reading all
         * the metadata stream UUID bytes.
         */
        if (top.elemIndex == _mItems.metadataStreamUuid._mUuid.size()) {
            /* Update for user */
            _mItems.metadataStreamUuid._mUuid = bt2_common::Uuid {_mCurMetadataStreamUuid.data()};

            /* Next: set metadata stream UUID item */
            this->_state(_State::SET_METADATA_STREAM_UUID_ITEM);
        }

        return _StateHandlingReaction::STOP;
    }

    /*
     * Appends the single LEB128 byte `byte` to `_mCurVarLenInt.val` and
     * updates `_mCurVarLenInt.len` accordingly.
     */
    void _appendVarLenIntByte(const std::uint8_t byte)
    {
        using namespace bt2_common::literals::datalen;

        /* Validate upcoming variable-length integer length */
        if ((_mCurVarLenInt.len + 7_bits) > 64_bits) {
            this->_throwDecodingError(
                "Unsupported oversized (more than 64 bits of data) variable-length integer field.");
        }

        /* Mark this byte as consumed immediately */
        this->_consumeAvailData(8_bits);

        /* Update unsigned integer value, clearing the continuation bit */
        _mCurVarLenInt.val |= (static_cast<unsigned long long>(byte & 0x7f) << *_mCurVarLenInt.len);

        /* Update current variable-length integer length */
        _mCurVarLenInt.len += 7_bits;
    }

    /*
     * Common variable-length unsigned integer field state handler
     * updating `item`.
     */
    template <bool IsSignedV, typename ItemT>
    void _handleCommonVarLenIntFieldState(ItemT& item)
    {
        BT_ASSERT_DBG(_mCurScalarFc);
        this->_alignHead(*_mCurScalarFc);

        while (true) {
            /*
             * Read a single byte, and then:
             *
             * If the variable-length integer is not ended:
             *     Continue.
             *
             * Otherwise:
             *     Set the variable-length integer element and read the
             *     next field.
             *
             * See <https://en.wikipedia.org/wiki/LEB128>.
             */
            BT_ASSERT_DBG(!_mHeadOffsetInCurPkt.hasExtraBits());

            /* Require at least one byte */
            this->_requireContentData(bt2_common::DataLen::fromBytes(1));

            /* Read current byte */
            const auto byte = *this->_bufAtHead();

            if ((byte & 0x80) == 0) {
                /* This is the last byte */
                this->_appendVarLenIntByte(byte);

                /*
                 * Update for user.
                 *
                 * `_headOffsetInItemSeq()` now returns the offset at
                 * the _end_ of the variable-length integer; the
                 * iterator user expects its beginning offset.
                 */
                item._val(internal::VarLenIntFieldVal<IsSignedV>::val(_mCurVarLenInt.len,
                                                                      _mCurVarLenInt.val));
                item._mLen = _mCurVarLenInt.len;
                this->_updateForUser(item, this->_headOffsetInItemSeq() - item.fieldLen());

                /*
                 * Any state handler which calls this method template
                 * may be reentered as is. This may happen if the
                 * _requireContentData() call above throws
                 * `bt2_common::TryAgain`, for example.
                 *
                 * This means there's no initial setup to read a
                 * variable-length integer field: the state handlers
                 * just call this method template to start _and_ to
                 * continue.
                 *
                 * Because of this, and because both
                 * `_mCurVarLenInt.len` and `_mCurVarLenInt.val` must be
                 * zero before starting to read a variable-length
                 * integer field, we reset them here for the next
                 * variable-length integer field reading operation.
                 *
                 * _resetForNewPkt() also resets both variables before
                 * starting to read a packet.
                 */
                _mCurVarLenInt.val = 0;
                _mCurVarLenInt.len = bt2_common::DataLen::fromBits(0);

                /* Next: read next field */
                this->_prepareToReadNextField();
                return;
            }

            /* Not the last byte */
            this->_appendVarLenIntByte(byte);
        }

        bt_common_abort();
    }

    /*
     * Common variable-length unsigned integer field state handler.
     *
     * `WithRoleV` indicates whether or not the unsigned integer
     * field has at least one role.
     *
     * `SaveValV` indicates whether or not to save the unsigned integer
     * field value.
     */
    template <typename FcT, _WithRole WithRoleV, _SaveVal SaveValV, typename ItemT>
    _StateHandlingReaction _handleCommonReadVarLenUIntFieldState(ItemT& item)
    {
        /* This call sets the value of `item` */
        this->_handleCommonVarLenIntFieldState<false>(item);

        /*
         * Handle role and value saving.
         *
         * We can't use `_mCurVarLenInt.val` here because the
         * successful _handleCommonVarLenIntFieldState() call above
         * reset it.
         */
        return this->_handleCommonUIntFieldState<FcT, WithRoleV, SaveValV>(item, item.val());
    }

    /*
     * Common variable-length signed integer field state handler.
     *
     * `SaveValV` indicates whether or not to save the signed integer
     * field value.
     */
    template <typename FcT, _SaveVal SaveValV, typename ItemT>
    _StateHandlingReaction _handleCommonReadVarLenSIntFieldState(ItemT& item)
    {
        /* This call sets the value of `item` */
        this->_handleCommonVarLenIntFieldState<true>(item);

        /* May be a selector of some upcoming optional/variant field */
        if (SaveValV == _SaveVal::YES) {
            /*
             * We can't use `_mCurVarLenInt.val` here because the
             * successful _handleCommonVarLenIntFieldState() call above
             * reset it.
             */
            this->_saveVal(static_cast<const FcT&>(*_mCurScalarFc).valSavingIndexes(), item.val());
        }

        return _StateHandlingReaction::STOP;
    }

    /*
     * This acts as an "infinite" data length value.
     *
     * We make it a multiple of eight bits so that, when there's no
     * expected total packet length, the check in
     * _handleSetPktInfoItemState() passes.
     */
    static constexpr bt2_common::DataLen _infDataLen() noexcept
    {
        return bt2_common::DataLen::fromBits(std::numeric_limits<unsigned long long>::max() &
                                             ~7ULL);
    }

    /* Underlying medium to request data from */
    Medium::UP _mMedium;

    /* Trace class */
    const TraceCls *_mTraceCls;

    /* Current state */
    _State _mState = _State::INIT;

    /* State to restore after having skipped padding bits */
    _State _mPostSkipPaddingState;

    /* Current data buffer */
    Buf _mBuf;

    /* Offset of current data buffer within current packet */
    bt2_common::DataLen _mBufOffsetInCurPkt = bt2_common::DataLen::fromBits(0);

    /* Offset of current packet beginning within its item sequence */
    bt2_common::DataLen _mCurPktOffsetInItemSeq = bt2_common::DataLen::fromBits(0);

    /* Head offset within current packet */
    bt2_common::DataLen _mHeadOffsetInCurPkt = bt2_common::DataLen::fromBits(0);

    /* Current user-visible item offset within the item sequence */
    bt2_common::DataLen _mCurItemOffsetInItemSeq = bt2_common::DataLen::fromBits(0);

    /* True if this iterator is ended */
    bool _mIsEnded = false;

    /* Current item */
    const Item *_mCurItem = nullptr;

    /* Item instances */
    struct
    {
        PktBeginItem pktBegin;
        PktEndItem pktEnd;
        ScopeBeginItem scopeBegin;
        ScopeEndItem scopeEnd;
        PktContentBeginItem pktContentBegin;
        PktContentEndItem pktContentEnd;
        EventRecordBeginItem eventRecordBegin;
        EventRecordEndItem eventRecordEnd;
        PktMagicNumberItem pktMagicNumber;
        MetadataStreamUuidItem metadataStreamUuid;
        DataStreamInfoItem dataStreamInfo;
        PktInfoItem pktInfo;
        EventRecordInfoItem eventRecordInfo;
        DefClkValItem defClkVal;
        FixedLenBitArrayFieldItem fixedLenBitArrayField;
        FixedLenBoolFieldItem fixedLenBoolField;
        FixedLenSIntFieldItem fixedLenSIntField;
        FixedLenUIntFieldItem fixedLenUIntField;
        FixedLenSEnumFieldItem fixedLenSEnumField;
        FixedLenUEnumFieldItem fixedLenUEnumField;
        FixedLenFloatFieldItem fixedLenFloatField;
        VarLenSIntFieldItem varLenSIntField;
        VarLenUIntFieldItem varLenUIntField;
        VarLenSEnumFieldItem varLenSEnumField;
        VarLenUEnumFieldItem varLenUEnumField;
        NullTerminatedStrFieldBeginItem nullTerminatedStrFieldBegin;
        NullTerminatedStrFieldEndItem nullTerminatedStrFieldEnd;
        StrFieldSubstrItem strFieldSubstr;
        BlobFieldSectionItem blobFieldSection;
        StaticLenArrayFieldBeginItem staticLenArrayFieldBegin;
        StaticLenArrayFieldEndItem staticLenArrayFieldEnd;
        DynLenArrayFieldBeginItem dynLenArrayFieldBegin;
        DynLenArrayFieldEndItem dynLenArrayFieldEnd;
        StaticLenStrFieldBeginItem staticLenStrFieldBegin;
        StaticLenStrFieldEndItem staticLenStrFieldEnd;
        DynLenStrFieldBeginItem dynLenStrFieldBegin;
        DynLenStrFieldEndItem dynLenStrFieldEnd;
        StaticLenBlobFieldBeginItem staticLenBlobFieldBegin;
        StaticLenBlobFieldEndItem staticLenBlobFieldEnd;
        DynLenBlobFieldBeginItem dynLenBlobFieldBegin;
        DynLenBlobFieldEndItem dynLenBlobFieldEnd;
        StructFieldBeginItem structFieldBegin;
        StructFieldEndItem structFieldEnd;
        VariantFieldWithSIntSelBeginItem variantFieldWithSIntSelBegin;
        VariantFieldWithSIntSelEndItem variantFieldWithSIntSelEnd;
        VariantFieldWithUIntSelBeginItem variantFieldWithUIntSelBegin;
        VariantFieldWithUIntSelEndItem variantFieldWithUIntSelEnd;
        OptionalFieldWithBoolSelBeginItem optionalFieldWithBoolSelBegin;
        OptionalFieldWithBoolSelEndItem optionalFieldWithBoolSelEnd;
        OptionalFieldWithSIntSelBeginItem optionalFieldWithSIntSelBegin;
        OptionalFieldWithSIntSelEndItem optionalFieldWithSIntSelEnd;
        OptionalFieldWithUIntSelBeginItem optionalFieldWithUIntSelBegin;
        OptionalFieldWithUIntSelEndItem optionalFieldWithUIntSelEnd;
    } _mItems;

    /* Last fixed-length bit array field byte order */
    nonstd::optional<ir::ByteOrder> _mLastFixedLenBitArrayFieldByteOrder;

    /* Remaining padding bits to skip for alignment */
    bt2_common::DataLen _mRemainingLenToSkip = bt2_common::DataLen::fromBits(0);

    /* Current data stream class or event record class ID */
    nonstd::optional<unsigned long long> _mCurClsId;

    /* Current metadata stream UUID */
    std::array<bt2_common::Uuid::Val, bt2_common::Uuid::size()> _mCurMetadataStreamUuid;

    /* Current variable-length integer data */
    struct
    {
        /* Current value */
        unsigned long long val = 0;

        /* Current length */
        bt2_common::DataLen len = bt2_common::DataLen::fromBits(0);
    } _mCurVarLenInt;

    /* Current scalar field class */
    const Fc *_mCurScalarFc = nullptr;

    /* Current scope */
    struct
    {
        ir::FieldLocScope scope;
        const StructFc *fc = nullptr;
    } _mCurScope;

    struct
    {
        /* Expected total length of current packet */
        bt2_common::DataLen total = bt2_common::DataLen::fromBits(0);

        /* Expected content length of current packet */
        bt2_common::DataLen content = bt2_common::DataLen::fromBits(0);
    } _mCurPktExpectedLens;

    /* Stack */
    std::vector<_StackFrame> _mStack;

    /*
     * Saved values (dynamic-length field lengths and variant/optional
     * field selectors).
     */
    std::vector<unsigned long long> _mSavedVals;

    /* Current default clock value, if any */
    unsigned long long _mDefClkVal = 0;
};

namespace internal {

/*
 * Byte-aligned, byte-sized, big-endian specialization.
 */
template <bool IsSignedV, std::size_t LenBitsV>
struct ReadFixedLenIntFunc<ir::ByteOrder::BIG, IsSignedV, LenBitsV> final
{
    static ReadFixedLenIntFuncRetT<IsSignedV> read(const ItemSeqIter& iter,
                                                   const FixedLenBitArrayFc&) noexcept
    {
        return static_cast<ReadFixedLenIntFuncRetT<IsSignedV>>(
            bt2_common::readFixedLenIntBe<bt2_common::StdIntT<LenBitsV, IsSignedV>>(
                iter._bufAtHead()));
    }
};

/*
 * Byte-aligned, byte-sized, little-endian specialization.
 */
template <bool IsSignedV, std::size_t LenBitsV>
struct ReadFixedLenIntFunc<ir::ByteOrder::LITTLE, IsSignedV, LenBitsV> final
{
    static ReadFixedLenIntFuncRetT<IsSignedV> read(const ItemSeqIter& iter,
                                                   const FixedLenBitArrayFc&) noexcept
    {
        return static_cast<ReadFixedLenIntFuncRetT<IsSignedV>>(
            bt2_common::readFixedLenIntLe<bt2_common::StdIntT<LenBitsV, IsSignedV>>(
                iter._bufAtHead()));
    }
};

/*
 * Any alignment, any length, big-endian specialization.
 */
template <bool IsSignedV>
struct ReadFixedLenIntFunc<ir::ByteOrder::BIG, IsSignedV, 0> final
{
    static ReadFixedLenIntFuncRetT<IsSignedV> read(const ItemSeqIter& iter,
                                                   const FixedLenBitArrayFc& fc) noexcept
    {
        ItemSeqIter::_checkLastFixedLenBitArrayFieldByteOrder(iter, fc);

        ReadFixedLenIntFuncRetT<IsSignedV> val;

        bt_bitfield_read_be(iter._bufAtHead(), std::uint8_t,
                            iter._mHeadOffsetInCurPkt.extraBitCount(), *fc.len(), &val);
        return val;
    }
};

/*
 * Any alignment, any length, little-endian specialization.
 */
template <bool IsSignedV>
struct ReadFixedLenIntFunc<ir::ByteOrder::LITTLE, IsSignedV, 0> final
{
    static ReadFixedLenIntFuncRetT<IsSignedV> read(const ItemSeqIter& iter,
                                                   const FixedLenBitArrayFc& fc) noexcept
    {
        ItemSeqIter::_checkLastFixedLenBitArrayFieldByteOrder(iter, fc);

        ReadFixedLenIntFuncRetT<IsSignedV> val;

        bt_bitfield_read_le(iter._bufAtHead(), std::uint8_t,
                            iter._mHeadOffsetInCurPkt.extraBitCount(), *fc.len(), &val);
        return val;
    }
};

} /* namespace internal */
} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_ITEM_SEQ_ITEM_SEQ_ITER_HPP */
