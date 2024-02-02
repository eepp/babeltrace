/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _CTF_SRC_METADATA_JSON_CTF_2_METADATA_STREAM_PARSER_HPP
#define _CTF_SRC_METADATA_JSON_CTF_2_METADATA_STREAM_PARSER_HPP

#include <cstdint>

#include <babeltrace2/babeltrace.h>

#include "../ctf-ir.hpp"
#include "../metadata-stream-parser.hpp"
#include "val-req.hpp"

namespace ctf {
namespace src {

/*
 * CTF 2 metadata stream (JSON text sequence) parser.
 *
 * Build an instance of `Ctf2MetadataStreamParser`, and then call
 * parseSection() as often as needed with one or more complete CTF 2
 * fragments.
 */
class Ctf2MetadataStreamParser final : public MetadataStreamParser
{
public:
    /*
     * Builds a CTF 2 metadata stream parser.
     *
     * If `selfComp` isn't `empty`, then the parser uses it each time
     * you call parseSection() to finalize the current trace class.
     */
    explicit Ctf2MetadataStreamParser(const ClkClsCfg& clkClsCfg,
                                      bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp,
                                      const bt2c::Logger& parentLogger);

    /*
     * Parses the whole CTF 2 metadata stream in `buffer` and returns
     * the resulting trace class and optional metadata stream UUID on
     * success, or appends a cause to the error of the current thread
     * and throws `bt2c::Error` otherwise.
     */
    static ParseRet parse(const ClkClsCfg& clkClsCfg,
                          bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp,
                          bt2s::span<const std::uint8_t> buffer, const bt2c::Logger& parentLogger);

private:
    void _parseSection(bt2s::span<const std::uint8_t> buffer) override;

    /*
     * Parses one or more complete fragments in `buffer`, updating the
     * internal state on success, or appending a cause to the error of
     * the current thread and throwing `bt2c::Error` otherwise.
     */
    void _parseFragments(bt2s::span<const std::uint8_t> buffer);

    /*
     * Parses the JSON fragment in `buffer`, updating the internal state
     * on success, or appending a cause to the error of the current
     * thread and throwing `bt2c::Error` on failure.
     */
    void _parseFragment(bt2s::span<const std::uint8_t> buffer);

    /*
     * Handles the JSON fragment `jsonFragment`, updating the internal
     * state on success, or appending a cause to the error of the
     * current thread and throwing `bt2c::Error` on failure.
     */
    void _handleFragment(bt2c::JsonVal::UP jsonFragment);

    /*
     * Validates the field roles of the JSON packet header field class
     * `jsonPktHeaderFc`.
     */
    void _validatePktHeaderFcRoles(const bt2c::JsonObjVal& jsonPktHeaderFc);

    /*
     * Validates the field roles of the JSON trace class fragment
     * `jsonFragment`.
     */
    void _validateTraceClsFragmentRoles(const bt2c::JsonObjVal& jsonFragment);

    /*
     * Handles the JSON trace class fragment `jsonFragment`, updating
     * the internal state on success, or appending a cause to the error
     * of the current thread and throwing `bt2c::Error` on
     * failure.
     */
    void _handleTraceClsFragment(bt2c::JsonVal::UP jsonFragment);

    /*
     * Handles the JSON clock class fragment `jsonFragment`, updating
     * the internal state on success, or appending a cause to the error
     * of the current thread and throwing `bt2c::Error` on
     * failure.
     */
    void _handleClkClsFragment(const bt2c::JsonObjVal& jsonFragment);

    /*
     * Validates that the JSON scope field class `jsonScopeFc` doesn't
     * contain a JSON unsigned integer field class having a default
     * clock timestamp role if `hasDefClkCls` is false.
     */
    void _validateDefClkTsRoles(const bt2c::JsonObjVal& jsonScopeFc, bool hasDefClkCls);

    /*
     * Validates that the JSON data stream class fragment `jsonFragment`
     * doesn't contain a JSON unsigned integer field class having a
     * default clock timestamp role if `hasDefClkCls` is false.
     */
    void _validateDataStreamClsFragmentRoles(const bt2c::JsonObjVal& jsonFragment,
                                             bool hasDefClkCls);

    /*
     * Handles the JSON data stream class fragment `jsonFragment`,
     * updating the internal state on success, or appending a cause to
     * the error of the current thread and throwing `bt2c::Error`
     * on failure.
     */
    void _handleDataStreamClsFragment(bt2c::JsonVal::UP jsonFragment);

    /*
     * Handles the JSON event record class fragment `jsonFragment`,
     * updating the internal state on success, or appending a cause to
     * the error of the current thread and throwing `bt2c::Error`
     * on failure.
     */
    void _handleEventRecordClsFragment(const bt2c::JsonObjVal& jsonFragment);

    /*
     * Ensures that `*_mTraceCls` exists.
     */
    void _ensureExistingTraceCls();

    /*
     * If a JSON value has the key `key` in `jsonVal`:
     *     Returns `nullptr`.
     *
     * Otherwise:
     *     Converts `*jsonVal[key]` to a scope field class and returns
     *     it, considering the JSON trace class fragment value
     *     `jsonTraceCls`, the JSON data stream class fragment value
     *     `jsonDataStreamCls` and the JSON event record class fragment
     *     value `jsonEventRecordCls` as the conversion context.
     */
    Fc::UP _scopeFcOfJsonVal(const bt2c::JsonObjVal& jsonVal, const std::string& key,
                             ir::FieldLocScope scope, const bt2c::JsonVal *jsonTraceCls,
                             const bt2c::JsonVal *jsonDataStreamCls,
                             const bt2c::JsonVal *jsonEventRecordCls);

    /*
     * If a JSON value has the key `key` in the JSON event record class
     * fragment value `jsonVal`:
     *     Returns `nullptr`.
     *
     * Otherwise:
     *     Converts `*jsonEventRecordCls[key]` to a scope field class
     *     and returns it, considering the JSON trace class fragment
     *     value `_mJsonTraceCls`, the data stream class `dataStreamCls`
     *     and the JSON event record class fragment value
     *     `jsonEventRecordCls` as the conversion context.
     */
    Fc::UP _eventRecordClsScopeFcOfJsonVal(const bt2c::JsonObjVal& jsonEventRecordCls,
                                           const std::string& key, ir::FieldLocScope scope,
                                           const DataStreamCls& dataStreamCls);

    /*
     * If a JSON value has the key `key` in the JSON data stream class
     * fragment value `jsonDataStreamCls`:
     *     Returns `nullptr`.
     *
     * Otherwise:
     *     Converts `*jsonDataStreamCls[key]` to a field class and returns it,
     *     considering the JSON trace class fragment value
     *     `_mJsonTraceCls`, the JSON data stream class fragment value
     *     `jsonDataStreamCls` as the conversion context.
     */
    Fc::UP _dataStreamClsScopeFcOfJsonVal(const bt2c::JsonObjVal& jsonDataStreamCls,
                                          const std::string& key, ir::FieldLocScope scope);

    /*
     * If a JSON value has the key `key` in the JSON trace class
     * fragment value `jsonTraceCls`:
     *     Returns `nullptr`.
     *
     * Otherwise:
     *     Converts `*jsonTraceCls[key]` to a field class and returns
     *     it, considering the JSON trace class fragment value
     *     `jsonTraceCls` as the conversion context.
     */
    Fc::UP _traceClsScopeFcOfJsonVal(const bt2c::JsonObjVal& jsonTraceCls, const std::string& key);

    /*
     * Returns a text location with an offset of `at` relative to
     * the beginning of `buffer`, also considering `_mCurOffsetInStream`.
     *
     * `at` must be within `buffer`.
     */
    bt2c::TextLoc _loc(bt2s::span<const std::uint8_t> buffer,
                       const std::uint8_t * const at) const noexcept
    {
        BT_ASSERT_DBG(at >= buffer.begin());
        BT_ASSERT_DBG(at < buffer.end());

        return bt2c::TextLoc {_mCurOffsetInStream.bytes() + (at - buffer.begin())};
    }

private:
    /* Logging configuration */
    bt2c::Logger _mLogger;

    /* Current offset within the whole metadata stream */
    bt2c::DataLen _mCurOffsetInStream = bt2c::DataLen::fromBytes(0);

    /* Current fragment index */
    std::size_t _mCurFragmentIndex = 0;

    /* Fragment requirement */
    Ctf2JsonAnyFragmentValReq _mFragmentValReq;

    /* Default clock offset JSON value */
    bt2c::JsonObjVal::UP _mDefClkOffsetVal;

    /*
     * Map of clock class name to clock class object.
     *
     * Clock class fragments "float" in a CTF 2 metadata stream, in that
     * they aren't used yet, but could be afterwards through a reference
     * within a data stream class.
     *
     * This map stores them until the parser needs one for a data stream
     * class.
     */
    std::unordered_map<std::string, ClkCls::SP> _mClkClasses;

    /*
     * fcFromJsonVal() needs some JSON context (trace class, data stream
     * class, and event record class) to validate the length/selector
     * field classes (dependencies) of dependent (dynamic-length,
     * optional, and variant) field classes.
     *
     * The `_mJsonDataStreamClasses` member keeps a mapping of CTF IR
     * data stream classes (owned by `*_mTraceCls` below) to their
     * original JSON value. The `_mJsonTraceCls` member is possibly the
     * JSON value of `*_mTraceCls` (`*_mTraceCls` may exist without any
     * JSON value equivalent).
     *
     * When _handleEventRecordClsFragment() calls fcFromJsonVal(),
     * it passes:
     *
     * `jsonTraceCls` parameter:
     *     `_mJsonTraceCls.get()`
     *
     * `jsonDataStreamClsCls` parameter:
     *     The corresponding JSON value within
     *     `_mJsonDataStreamClasses`.
     *
     * `jsonEventRecordCls` parameter:
     *     The current JSON event record class fragment value.
     *
     * Those three JSON values constitute what's needed to find any
     * dependency. fcFromJsonVal() uses JSON values instead of CTF IR
     * objects because:
     *
     * • Finding a dependency within the current scope requires the JSON
     *   value, as the corresponding CTF IR object is currently being
     *   built and many members of CTF IR objects are immutable.
     *
     *   Using only JSON values makes it possible to apply the same
     *   scope traversing strategy, whether it's the current one or a
     *   previous one.
     *
     * • For text parsing error messages, the JSON values contain their
     *   original location within the metadata stream.
     *
     *   Using a CTF IR trace class and CTF IR data stream classes would
     *   require keeping mappings of CTF IR field classes to text
     *   locations.
     */
    std::unordered_map<const DataStreamCls *, bt2c::JsonVal::UP> _mJsonDataStreamClasses;
    bt2c::JsonVal::UP _mJsonTraceCls;

    /*  True if the tracer is LTTng (see _handleTraceClsFragment()) */
    bool _mIsLttng = false;
};

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_JSON_CTF_2_METADATA_STREAM_PARSER_HPP */
