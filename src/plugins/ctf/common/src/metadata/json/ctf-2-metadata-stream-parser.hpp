/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _CTF_SRC_METADATA_JSON_CTF_2_METADATA_STREAM_PARSER_HPP
#define _CTF_SRC_METADATA_JSON_CTF_2_METADATA_STREAM_PARSER_HPP

#include <cstdint>
#include <memory>
#include <sstream>
#include <babeltrace2/babeltrace.h>

#include "cpp-common/uuid.hpp"
#include "cpp-common/data-len.hpp"
#include "cpp-common/optional.hpp"
#include "../ctf-ir.hpp"
#include "../metadata-stream-parser.hpp"
#include "cpp-common/log-cfg.hpp"
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
     * If `selfComp` isn't `nullptr`, then the parser uses it each time
     * you call parseSection() to finalize the current trace class.
     */
    explicit Ctf2MetadataStreamParser(bt_self_component *selfComp,
                                      const bt2_common::LogCfg& logCfg);

private:
    void _parseSection(const uint8_t *begin, const uint8_t *end) override;

    /*
     * Parses one or more complete fragments between `begin` and `end`,
     * updating the internal state on success, or throwing
     * `bt2_common::TextParseError` otherwise.
     */
    void _parseFragments(const std::uint8_t *begin, const std::uint8_t *end);

    /*
     * Parses the JSON fragment between `begin` (included) and `end`
     * (excluded), updating the internal state on success, or throwing
     * `bt2_common::TextParseError` on failure.
     */
    void _parseFragment(const std::uint8_t *begin, const std::uint8_t *end);

    /*
     * Handles the JSON fragment `jsonFragment`, updating the internal
     * state on success, or throwing `bt2_common::TextParseError` on
     * failure.
     */
    void _handleFragment(bt2_common::JsonVal::UP jsonFragment);

    /*
     * Validates the field roles of the JSON packet header field class
     * `jsonPktHeaderFc`.
     */
    void _validatePktHeaderFcRoles(const bt2_common::JsonObjVal& jsonPktHeaderFc);

    /*
     * Validates the field roles of the JSON trace class fragment
     * `jsonFragment`.
     */
    void _validateTraceClsFragmentRoles(const bt2_common::JsonObjVal& jsonFragment);

    /*
     * Handles the JSON trace class fragment `jsonFragment`, updating
     * the internal state on success, or throwing
     * `bt2_common::TextParseError` on failure.
     */
    void _handleTraceClsFragment(bt2_common::JsonVal::UP jsonFragment);

    /*
     * Handles the JSON clock class fragment `jsonFragment`, updating
     * the internal state on success, or throwing
     * `bt2_common::TextParseError` on failure.
     */
    void _handleClkClsFragment(const bt2_common::JsonObjVal& jsonFragment);

    /*
     * Validates that the JSON scope field class `jsonScopeFc` doesn't
     * contain a JSON unsigned integer field class having a default
     * clock timestamp role if `hasDefClkCls` is false.
     */
    void _validateDefClkTsRoles(const bt2_common::JsonObjVal& jsonScopeFc, bool hasDefClkCls);

    /*
     * Validates that the JSON data stream class fragment `jsonFragment`
     * doesn't contain a JSON unsigned integer field class having a
     * default clock timestamp role if `hasDefClkCls` is false.
     */
    void _validateDataStreamClsFragmentRoles(const bt2_common::JsonObjVal& jsonFragment,
                                             bool hasDefClkCls);

    /*
     * Handles the JSON data stream class fragment `jsonFragment`,
     * updating the internal state on success, or throwing
     * `bt2_common::TextParseError` on failure.
     */
    void _handleDataStreamClsFragment(bt2_common::JsonVal::UP jsonFragment);

    /*
     * Handles the JSON event record class fragment `jsonFragment`,
     * updating the internal state on success, or throwing
     * `bt2_common::TextParseError` on failure.
     */
    void _handleEventRecordClsFragment(const bt2_common::JsonObjVal& jsonFragment);

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
    Fc::UP _scopeFcOfJsonVal(const bt2_common::JsonObjVal& jsonVal, const std::string& key,
                             ir::FieldLocScope scope, const bt2_common::JsonVal *jsonTraceCls,
                             const bt2_common::JsonVal *jsonDataStreamCls,
                             const bt2_common::JsonVal *jsonEventRecordCls);

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
    Fc::UP _eventRecordClsScopeFcOfJsonVal(const bt2_common::JsonObjVal& jsonEventRecordCls,
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
    Fc::UP _dataStreamClsScopeFcOfJsonVal(const bt2_common::JsonObjVal& jsonDataStreamCls,
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
    Fc::UP _traceClsScopeFcOfJsonVal(const bt2_common::JsonObjVal& jsonTraceCls,
                                     const std::string& key);

    /*
     * Returns a text location with an offset of `at` relative to
     * `begin`, also considering `_mCurOffsetInStream`.
     */
    bt2_common::TextLoc _loc(const std::uint8_t * const begin,
                             const std::uint8_t * const at) const noexcept
    {
        return bt2_common::TextLoc {_mCurOffsetInStream.bytes() + (at - begin)};
    }

private:
    /* Current offset within the whole metadata stream */
    bt2_common::DataLen _mCurOffsetInStream = bt2_common::DataLen::fromBytes(0);

    /* Current fragment index */
    std::size_t _mCurFragmentIndex = 0;

    /* Fragment requirement */
    Ctf2JsonAnyFragmentValReq _mFragmentValReq;

    /* Default clock offset JSON value */
    bt2_common::JsonObjVal::UP _mDefClkOffsetVal;

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
    std::unordered_map<const DataStreamCls *, bt2_common::JsonVal::UP> _mJsonDataStreamClasses;
    bt2_common::JsonVal::UP _mJsonTraceCls;

    /* Logging configuration */
    bt2_common::LogCfg _mLogCfg;
};

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_JSON_CTF_2_METADATA_STREAM_PARSER_HPP */
