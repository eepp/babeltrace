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
#include "ctf-2-fc-builder.hpp"
#include "logging-obj.hpp"

namespace ctf {
namespace src {

/*
 * CTF 2 metadata stream (JSON text sequence) parser.
 *
 * Build an instance of `Ctf2MetadataStreamParser`, and then call
 * parseSection() as often as needed with one or more _complete_ CTF 2
 * fragments.
 */
class Ctf2MetadataStreamParser final : public MetadataStreamParser, public LoggingObj
{
public:
    /*
     * Builds a CTF 2 metadata stream parser.
     *
     * If `selfComp` isn't `nullptr`, then the parser uses it each time
     * you call parseSection() to finalize the current trace class.
     */
    explicit Ctf2MetadataStreamParser(const ClkClsCfg& clkClsCfg, bt_self_component *selfComp,
                                      const bt2_common::LogCfg& logCfg);

    /*
     * Parses the whole CTF 2 metadata stream between `begin` and `end`
     * and returns the resulting trace class and optional metadata
     * stream UUID on success, or appends a cause to the error of the
     * current thread and throws `bt2_common::Error` otherwise.
     */
    static ParseRet parse(const ClkClsCfg& clkClsCfg, bt_self_component *selfComp,
                          const uint8_t *begin, const uint8_t *end,
                          const bt2_common::LogCfg& logCfg);

private:
    void _parseSection(const std::uint8_t *begin, const std::uint8_t *end) override;

    /*
     * Parses one or more complete fragments between `begin` and `end`,
     * updating the internal state on success, or appending a cause to
     * the error of the current thread and throwing `bt2_common::Error`
     * otherwise.
     */
    void _parseFragments(const std::uint8_t *begin, const std::uint8_t *end);

    /*
     * Parses the JSON fragment between `begin` (included) and `end`
     * (excluded), updating the internal state on success, or appending
     * a cause to the error of the current thread and throwing
     * `bt2_common::Error` on failure.
     */
    void _parseFragment(const std::uint8_t *begin, const std::uint8_t *end);

    /*
     * Handles the JSON fragment `jsonFragment`, updating the internal
     * state on success, or appending a cause to the error of the
     * current thread and throwing `bt2_common::Error` on failure.
     */
    void _handleFragment(bt2_common::JsonVal::UP jsonFragment);

    /*
     * Handles the JSON field class alias fragment `jsonFragment`,
     * updating the internal state on success, or appending a cause to
     * the error of the current thread and throwing `bt2_common::Error`
     * on failure.
     */
    void _handleFcAliasFragment(bt2_common::JsonVal::UP jsonFragment);

    /*
     * Forwards to validateScopeFcRoles() using the log configuration
     * and text location string format of this parser.
     *
     * Appends a cause to the error of the current thread and throws
     * `bt2_common::Error` on error.
     */
    void _validateScopeFcRoles(const Fc& fc, const ir::UIntFieldRoles& allowedRoles,
                               bool allowMetadataStreamUuidRole);

    /*
     * Validates the field roles of the packet header field class `fc`.
     */
    void _validatePktHeaderFcRoles(const Fc& fc);

    /*
     * Handles the JSON trace class fragment `jsonFragment`, updating
     * the internal state on success, or appending a cause to the error
     * of the current thread and throwing `bt2_common::Error` on
     * failure.
     */
    void _handleTraceClsFragment(bt2_common::JsonVal::UP jsonFragment);

    /*
     * Handles the JSON clock class fragment `jsonFragment`, updating
     * the internal state on success, or appending a cause to the error
     * of the current thread and throwing `bt2_common::Error` on
     * failure.
     */
    void _handleClkClsFragment(const bt2_common::JsonObjVal& jsonFragment);

    /*
     * Validates that the field class `fc` doesn't contain an unsigned
     * integer field class having a default clock timestamp role if
     * `allowDefClkTsRole` is false.
     */
    void _validateClkTsRoles(const Fc& fc, bool allowClkTsRole);

    /*
     * Validates the roles of the packet context, event record header,
     * and common event record context field classes `pktCtxFc`,
     * `eventRecordHeaderFc`, and `commonEventRecordCtxFc`.
     */
    void _validateDataStreamClsRoles(const Fc *pktCtxFc, const Fc *eventRecordHeaderFc,
                                     const Fc *commonEventRecordCtxFc, bool allowDefClkTsRole);

    /*
     * Handles the JSON data stream class fragment `jsonFragment`,
     * updating the internal state on success, or appending a cause to
     * the error of the current thread and throwing `bt2_common::Error`
     * on failure.
     */
    void _handleDataStreamClsFragment(bt2_common::JsonVal::UP jsonFragment);

    /*
     * Validates the roles of specific event record context and event
     * record payload field classes `specCtxFc` and `payloadFc`.
     */
    void _validateEventRecordClsRoles(const Fc *specCtxFc, const Fc *payloadFc);

    /*
     * Handles the JSON event record class fragment `jsonFragment`,
     * updating the internal state on success, or appending a cause to
     * the error of the current thread and throwing `bt2_common::Error`
     * on failure.
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
     *     it, considering `pktHeaderFc`, `pktCtxFc`,
     *     `eventRecordHeaderFc`, `commonEventRecordCtxFc`,
     *     `specEventRecordCtxFc`, and `eventRecordPayloadFc` as the
     *     current packet header, packet context, event record header,
     *     common event record context, specific event record context,
     *     and event record payload field classes.
     */
    Fc::UP _scopeFcOfJsonVal(const bt2_common::JsonObjVal& jsonVal, const std::string& key,
                             ir::FieldLocScope scope, const Fc *pktHeaderFc = nullptr,
                             const Fc *pktCtxFc = nullptr, const Fc *eventRecordHeaderFc = nullptr,
                             const Fc *commonEventRecordCtxFc = nullptr,
                             const Fc *specEventRecordCtxFc = nullptr,
                             const Fc *eventRecordPayloadFc = nullptr);

    /*
     * If a JSON value has the key `key` in the JSON event record class
     * fragment value `jsonVal`:
     *     Returns `nullptr`.
     *
     * Otherwise:
     *     Converts `*jsonEventRecordCls[key]` to a scope field class
     *     and returns it, considering the current packet header field
     *     class, the field classes of `dataStreamCls`, and
     *     `specEventRecordCtxFc` and `eventRecordPayloadFc` as the
     *     current specific event record context and event record
     *     payload field classes.
     */
    Fc::UP _eventRecordClsScopeFcOfJsonVal(const bt2_common::JsonObjVal& jsonEventRecordCls,
                                           const std::string& key, ir::FieldLocScope scope,
                                           const DataStreamCls& dataStreamCls,
                                           const Fc *specEventRecordCtxFc = nullptr,
                                           const Fc *eventRecordPayloadFc = nullptr);

    /*
     * If a JSON value has the key `key` in the JSON data stream class
     * fragment value `jsonDataStreamCls`:
     *     Returns `nullptr`.
     *
     * Otherwise:
     *     Converts `*jsonDataStreamCls[key]` to a field class and
     *     returns it, considering the current packet header field
     *     class, and `pktCtxFc`, `eventRecordHeaderFc`, and
     *     `commonEventRecordCtxFc` as the current packet context, event
     *     record header, and common event record context field classes.
     */
    Fc::UP _dataStreamClsScopeFcOfJsonVal(const bt2_common::JsonObjVal& jsonDataStreamCls,
                                          const std::string& key, ir::FieldLocScope scope,
                                          const Fc *pktCtxFc = nullptr,
                                          const Fc *eventRecordHeaderFc = nullptr,
                                          const Fc *commonEventRecordCtxFc = nullptr);

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

    using LoggingObj::_locStr;

    std::string _locStr(const bt2_common::JsonVal& val) const
    {
        return this->_locStr(val.loc());
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

    /* Field class builder, which keeps track of field class aliases */
    Ctf2FcBuilder _mFcBuilder;

    /*  True if the tracer is LTTng (see _handleTraceClsFragment()) */
    bool _mIsLttng = false;
};

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_JSON_CTF_2_METADATA_STREAM_PARSER_HPP */
