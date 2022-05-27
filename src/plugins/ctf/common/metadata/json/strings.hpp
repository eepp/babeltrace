/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _CTF_METADATA_JSON_STRINGS_HPP
#define _CTF_METADATA_JSON_STRINGS_HPP

namespace ctf {
namespace json_strings {

static constexpr auto align = "alignment";
static constexpr auto bigEndian = "big-endian";
static constexpr auto byteOrder = "byte-order";
static constexpr auto clkCls = "clock-class";
static constexpr auto cycles = "cycles";
static constexpr auto dataStreamCls = "data-stream-class";
static constexpr auto dataStreamClsId = "data-stream-class-id";
static constexpr auto dataStreamId = "data-stream-id";
static constexpr auto defClkClsName = "default-clock-class-name";
static constexpr auto defClkTs = "default-clock-timestamp";
static constexpr auto descr = "description";
static constexpr auto discEventRecordCounterSnap = "discarded-event-record-counter-snapshot";
static constexpr auto dynLenArray = "dynamic-length-array";
static constexpr auto dynLenBlob = "dynamic-length-blob";
static constexpr auto dynLenStr = "dynamic-length-string";
static constexpr auto elemFc = "element-field-class";
static constexpr auto env = "environment";
static constexpr auto eventRecordCls = "event-record-class";
static constexpr auto eventRecordClsId = "event-record-class-id";
static constexpr auto eventRecordCommonCtx = "event-record-common-context";
static constexpr auto eventRecordCommonCtxFc = "event-record-common-context-field-class";
static constexpr auto eventRecordHeader = "event-record-header";
static constexpr auto eventRecordHeaderFc = "event-record-header-field-class";
static constexpr auto eventRecordPayload = "event-record-payload";
static constexpr auto eventRecordSpecCtx = "event-record-specific-context";
static constexpr auto extensions = "extensions";
static constexpr auto fc = "field-class";
static constexpr auto fixedLenBitArray = "fixed-length-bit-array";
static constexpr auto fixedLenBool = "fixed-length-boolean";
static constexpr auto fixedLenFloat = "fixed-length-floating-point-number";
static constexpr auto fixedLenSEnum = "fixed-length-signed-enumeration";
static constexpr auto fixedLenSInt = "fixed-length-signed-integer";
static constexpr auto fixedLenUEnum = "fixed-length-unsigned-enumeration";
static constexpr auto fixedLenUInt = "fixed-length-unsigned-integer";
static constexpr auto freq = "frequency";
static constexpr auto id = "id";
static constexpr auto len = "length";
static constexpr auto lenFieldLoc = "length-field-location";
static constexpr auto littleEndian = "little-endian";
static constexpr auto mappings = "mappings";
static constexpr auto mediaType = "media-type";
static constexpr auto memberClasses = "member-classes";
static constexpr auto metadataStreamUuid = "metadata-stream-uuid";
static constexpr auto minAlign = "minimum-alignment";
static constexpr auto name = "name";
static constexpr auto ns = "namespace";
static constexpr auto nullTerminatedStr = "null-terminated-string";
static constexpr auto offset = "offset";
static constexpr auto optional = "optional";
static constexpr auto opts = "options";
static constexpr auto originIsUnixEpoch = "origin-is-unix-epoch";
static constexpr auto payloadFc = "payload-field-class";
static constexpr auto pktContentLen = "packet-content-length";
static constexpr auto pktCtx = "packet-context";
static constexpr auto pktCtxFc = "packet-context-field-class";
static constexpr auto pktEndDefClkTs = "packet-end-default-clock-timestamp";
static constexpr auto pktHeader = "packet-header";
static constexpr auto pktHeaderFc = "packet-header-field-class";
static constexpr auto pktMagicNumber = "packet-magic-number";
static constexpr auto pktSeqNum = "packet-sequence-number";
static constexpr auto pktTotalLen = "packet-total-length";
static constexpr auto preamble = "preamble";
static constexpr auto precision = "precision";
static constexpr auto prefDispBase = "preferred-display-base";
static constexpr auto roles = "roles";
static constexpr auto seconds = "seconds";
static constexpr auto selFieldLoc = "selector-field-location";
static constexpr auto selFieldRanges = "selector-field-ranges";
static constexpr auto specCtxFc = "specific-context-field-class";
static constexpr auto staticLenArray = "static-length-array";
static constexpr auto staticLenBlob = "static-length-blob";
static constexpr auto staticLenStr = "static-length-string";
static constexpr auto structure = "structure";
static constexpr auto traceCls = "trace-class";
static constexpr auto type = "type";
static constexpr auto userAttrs = "user-attributes";
static constexpr auto uuid = "uuid";
static constexpr auto variant = "variant";
static constexpr auto varLenSEnum = "variable-length-signed-enumeration";
static constexpr auto varLenSInt = "variable-length-signed-integer";
static constexpr auto varLenUEnum = "variable-length-unsigned-enumeration";
static constexpr auto varLenUInt = "variable-length-unsigned-integer";
static constexpr auto version = "version";

} /* namespace json_strings */
} /* namespace ctf */

#endif /* _CTF_METADATA_JSON_STRINGS_HPP */
