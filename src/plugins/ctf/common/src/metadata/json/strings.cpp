/*
 * Copyright (c) 2022-2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include "strings.hpp"

namespace ctf {
namespace jsonstr {

constexpr const char *accuracy = "accuracy";
constexpr const char *align = "alignment";
constexpr const char *attrs = "attributes";
constexpr const char *bigEndian = "big-endian";
constexpr const char *bitOrder = "bit-order";
constexpr const char *byteOrder = "byte-order";
constexpr const char *clkCls = "clock-class";
constexpr const char *cycles = "cycles";
constexpr const char *dataStreamCls = "data-stream-class";
constexpr const char *dataStreamClsId = "data-stream-class-id";
constexpr const char *dataStreamId = "data-stream-id";
constexpr const char *defClkClsId = "default-clock-class-id";
constexpr const char *defClkTs = "default-clock-timestamp";
constexpr const char *descr = "description";
constexpr const char *discEventRecordCounterSnap = "discarded-event-record-counter-snapshot";
constexpr const char *dynLenArray = "dynamic-length-array";
constexpr const char *dynLenBlob = "dynamic-length-blob";
constexpr const char *dynLenStr = "dynamic-length-string";
constexpr const char *elemFc = "element-field-class";
constexpr const char *encoding = "encoding";
constexpr const char *env = "environment";
constexpr const char *eventRecordCls = "event-record-class";
constexpr const char *eventRecordClsId = "event-record-class-id";
constexpr const char *eventRecordCommonCtx = "event-record-common-context";
constexpr const char *eventRecordCommonCtxFc = "event-record-common-context-field-class";
constexpr const char *eventRecordHeader = "event-record-header";
constexpr const char *eventRecordHeaderFc = "event-record-header-field-class";
constexpr const char *eventRecordPayload = "event-record-payload";
constexpr const char *eventRecordSpecCtx = "event-record-specific-context";
constexpr const char *extensions = "extensions";
constexpr const char *fc = "field-class";
constexpr const char *fcAlias = "field-class-alias";
constexpr const char *fixedLenBitArray = "fixed-length-bit-array";
constexpr const char *fixedLenBitMap = "fixed-length-bit-map";
constexpr const char *fixedLenBool = "fixed-length-boolean";
constexpr const char *fixedLenFloat = "fixed-length-floating-point-number";
constexpr const char *fixedLenSInt = "fixed-length-signed-integer";
constexpr const char *fixedLenUInt = "fixed-length-unsigned-integer";
constexpr const char *flags = "flags";
constexpr const char *freq = "frequency";
constexpr const char *ftl = "first-to-last";
constexpr const char *id = "id";
constexpr const char *len = "length";
constexpr const char *lenFieldLoc = "length-field-location";
constexpr const char *littleEndian = "little-endian";
constexpr const char *ltf = "last-to-first";
constexpr const char *mappings = "mappings";
constexpr const char *mediaType = "media-type";
constexpr const char *memberClasses = "member-classes";
constexpr const char *metadataStreamUuid = "metadata-stream-uuid";
constexpr const char *minAlign = "minimum-alignment";
constexpr const char *name = "name";
constexpr const char *ns = "namespace";
constexpr const char *nullTerminatedStr = "null-terminated-string";
constexpr const char *offsetFromOrigin = "offset-from-origin";
constexpr const char *optional = "optional";
constexpr const char *opts = "options";
constexpr const char *origin = "origin";
constexpr const char *path = "path";
constexpr const char *payloadFc = "payload-field-class";
constexpr const char *pktContentLen = "packet-content-length";
constexpr const char *pktCtx = "packet-context";
constexpr const char *pktCtxFc = "packet-context-field-class";
constexpr const char *pktEndDefClkTs = "packet-end-default-clock-timestamp";
constexpr const char *pktHeader = "packet-header";
constexpr const char *pktHeaderFc = "packet-header-field-class";
constexpr const char *pktMagicNumber = "packet-magic-number";
constexpr const char *pktSeqNum = "packet-sequence-number";
constexpr const char *pktTotalLen = "packet-total-length";
constexpr const char *preamble = "preamble";
constexpr const char *precision = "precision";
constexpr const char *prefDispBase = "preferred-display-base";
constexpr const char *roles = "roles";
constexpr const char *seconds = "seconds";
constexpr const char *selFieldLoc = "selector-field-location";
constexpr const char *selFieldRanges = "selector-field-ranges";
constexpr const char *specCtxFc = "specific-context-field-class";
constexpr const char *staticLenArray = "static-length-array";
constexpr const char *staticLenBlob = "static-length-blob";
constexpr const char *staticLenStr = "static-length-string";
constexpr const char *structure = "structure";
constexpr const char *traceCls = "trace-class";
constexpr const char *type = "type";
constexpr const char *uid = "uid";
constexpr const char *unixEpoch = "unix-epoch";
constexpr const char *utf16Be = "utf-16be";
constexpr const char *utf16Le = "utf-16le";
constexpr const char *utf32Be = "utf-32be";
constexpr const char *utf32Le = "utf-32le";
constexpr const char *utf8 = "utf-8";
constexpr const char *uuid = "uuid";
constexpr const char *variant = "variant";
constexpr const char *varLenSInt = "variable-length-signed-integer";
constexpr const char *varLenUInt = "variable-length-unsigned-integer";
constexpr const char *version = "version";

} /* namespace jsonstr */
} /* namespace ctf */
