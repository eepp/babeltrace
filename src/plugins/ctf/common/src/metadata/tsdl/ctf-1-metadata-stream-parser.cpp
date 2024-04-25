/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2022 Francis Deslauriers <francis.deslauriers@efficios.com>
 */

#include "compat/memstream.h"

#include "ctf-1-metadata-stream-parser.hpp"

namespace ctf {
namespace src {

namespace {

ir::DispBase
dispBaseFromIrDispBase(const bt_field_class_integer_preferred_display_base dispBase) noexcept
{
    return static_cast<ir::DispBase>(dispBase);
}

ir::ByteOrder byteOrderFromOrigByteOrder(const ctf_byte_order origByteOrder)
{
    switch (origByteOrder) {
    case CTF_BYTE_ORDER_LITTLE:
        return ir::ByteOrder::LITTLE;
    case CTF_BYTE_ORDER_BIG:
        return ir::ByteOrder::BIG;
    default:
        bt_common_abort();
    }
}

bt2s::optional<ir::UIntFieldRole>
roleFromOrigMeaning(const ctf_field_class_meaning meaning) noexcept
{
    switch (meaning) {
    case CTF_FIELD_CLASS_MEANING_PACKET_BEGINNING_TIME:
        return {ir::UIntFieldRole::DEF_CLK_TS};
    case CTF_FIELD_CLASS_MEANING_PACKET_END_TIME:
        return {ir::UIntFieldRole::PKT_END_DEF_CLK_TS};
    case CTF_FIELD_CLASS_MEANING_EVENT_CLASS_ID:
        return {ir::UIntFieldRole::EVENT_RECORD_CLS_ID};
    case CTF_FIELD_CLASS_MEANING_STREAM_CLASS_ID:
        return {ir::UIntFieldRole::DATA_STREAM_CLS_ID};
    case CTF_FIELD_CLASS_MEANING_DATA_STREAM_ID:
        return {ir::UIntFieldRole::DATA_STREAM_ID};
    case CTF_FIELD_CLASS_MEANING_MAGIC:
        return {ir::UIntFieldRole::PKT_MAGIC_NUMBER};
    case CTF_FIELD_CLASS_MEANING_PACKET_COUNTER_SNAPSHOT:
        return {ir::UIntFieldRole::PKT_SEQ_NUM};
    case CTF_FIELD_CLASS_MEANING_DISC_EV_REC_COUNTER_SNAPSHOT:
        return {ir::UIntFieldRole::DISC_EVENT_RECORD_COUNTER_SNAP};
    case CTF_FIELD_CLASS_MEANING_EXP_PACKET_TOTAL_SIZE:
        return {ir::UIntFieldRole::PKT_TOTAL_LEN};
    case CTF_FIELD_CLASS_MEANING_EXP_PACKET_CONTENT_SIZE:
        return {ir::UIntFieldRole::PKT_CONTENT_LEN};
    case CTF_FIELD_CLASS_MEANING_UUID:
    case CTF_FIELD_CLASS_MEANING_NONE:
        return bt2s::nullopt;
    default:
        bt_common_abort();
    }
}

/*
 * Returns the integer field class roles which correspond to the meaning
 * of the original CTF IR integer field class `origIntFc`.
 */
ir::UIntFieldRoles rolesFromOrigIntFc(const ctf_field_class_int& origIntFc)
{
    ir::UIntFieldRoles roles;

    const auto role = roleFromOrigMeaning(origIntFc.meaning);

    if (role) {
        roles.insert(*role);
    }

    const auto hasPktEndDefClkTsRole = role && *role == ir::UIntFieldRole::PKT_END_DEF_CLK_TS;

    if (!hasPktEndDefClkTsRole && origIntFc.mapped_clock_class) {
        roles.insert(ir::UIntFieldRole::DEF_CLK_TS);
    }

    return roles;
}

/*
 * Translates the original CTF IR integer field class `origFc` and
 * returns the translated object.
 */
Fc::UP fcFromOrigFc(const ctf_field_class_int& oldFc)
{
    if (oldFc.is_signed) {
        return createFixedLenSIntFc(oldFc.base.base.alignment,
                                    bt2c::DataLen::fromBits(oldFc.base.size),
                                    byteOrderFromOrigByteOrder(oldFc.base.byte_order),
                                    dispBaseFromIrDispBase(oldFc.disp_base));
    } else {
        auto roles = rolesFromOrigIntFc(oldFc);

        return createFixedLenUIntFc(oldFc.base.base.alignment,
                                    bt2c::DataLen::fromBits(oldFc.base.size),
                                    byteOrderFromOrigByteOrder(oldFc.base.byte_order),
                                    dispBaseFromIrDispBase(oldFc.disp_base), std::move(roles));
    }
}

/*
 * Translates the mappings of the original CTF IR enumeration field
 * class `origFc` and returns the translated objects.
 */
template <typename EnumT>
static typename EnumT::Mappings enumFcMappingsFromOrigEnumFc(const ctf_field_class_enum& origFc)
{
    using Mappings = typename EnumT::Mappings;
    using RangeSet = typename Mappings::mapped_type;

    Mappings mappings;

    for (std::size_t mappingIndex = 0; mappingIndex < origFc.mappings->len; ++mappingIndex) {
        auto& origMapping =
            *ctf_field_class_enum_borrow_mapping_by_index_const(&origFc, mappingIndex);

        typename RangeSet::Set ranges;

        for (std::size_t rangeIdx = 0; rangeIdx < origMapping.ranges->len; ++rangeIdx) {
            auto& origRange =
                *ctf_field_class_enum_mapping_borrow_range_by_index_const(&origMapping, rangeIdx);

            ranges.emplace(static_cast<typename EnumT::Val>(origRange.lower.u),
                           static_cast<typename EnumT::Val>(origRange.upper.u));
        }

        typename Mappings::mapped_type rangeSet {ranges};

        mappings.emplace(std::make_pair(origMapping.label->str, RangeSet {ranges}));
    }

    return mappings;
}

/*
 * Translates the original CTF IR enumeration field class `origFc` and
 * returns the translated object.
 */
Fc::UP fcFromOrigFc(const ctf_field_class_enum& origFc)
{
    const auto byteOrder = byteOrderFromOrigByteOrder(origFc.base.base.byte_order);
    const auto dispBase = dispBaseFromIrDispBase(origFc.base.disp_base);

    if (origFc.base.is_signed) {
        return createFixedLenSEnumFc(
            origFc.base.base.base.alignment, bt2c::DataLen::fromBits(origFc.base.base.size),
            byteOrder, enumFcMappingsFromOrigEnumFc<FixedLenSEnumFc>(origFc), dispBase);
    } else {
        return createFixedLenUEnumFc(origFc.base.base.base.alignment,
                                     bt2c::DataLen::fromBits(origFc.base.base.size), byteOrder,
                                     enumFcMappingsFromOrigEnumFc<FixedLenUEnumFc>(origFc),
                                     dispBase, rolesFromOrigIntFc(origFc.base));
    }
}

/*
 * Translates the original CTF IR floating-point number field class
 * `origFc` and returns the translated object.
 */
Fc::UP fcFromOrigFc(const ctf_field_class_float& origFc)
{
    return createFixedLenFloatFc(origFc.base.base.alignment,
                                 bt2c::DataLen::fromBits(origFc.base.size),
                                 byteOrderFromOrigByteOrder(origFc.base.byte_order));
}

/*
 * Returns the event record class log level name which corresponds to
 * the original CTF IR event record class log level `origLogLevel`.
 */
const char *eventRecordClsLogLevelNameFromOrigLogLevel(const bt_event_class_log_level origLogLevel)
{
    switch (origLogLevel) {
    case BT_EVENT_CLASS_LOG_LEVEL_EMERGENCY:
        return "emergency";
    case BT_EVENT_CLASS_LOG_LEVEL_ALERT:
        return "alert";
    case BT_EVENT_CLASS_LOG_LEVEL_CRITICAL:
        return "critical";
    case BT_EVENT_CLASS_LOG_LEVEL_ERROR:
        return "error";
    case BT_EVENT_CLASS_LOG_LEVEL_WARNING:
        return "warning";
    case BT_EVENT_CLASS_LOG_LEVEL_NOTICE:
        return "notice";
    case BT_EVENT_CLASS_LOG_LEVEL_INFO:
        return "info";
    case BT_EVENT_CLASS_LOG_LEVEL_DEBUG_SYSTEM:
        return "debug:system";
    case BT_EVENT_CLASS_LOG_LEVEL_DEBUG_PROGRAM:
        return "debug:program";
    case BT_EVENT_CLASS_LOG_LEVEL_DEBUG_PROCESS:
        return "debug:process";
    case BT_EVENT_CLASS_LOG_LEVEL_DEBUG_MODULE:
        return "debug:module";
    case BT_EVENT_CLASS_LOG_LEVEL_DEBUG_UNIT:
        return "debug:unit";
    case BT_EVENT_CLASS_LOG_LEVEL_DEBUG_FUNCTION:
        return "debug:function";
    case BT_EVENT_CLASS_LOG_LEVEL_DEBUG_LINE:
        return "debug:line";
    case BT_EVENT_CLASS_LOG_LEVEL_DEBUG:
        return "debug";
    default:
        bt_common_abort();
    }
}

/*
 * Returns the event record class user attributes which correspond to
 * the log level and EMF URI properties of the original CTF IR event
 * record class `origEventRecordCls`.
 */
ir::OptUserAttrs
eventRecordClsBtUserAttrsFromOrigEventRecordCls(const ctf_event_class& origEventRecordCls)
{
    if (origEventRecordCls.emf_uri->len == 0 && !origEventRecordCls.is_log_level_set) {
        /* No log level and no EMF URI: no user attributes */
        return ir::OptUserAttrs {};
    }

    auto userAttrs = bt2::MapValue::create();
    auto nsMapVal = userAttrs->insertEmptyMap("babeltrace.org,2020");

    if (origEventRecordCls.emf_uri->len) {
        /* Set EMF URI user attribute */
        nsMapVal.insert("emf-uri", origEventRecordCls.emf_uri->str);
    }

    if (origEventRecordCls.is_log_level_set) {
        /* Set log level user attribute */
        nsMapVal.insert("log-level",
                        eventRecordClsLogLevelNameFromOrigLogLevel(origEventRecordCls.log_level));
    }

    return userAttrs;
}

/*
 * Translates the environment entries of the original CTF IR trace class
 * `origTraceCls` to a map value and returns it.
 */
bt2::ConstMapValue::Shared envMapValFromOrigTraceCls(const ctf_trace_class& origTraceCls)
{
    auto envMapVal = bt2::MapValue::create();

    for (std::size_t i = 0; i < origTraceCls.env_entries->len; ++i) {
        auto& origEnvEntry = *ctf_trace_class_borrow_env_entry_by_index(
            const_cast<ctf_trace_class *>(&origTraceCls), i);

        if (origEnvEntry.type == CTF_TRACE_CLASS_ENV_ENTRY_TYPE_INT) {
            envMapVal->insert(origEnvEntry.name->str, origEnvEntry.value.i);
        } else {
            BT_ASSERT(origEnvEntry.type == CTF_TRACE_CLASS_ENV_ENTRY_TYPE_STR);
            envMapVal->insert(origEnvEntry.name->str, origEnvEntry.value.str->str);
        }
    }

    return bt2::ConstMapValue::Shared::createWithoutRef(envMapVal.release().libObjPtr());
}

} /* namespace */

Fc::UP Ctf1MetadataStreamParser::_fcFromOrigFc(const ctf_field_class_struct& origFc)
{
    StructFc::MemberClasses memberClasses;

    for (std::size_t i = 0; i < origFc.members->len; ++i) {
        auto& origMemberCls = *ctf_field_class_struct_borrow_member_by_index_const(&origFc, i);

        memberClasses.emplace_back(createStructFieldMemberCls(
            origMemberCls.name->str, this->_fcFromOrigFc(*origMemberCls.fc)));
    }

    return createStructFc(std::move(memberClasses), origFc.base.alignment);
}

Fc::UP Ctf1MetadataStreamParser::_fcFromOrigFc(const ctf_field_class_array& origFc)
{
    if (origFc.base.is_text) {
        return createStaticLenStrFc(origFc.length);
    }

    return createStaticLenArrayFc(origFc.length, this->_fcFromOrigFc(*origFc.base.elem_fc),
                                  origFc.base.base.alignment, ir::OptUserAttrs {},
                                  origFc.meaning == CTF_FIELD_CLASS_MEANING_UUID);
}

FieldLoc Ctf1MetadataStreamParser::_fieldLocFromOrigFieldPath(const ctf_field_path& origFieldPath)
{
    /* Get original CTF IR root field class and CTF IR scope */
    const auto origFcAndScope = [this, &origFieldPath] {
        switch (origFieldPath.root) {
        case CTF_SCOPE_PACKET_HEADER:
            return std::make_pair(_mFcTranslationCtx.origTraceCls->packet_header_fc,
                                  ir::FieldLocScope::PKT_HEADER);
        case CTF_SCOPE_PACKET_CONTEXT:
            return std::make_pair(_mFcTranslationCtx.origDataStreamCls->packet_context_fc,
                                  ir::FieldLocScope::PKT_CTX);
        case CTF_SCOPE_EVENT_HEADER:
            return std::make_pair(_mFcTranslationCtx.origDataStreamCls->event_header_fc,
                                  ir::FieldLocScope::EVENT_RECORD_HEADER);
        case CTF_SCOPE_EVENT_COMMON_CONTEXT:
            return std::make_pair(_mFcTranslationCtx.origDataStreamCls->event_common_context_fc,
                                  ir::FieldLocScope::EVENT_RECORD_COMMON_CTX);
        case CTF_SCOPE_EVENT_SPECIFIC_CONTEXT:
            return std::make_pair(_mFcTranslationCtx.origEventRecordCls->spec_context_fc,
                                  ir::FieldLocScope::EVENT_RECORD_SPEC_CTX);
        case CTF_SCOPE_EVENT_PAYLOAD:
            return std::make_pair(_mFcTranslationCtx.origEventRecordCls->payload_fc,
                                  ir::FieldLocScope::EVENT_RECORD_PAYLOAD);
        default:
            bt_common_abort();
        }
    }();

    /* Translate field path to field scope */
    FieldLoc::Items items;
    auto origFc = origFcAndScope.first;

    for (std::size_t i = 0; i < origFieldPath.path->len; ++i) {
        switch (origFc->type) {
        case CTF_FIELD_CLASS_TYPE_SEQUENCE:
        case CTF_FIELD_CLASS_TYPE_ARRAY:
        {
            const auto childIndex = ctf_field_path_borrow_index_by_index(&origFieldPath, i);

            BT_ASSERT(childIndex == -1);
            origFc = ctf_field_class_as_array_base(origFc)->elem_fc;
            break;
        }
        case CTF_FIELD_CLASS_TYPE_STRUCT:
        {
            const auto childIndex = ctf_field_path_borrow_index_by_index(&origFieldPath, i);
            const auto origChildFc =
                ctf_field_class_compound_borrow_named_field_class_by_index(origFc, childIndex);

            BT_ASSERT(origChildFc);
            items.emplace_back(origChildFc->name->str);
            origFc = origChildFc->fc;
            break;
        }
        case CTF_FIELD_CLASS_TYPE_VARIANT:
        {
            const auto childIndex = ctf_field_path_borrow_index_by_index(&origFieldPath, i);
            const auto origChildFc =
                ctf_field_class_compound_borrow_named_field_class_by_index(origFc, childIndex);

            BT_ASSERT_DBG(origChildFc);

            /*
             * Variant field class option names aren't part of a CTF IR
             * field location: like for the current element of an array
             * field, a dependency which is part of a variant field F is
             * always within the current option of F.
             */
            origFc = origChildFc->fc;
            break;
        }
        default:
            break;
        }
    }

    return createFieldLoc(origFcAndScope.second, std::move(items));
}

Fc::UP Ctf1MetadataStreamParser::_fcFromOrigFc(const ctf_field_class_sequence& origFc)
{
    auto lenFieldLoc = this->_fieldLocFromOrigFieldPath(origFc.length_path);

    if (origFc.base.is_text) {
        return createDynLenStrFc(std::move(lenFieldLoc));
    }

    return createDynLenArrayFc(std::move(lenFieldLoc), this->_fcFromOrigFc(*origFc.base.elem_fc));
}

Fc::UP Ctf1MetadataStreamParser::_fcFromOrigFc(const ctf_field_class_variant& origFc)
{
    auto selFieldLoc = this->_fieldLocFromOrigFieldPath(origFc.tag_path);

    if (origFc.tag_fc->base.is_signed) {
        return createVariantFc(this->_variantOptsFromOrigVariantFc<VariantWithSIntSelFc>(origFc),
                               std::move(selFieldLoc));
    } else {
        return createVariantFc(this->_variantOptsFromOrigVariantFc<VariantWithUIntSelFc>(origFc),
                               std::move(selFieldLoc));
    }
}

Fc::UP Ctf1MetadataStreamParser::_fcFromOrigFc(const ctf_field_class& origFc)
{
    /*
     * The ctf_field_class_as_*() functions only accept non-const
     * pointers.
     */
    auto& nonConstOrigFc = const_cast<ctf_field_class&>(origFc);

    switch (origFc.type) {
    case CTF_FIELD_CLASS_TYPE_INT:
        return fcFromOrigFc(*ctf_field_class_as_int(&nonConstOrigFc));
    case CTF_FIELD_CLASS_TYPE_ENUM:
        return fcFromOrigFc(*ctf_field_class_as_enum(&nonConstOrigFc));
    case CTF_FIELD_CLASS_TYPE_FLOAT:
        return fcFromOrigFc(*ctf_field_class_as_float(&nonConstOrigFc));
    case CTF_FIELD_CLASS_TYPE_STRING:
        return createNullTerminatedStrFc();
    case CTF_FIELD_CLASS_TYPE_STRUCT:
        return this->_fcFromOrigFc(*ctf_field_class_as_struct(&nonConstOrigFc));
    case CTF_FIELD_CLASS_TYPE_ARRAY:
        return this->_fcFromOrigFc(*ctf_field_class_as_array(&nonConstOrigFc));
    case CTF_FIELD_CLASS_TYPE_SEQUENCE:
        return this->_fcFromOrigFc(*ctf_field_class_as_sequence(&nonConstOrigFc));
    case CTF_FIELD_CLASS_TYPE_VARIANT:
        return this->_fcFromOrigFc(*ctf_field_class_as_variant(&nonConstOrigFc));
    default:
        bt_common_abort();
    }
}

bt2c::FileUP Ctf1MetadataStreamParser::_fileUpFromStr(const std::string& str)
{
    const auto fp = bt_fmemopen(const_cast<char *>(str.data()), str.size(), "rb");

    if (!fp) {
        BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error, "bt_fmemopen() failed.");
    }

    return bt2c::FileUP {fp};
}

void Ctf1MetadataStreamParser::_parseSection(const bt2s::span<const std::uint8_t> buffer)
{
    const auto plaintextMetadata = _mStreamDecoder.decode(buffer);
    auto plaintextFile = this->_fileUpFromStr(plaintextMetadata);

    /* Append the metadata text content to the TSDL scanner */
    {
        const auto ret = ctf_scanner_append_ast(_mScanner.get(), plaintextFile.get());

        if (ret) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW(
                bt2c::Error, "Cannot create the metadata stream AST from TSDL text: ret={}", ret);
        }
    }

    /* Make some basic AST node validation */
    {
        const auto ret = ctf_visitor_semantic_check(0, &_mScanner.get()->ast->root, _mLogger);

        if (ret) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW(
                bt2c::Error, "Failed to validate metadata stream AST nodes: ret={}", ret);
        }
    }

    /* Convert AST nodes to original CTF IR objects */
    {
        const auto ret = ctf_visitor_generate_ir_visit_node(_mOrigCtfIrGenerator.get(),
                                                            &_mScanner.get()->ast->root);

        switch (ret) {
        case 0:
            /* Success */
            break;
        case -EINCOMPLETE:
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error, "Incomplete metadata stream section.");
        default:
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW(
                bt2c::Error,
                "Failed to create original CTF IR objects from metadata stream AST nodes: ret={}",
                ret);
        }
    }

    /* Translate original CTF IR objects to current CTF IR ones */
    this->_tryTranslate(*_mOrigCtfIrGenerator->ctf_tc);
}

void Ctf1MetadataStreamParser::_tryTranslate(ctf_trace_class& origTraceCls)
{
    _mFcTranslationCtx.origTraceCls = &origTraceCls;

    if (!_mTraceCls) {
        /* No trace class yet: translate original CTF IR trace class */
        _mTraceCls = this->_translateTraceCls(origTraceCls);
    }

    /* Try to translate data stream classes and event record classes */
    for (std::size_t iDataStreamCls = 0; iDataStreamCls < origTraceCls.stream_classes->len;
         ++iDataStreamCls) {
        auto& origDataStreamCls =
            *static_cast<ctf_stream_class *>(origTraceCls.stream_classes->pdata[iDataStreamCls]);

        _mFcTranslationCtx.origDataStreamCls = &origDataStreamCls;
        _mFcTranslationCtx.origEventRecordCls = nullptr;
        _mFcTranslationCtx.dataStreamCls = &this->_tryTranslateDataStreamCls(origDataStreamCls);

        for (std::size_t iEventRecordCls = 0;
             iEventRecordCls < origDataStreamCls.event_classes->len; iEventRecordCls++) {
            auto& origEventRecordCls = *static_cast<ctf_event_class *>(
                origDataStreamCls.event_classes->pdata[iEventRecordCls]);

            _mFcTranslationCtx.origEventRecordCls = &origEventRecordCls;
            this->_tryTranslateEventRecordCls(origEventRecordCls);
        }
    }
}

std::unique_ptr<TraceCls>
Ctf1MetadataStreamParser::_translateTraceCls(ctf_trace_class& origTraceCls)
{
    BT_ASSERT(!origTraceCls.is_translated);

    /* Translate packet header field class */
    Fc::UP pktHeaderFc;

    if (origTraceCls.packet_header_fc) {
        pktHeaderFc = this->_fcFromOrigFc(*origTraceCls.packet_header_fc);
    }

    /* UUID */
    bt2s::optional<bt2c::Uuid> uuid;

    if (origTraceCls.is_uuid_set) {
        uuid = origTraceCls.uuid;
    }

    /* Create trace class */
    auto traceCls = createTraceCls(std::move(uuid), envMapValFromOrigTraceCls(origTraceCls),
                                   std::move(pktHeaderFc));

    /* Mark original CTF IR trace class as translated */
    origTraceCls.is_translated = true;

    /* Return created trace class */
    return traceCls;
}

ClkCls::SP Ctf1MetadataStreamParser::_clkClsFromOrigClkCls(const ctf_clock_class& origClkCls)
{
    /* Try to find a corresponding clock class for `origClkCls`*/
    const auto it = _mClkClsMap.find(&origClkCls);

    if (it != _mClkClsMap.end()) {
        /* Found it */
        return it->second;
    }

    /* Translate clock class */
    {
        /* Description */
        bt2s::optional<std::string> descr;

        if (origClkCls.description->len > 0) {
            descr = origClkCls.description->str;
        }

        /* UUID */
        bt2s::optional<bt2c::Uuid> uuid;

        if (origClkCls.has_uuid) {
            uuid = origClkCls.uuid;
        }

        /* Create clock class */
        auto clkCls = createClkCls(
            origClkCls.name->str, origClkCls.frequency,
            ir::ClkOffset {origClkCls.offset_seconds, origClkCls.offset_cycles},
            origClkCls.is_absolute, std::move(descr), origClkCls.precision, std::move(uuid));

        /* Add to map of translated clock classes */
        _mClkClsMap.emplace(&origClkCls, clkCls);

        /* Return created clock class */
        return clkCls;
    }
}

DataStreamCls&
Ctf1MetadataStreamParser::_tryTranslateDataStreamCls(ctf_stream_class& origDataStreamCls)
{
    if (origDataStreamCls.is_translated) {
        /* Already translated: return it */
        return *(*_mTraceCls)[origDataStreamCls.id];
    }

    /* Translate packet context field class */
    Fc::UP pktCtxFc;

    if (origDataStreamCls.packet_context_fc) {
        pktCtxFc = this->_fcFromOrigFc(*origDataStreamCls.packet_context_fc);
    }

    /* Translate event record header field class */
    Fc::UP eventRecordHeaderFc;

    if (origDataStreamCls.event_header_fc) {
        eventRecordHeaderFc = this->_fcFromOrigFc(*origDataStreamCls.event_header_fc);
    }

    /* Translate common event record context field class */
    Fc::UP commonEventRecordCtxFc;

    if (origDataStreamCls.event_common_context_fc) {
        commonEventRecordCtxFc = this->_fcFromOrigFc(*origDataStreamCls.event_common_context_fc);
    }

    /* Translate default clock class */
    ClkCls::SP defClkCls;

    if (origDataStreamCls.default_clock_class) {
        defClkCls = this->_clkClsFromOrigClkCls(*origDataStreamCls.default_clock_class);
    }

    /* Create data stream class */
    auto dataStreamClsSp = createDataStreamCls(
        origDataStreamCls.id, bt2s::nullopt, bt2s::nullopt, std::move(pktCtxFc),
        std::move(eventRecordHeaderFc), std::move(commonEventRecordCtxFc), std::move(defClkCls));
    auto& dataStreamCls = *dataStreamClsSp;

    /* Add to trace class */
    _mTraceCls->addDataStreamCls(std::move(dataStreamClsSp));

    /* Mark original CTF IR data stream class as translated */
    origDataStreamCls.is_translated = true;

    /* Return created data stream class */
    return dataStreamCls;
}

void Ctf1MetadataStreamParser::_tryTranslateEventRecordCls(ctf_event_class& origEventRecordCls)
{
    if (origEventRecordCls.is_translated) {
        /* Already translated */
        return;
    }

    /* Translate specific context field class, if any */
    Fc::UP specCtxFc;

    if (origEventRecordCls.spec_context_fc) {
        specCtxFc = this->_fcFromOrigFc(*origEventRecordCls.spec_context_fc);
    }

    /* Translate payload field class, if any */
    Fc::UP payloadFc;

    if (origEventRecordCls.payload_fc) {
        payloadFc = this->_fcFromOrigFc(*origEventRecordCls.payload_fc);
    }

    /* Create event record class */
    auto eventRecordCls = createEventRecordCls(
        origEventRecordCls.id, bt2s::nullopt, origEventRecordCls.name->str, std::move(specCtxFc),
        std::move(payloadFc), eventRecordClsBtUserAttrsFromOrigEventRecordCls(origEventRecordCls));

    /* Add to data stream class */
    BT_ASSERT(_mFcTranslationCtx.dataStreamCls);
    _mFcTranslationCtx.dataStreamCls->addEventRecordCls(std::move(eventRecordCls));

    /* Mark original CTF IR event record class as translated */
    origEventRecordCls.is_translated = true;
}

Ctf1MetadataStreamParser::Ctf1MetadataStreamParser(
    const ClkClsCfg& clkClsCfg, const bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp,
    const bt2c::Logger& parentLogger) :
    MetadataStreamParser {clkClsCfg, selfComp},
    _mLogger {parentLogger, "PLUGIN/CTF/CTF-1-META-STREAM-PARSER"},
    _mOrigCtfIrGenerator {ctf_visitor_generate_ir_create({}, _mLogger)},
    _mScanner {ctf_scanner_alloc(_mLogger)}, _mStreamDecoder {_mLogger}
{
}

MetadataStreamParser::ParseRet Ctf1MetadataStreamParser::parse(
    const ClkClsCfg& clkClsCfg, const bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp,
    const bt2s::span<const std::uint8_t> buffer, const bt2c::Logger& parentLogger)
{
    Ctf1MetadataStreamParser parser {clkClsCfg, selfComp, parentLogger};

    parser.parseSection(buffer);
    return {parser.releaseTraceCls(), parser.metadataStreamUuid()};
}

} /* namespace src */
} /* namespace ctf */
