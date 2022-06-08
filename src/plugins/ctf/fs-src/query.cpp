/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * Babeltrace CTF file system Reader Component queries
 */

#define BT_LOG_OUTPUT_LEVEL logCfg.logLevel()
#define BT_LOG_TAG          "PLUGIN/SRC.CTF.FS/QUERY"
#include "logging/log.h"

#include "query.hpp"
#include <stdbool.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "common/assert.h"
#include "metadata.hpp"
#include "plugins/ctf/common/src/metadata/tsdl/metadata-stream-decoder.hpp"
#include "plugins/ctf/common/src/metadata/tsdl/ctf-1-metadata-stream-parser.hpp"
#include "common/common.h"
#include "common/macros.h"
#include "plugins/common/param-validation/param-validation.h"
#include <babeltrace2/babeltrace.h>
#include "fs.hpp"
#include "logging/comp-logging.h"
#include "cpp-common/libc-up.hpp"
#include "cpp-common/exc.hpp"
#include "cpp-common/comp-logging.hpp"
#include "cpp-common/file-utils.hpp"

#define METADATA_TEXT_SIG "/* CTF 1.8"

struct range
{
    int64_t begin_ns = 0;
    int64_t end_ns = 0;
    bool set = false;
};

static struct bt_param_validation_map_value_entry_descr metadataInfoQueryParamsDesc[] = {
    {"path", BT_PARAM_VALIDATION_MAP_VALUE_ENTRY_MANDATORY,
     bt_param_validation_value_descr::makeString()},
    BT_PARAM_VALIDATION_MAP_VALUE_ENTRY_END};

BT_HIDDEN
bt2::Value::Shared metadata_info_query(bt2::ConstMapValue params, const bt2_common::LogCfg& logCfg)
{
    gchar *validateError = NULL;
    auto validationStatus = bt_param_validation_validate(
        params.libObjPtr(), metadataInfoQueryParamsDesc, &validateError);

    if (validationStatus == BT_PARAM_VALIDATION_STATUS_MEMORY_ERROR) {
        throw bt2_common::MemoryError {};
    } else if (validationStatus == BT_PARAM_VALIDATION_STATUS_VALIDATION_ERROR) {
        const std::string error {validateError};

        g_free(validateError);
        BT_COMP_CLASS_LOGE_APPEND_CAUSE_AND_THROW(bt2_common::Error, logCfg.selfCompCls(), "%s",
                                                  error.data());
    }

    const auto path = params["path"]->asString().value();

    try {
        const auto buffer =
            bt2_common::dataFromFile(std::string {path.to_string() + "/metadata"}.c_str());

        ctf::src::MetadataStreamDecoder decoder {logCfg};

        auto plainText =
            decoder.decode(buffer.data(), bt2_common::DataLen::fromBytes(buffer.size()));

        auto result = bt2::MapValue::create();
        /*
         * If the metadata does not already start with the plaintext metadata
         * signature, prepend it.
         */
        if (plainText.rfind(METADATA_TEXT_SIG, 0) != 0) {
            plainText.insert(0, std::string {METADATA_TEXT_SIG} + " */\n\n");
        }

        result->insert("text", plainText.data());

        result->insert("is-packetized", decoder.pktInfo().has_value());
        return result;
    } catch (const bt2_common::Error&) {
        BT_COMP_CLASS_LOGE_APPEND_CAUSE_AND_RETHROW(
            logCfg.selfCompCls(), "Error getting plaintext metadata section from file");
    }
}

static void add_range(bt2::MapValue info, struct range *range, const char *range_name)
{
    if (!range->set) {
        /* Not an error. */
        return;
    }

    bt2::MapValue rangeMap = info.insertEmptyMap(range_name);
    rangeMap.insert("begin", range->begin_ns);
    rangeMap.insert("end", range->end_ns);
}

static void populate_stream_info(struct ctf_fs_ds_file_group *group, bt2::MapValue groupInfo,
                                 struct range *stream_range, const bt2_common::LogCfg& logCfg)
{
    /*
     * Since each `struct ctf_fs_ds_file_group` has a sorted array of
     * `struct ctf_fs_ds_index_entry`, we can compute the stream range from
     * the timestamp_begin of the first index entry and the timestamp_end
     * of the last index entry.
     */
    BT_ASSERT(group->index);
    BT_ASSERT(group->index->entries);
    BT_ASSERT(group->index->entries->len > 0);

    /* First entry. */
    ctf_fs_ds_index_entry *first_ds_index_entry =
        (struct ctf_fs_ds_index_entry *) g_ptr_array_index(group->index->entries, 0);

    /* Last entry. */
    ctf_fs_ds_index_entry *last_ds_index_entry = (struct ctf_fs_ds_index_entry *) g_ptr_array_index(
        group->index->entries, group->index->entries->len - 1);

    stream_range->begin_ns = first_ds_index_entry->timestamp_begin_ns;
    stream_range->end_ns = last_ds_index_entry->timestamp_end_ns;

    /*
     * If any of the begin and end timestamps is not set it means that
     * packets don't include `timestamp_begin` _and_ `timestamp_end` fields
     * in their packet context so we can't set the range.
     */
    stream_range->set =
        stream_range->begin_ns != UINT64_C(-1) && stream_range->end_ns != UINT64_C(-1);

    add_range(groupInfo, stream_range, "range-ns");

    bt2_common::GCharUP portName = ctf_fs_make_port_name(group);
    if (!portName) {
        BT_COMP_CLASS_LOGE_APPEND_CAUSE_AND_THROW(bt2_common::Error, logCfg.selfCompCls(),
                                                  "Failed to make port name");
    }

    groupInfo.insert("port-name", portName.get());
}

static void populate_trace_info(const struct ctf_fs_trace *trace, bt2::MapValue traceInfo,
                                const bt2_common::LogCfg& logCfg)
{
    /* Add trace range info only if it contains streams. */
    if (trace->ds_file_groups.empty()) {
        BT_COMP_CLASS_LOGE_APPEND_CAUSE_AND_THROW(bt2_common::Error, logCfg.selfCompCls(),
                                                  "Trace has no streams: trace-path=%s",
                                                  trace->path->str);
    }

    bt2::ArrayValue fileGroups = traceInfo.insertEmptyArray("stream-infos");

    /* Find range of all stream groups, and of the trace. */
    for (const ctf_fs_ds_file_group::UP& group : trace->ds_file_groups) {
        range group_range;
        bt2::MapValue groupInfo = fileGroups.appendEmptyMap();
        populate_stream_info(group.get(), groupInfo, &group_range, logCfg);
    }
}

BT_HIDDEN
bt2::Value::Shared trace_infos_query(bt2::ConstMapValue params, const bt2_common::LogCfg& logCfg)
{
    ctf_fs_component::UP ctf_fs = ctf_fs_component_create(logCfg);
    if (!ctf_fs) {
        BT_COMP_CLASS_LOGE_APPEND_CAUSE_AND_THROW(bt2_common::Error, logCfg.selfCompCls(),
                                                  "Cannot create ctf_fs_component");
    }

    const bt_value *inputs_value = NULL;
    const bt_value *trace_name_value;

    if (!read_src_fs_parameters(params.libObjPtr(), &inputs_value, &trace_name_value,
                                ctf_fs.get())) {
        BT_COMP_CLASS_LOGE_APPEND_CAUSE_AND_THROW(bt2_common::Error, logCfg.selfCompCls(),
                                                  "Failed to read parameters");
    }

    if (ctf_fs_component_create_ctf_fs_trace(ctf_fs.get(), inputs_value, trace_name_value,
                                             nullptr)) {
        BT_COMP_CLASS_LOGE_APPEND_CAUSE_AND_THROW(bt2_common::Error, logCfg.selfCompCls(),
                                                  "Failed to create trace");
    }

    bt2::ArrayValue::Shared result = bt2::ArrayValue::create();
    bt2::MapValue traceInfo = result->appendEmptyMap();
    populate_trace_info(ctf_fs->trace.get(), traceInfo, logCfg);

    return result;
}

static struct bt_param_validation_map_value_entry_descr supportInfoQueryParamsDesc[] = {
    {"type", BT_PARAM_VALIDATION_MAP_VALUE_ENTRY_MANDATORY,
     bt_param_validation_value_descr::makeString()},
    {"input", BT_PARAM_VALIDATION_MAP_VALUE_ENTRY_MANDATORY,
     bt_param_validation_value_descr::makeString()},
    BT_PARAM_VALIDATION_MAP_VALUE_ENTRY_END};

BT_HIDDEN
bt2::Value::Shared support_info_query(bt2::ConstMapValue params, const bt2_common::LogCfg& logCfg)
{
    gchar *validateError = NULL;
    auto validationStatus = bt_param_validation_validate(
        params.libObjPtr(), supportInfoQueryParamsDesc, &validateError);

    if (validationStatus == BT_PARAM_VALIDATION_STATUS_MEMORY_ERROR) {
        throw bt2_common::MemoryError {};
    } else if (validationStatus == BT_PARAM_VALIDATION_STATUS_VALIDATION_ERROR) {
        const std::string error {validateError};

        g_free(validateError);
        BT_COMP_CLASS_LOGE_APPEND_CAUSE_AND_THROW(bt2_common::Error, logCfg.selfCompCls(), "%s",
                                                  error.data());
    }

    bpstd::string_view type = params["type"]->asString().value();

    if (type != "directory") {
        /*
         * The input type is not a directory so we are 100% sure it's not a CTF
         * 1.8 trace as it would need a directory with at least 1 metadata file
         * and 1 data stream file.
         */
        bt2::MapValue::Shared result = bt2::MapValue::create();
        result->insert("weight", 0.0f);
        return result;
    }

    bpstd::string_view input = params["input"]->asString().value();

    auto result = bt2::MapValue::create();
    try {
        const auto buffer =
            bt2_common::dataFromFile(std::string {input.to_string() + "/metadata"}.c_str());
        ctf::src::Ctf1MetadataStreamParser parser {ctf::src::ClkClsCfg {}, nullptr, logCfg};
        parser.parseSection(buffer.data(), buffer.data() + buffer.size());

        /*
         * We were able to parse the metadata file, so we are confident it's a
         * CTF trace.
         */
        result->insert("weight", 0.75);
        if (parser.traceCls() && parser.traceCls()->uuid()) {
            result->insert("group", parser.traceCls()->uuid()->str());
        }
    } catch (const bt2_common::NoSuchFileOrDirectoryError&) {
        /*
         * Failing to find the metadata file is not an error, it simply
         * indicates that the directory is not a trace. Report appropriate
         * weight of zero.
         */
        bt_current_thread_clear_error();
        result->insert("weight", 0.0);
    }
    return result;
}
