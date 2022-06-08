/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * Babeltrace CTF file system Reader Component queries
 */

#define BT_CLOG_CFG logCfg
#define BT_LOG_TAG  "PLUGIN/SRC.CTF.FS/QUERY"

#include "query.hpp"
#include <stdbool.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "common/assert.h"
#include "metadata.hpp"
#include "../common/src/metadata/tsdl/decoder.hpp"
#include "common/common.h"
#include "common/macros.h"
#include "plugins/common/param-validation/param-validation.h"
#include <babeltrace2/babeltrace.h>
#include "fs.hpp"
#include "cpp-common/cfg-logging-error-reporting.hpp"
#include "cpp-common/cfg-logging-error-reporting-throw.hpp"
#include "cpp-common/libc-up.hpp"
#include "cpp-common/exc.hpp"

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
        BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2_common::Error, "%s", error.data());
    }

    const char *path = params["path"]->asString().value().data();

    bt2_common::FileUP metadataFp(ctf_fs_metadata_open_file(path));
    if (!metadataFp) {
        BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2_common::Error,
                                        "Cannot open trace metadata: path=\"%s\".", path);
    }

    int bo;
    bool is_packetized;
    int ret = ctf_metadata_decoder_is_packetized(metadataFp.get(), &is_packetized, &bo, logCfg);
    if (ret) {
        BT_CLOGE_APPEND_CAUSE_AND_THROW(
            bt2_common::Error,
            "Cannot check whether or not the metadata stream is packetized: path=\"%s\".", path);
    }

    ctf_metadata_decoder_config decoder_cfg(logCfg);
    decoder_cfg.keep_plain_text = true;
    ctf_metadata_decoder_up decoder = ctf_metadata_decoder_create(&decoder_cfg);
    if (!decoder) {
        BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2_common::Error,
                                        "Cannot create metadata decoder: path=\"%s\".", path);
    }

    rewind(metadataFp.get());
    ctf_metadata_decoder_status decoder_status =
        ctf_metadata_decoder_append_content(decoder.get(), metadataFp.get());
    if (decoder_status) {
        BT_CLOGE_APPEND_CAUSE_AND_THROW(
            bt2_common::Error, "Cannot update metadata decoder's content: path=\"%s\".", path);
    }

    bt2::MapValue::Shared result = bt2::MapValue::create();
    result->insert("text", ctf_metadata_decoder_get_text(decoder.get()));
    result->insert("is-packetized", is_packetized);

    return result;
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
        BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2_common::Error, "Failed to make port name");
    }

    groupInfo.insert("port-name", portName.get());
}

static void populate_trace_info(const struct ctf_fs_trace *trace, bt2::MapValue traceInfo,
                                const bt2_common::LogCfg& logCfg)
{
    BT_ASSERT(trace->ds_file_groups);
    /* Add trace range info only if it contains streams. */
    if (trace->ds_file_groups->len == 0) {
        BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2_common::Error, "Trace has no streams: trace-path=%s",
                                        trace->path->str);
    }

    bt2::ArrayValue fileGroups = traceInfo.insertEmptyArray("stream-infos");

    /* Find range of all stream groups, and of the trace. */
    for (size_t group_idx = 0; group_idx < trace->ds_file_groups->len; group_idx++) {
        range group_range;
        ctf_fs_ds_file_group *group =
            (ctf_fs_ds_file_group *) g_ptr_array_index(trace->ds_file_groups, group_idx);

        bt2::MapValue groupInfo = fileGroups.appendEmptyMap();
        populate_stream_info(group, groupInfo, &group_range, logCfg);
    }
}

bt2::Value::Shared trace_infos_query(bt2::ConstMapValue params, const bt2_common::LogCfg& logCfg)
{
    ctf_fs_component::UP ctf_fs = ctf_fs_component_create(logCfg);
    if (!ctf_fs) {
        BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2_common::Error, "Cannot create ctf_fs_component");
    }

    const bt_value *inputs_value = NULL;
    const bt_value *trace_name_value;

    if (!read_src_fs_parameters(params.libObjPtr(), &inputs_value, &trace_name_value,
                                ctf_fs.get())) {
        BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2_common::Error, "Failed to read parameters");
    }

    if (ctf_fs_component_create_ctf_fs_trace(ctf_fs.get(), inputs_value, trace_name_value,
                                             nullptr)) {
        BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2_common::Error, "Failed to create trace");
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
        BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2_common::Error, "%s", error.data());
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

    bt2_common::GCharUP metadataPath {
        g_build_filename(input.c_str(), CTF_FS_METADATA_FILENAME, NULL)};
    if (!metadataPath) {
        BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2_common::Error, "Failed to read parameters");
    }

    double weight = 0;
    char uuid_str[BT_UUID_STR_LEN + 1];
    bool has_uuid = false;
    bt2_common::FileUP metadataFile {g_fopen(metadataPath.get(), "rb")};
    if (metadataFile) {
        enum ctf_metadata_decoder_status decoder_status;
        bt_uuid_t uuid;

        ctf_metadata_decoder_config metadata_decoder_config(logCfg);

        ctf_metadata_decoder_up metadata_decoder =
            ctf_metadata_decoder_create(&metadata_decoder_config);
        if (!metadata_decoder) {
            BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2_common::Error, "Failed to create metadata decoder");
        }

        decoder_status =
            ctf_metadata_decoder_append_content(metadata_decoder.get(), metadataFile.get());
        if (decoder_status != CTF_METADATA_DECODER_STATUS_OK) {
            BT_CLOGE_APPEND_CAUSE_AND_THROW(
                bt2_common::Error, "Failed to append metadata content: metadata-decoder-status=%d",
                decoder_status);
        }

        /*
         * We were able to parse the metadata file, so we are
         * confident it's a CTF trace.
         */
        weight = 0.75;

        /* If the trace has a UUID, return the stringified UUID as the group. */
        if (ctf_metadata_decoder_get_trace_class_uuid(metadata_decoder.get(), uuid) == 0) {
            bt_uuid_to_str(uuid, uuid_str);
            has_uuid = true;
        }
    }

    bt2::MapValue::Shared result = bt2::MapValue::create();
    result->insert("weight", weight);

    /* We are not supposed to have weight == 0 and a UUID. */
    BT_ASSERT(weight > 0 || !has_uuid);

    if (weight > 0 && has_uuid) {
        result->insert("group", uuid_str);
    }

    return result;
}
