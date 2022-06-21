/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2016-2017 Philippe Proulx <pproulx@efficios.com>
 * Copyright 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * Copyright 2010-2011 EfficiOS Inc. and Linux Foundation
 */

#define BT_CLOG_CFG         (logCfg)
#define BT_LOG_OUTPUT_LEVEL (logCfg.logLevel())
#define BT_LOG_TAG          "PLUGIN/SRC.CTF.FS/DS"
#include "logging/comp-logging.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <glib.h>
#include <inttypes.h>
#include "compat/mman.h"
#include "compat/endian.h"
#include <babeltrace2/babeltrace.h>
#include "common/common.h"
#include "file.hpp"
#include "metadata.hpp"
#include "../common/src/msg-iter/msg-iter.hpp"
#include "common/assert.h"
#include "data-stream-file.hpp"
#include <string.h>
#include "cpp-common/cfg-logging.hpp"
#include "cpp-common/cfg-logging-error-reporting.hpp"
#include "cpp-common/make-unique.hpp"
#include "fs.hpp"

static inline size_t remaining_mmap_bytes(struct ctf_fs_ds_file *ds_file)
{
    BT_ASSERT_DBG(ds_file->mmap_len >= ds_file->request_offset_in_mapping);
    return ds_file->mmap_len - ds_file->request_offset_in_mapping;
}

/*
 * Return true if `offset_in_file` is in the current mapping.
 */

static bool offset_ist_mapped(struct ctf_fs_ds_file *ds_file, off_t offset_in_file)
{
    return offset_in_file >= ds_file->mmap_offset_in_file &&
           offset_in_file < (ds_file->mmap_offset_in_file + ds_file->mmap_len);
}

static enum ctf_msg_iter_medium_status ds_file_munmap(struct ctf_fs_ds_file *ds_file)
{
    const bt2_common::LogCfg& logCfg = ds_file->logCfg;

    BT_ASSERT(ds_file);

    if (!ds_file->mmap_addr) {
        return CTF_MSG_ITER_MEDIUM_STATUS_OK;
    }

    if (bt_munmap(ds_file->mmap_addr, ds_file->mmap_len)) {
        BT_CLOGE_ERRNO("Cannot memory-unmap file",
                       ": address=%p, size=%zu, file_path=\"%s\", file=%p", ds_file->mmap_addr,
                       ds_file->mmap_len, ds_file->file ? ds_file->file->path.c_str() : "NULL",
                       ds_file->file ? ds_file->file->fp.get() : NULL);
        return CTF_MSG_ITER_MEDIUM_STATUS_ERROR;
    }

    ds_file->mmap_addr = NULL;

    return CTF_MSG_ITER_MEDIUM_STATUS_OK;
}

/*
 * mmap a region of `ds_file` such that `requested_offset_in_file` is in the
 * mapping.  If the currently mmap-ed region already contains
 * `requested_offset_in_file`, the mapping is kept.
 *
 * Set `ds_file->requested_offset_in_mapping` based on `request_offset_in_file`,
 * such that the next call to `request_bytes` will return bytes starting at that
 * position.
 *
 * `requested_offset_in_file` must be a valid offset in the file.
 */
static enum ctf_msg_iter_medium_status ds_file_mmap(struct ctf_fs_ds_file *ds_file,
                                                    off_t requested_offset_in_file)
{
    const bt2_common::LogCfg& logCfg = ds_file->logCfg;

    /* Ensure the requested offset is in the file range. */
    BT_ASSERT(requested_offset_in_file >= 0);
    BT_ASSERT(requested_offset_in_file < ds_file->file->size);

    /*
     * If the mapping already contains the requested offset, just adjust
     * requested_offset_in_mapping.
     */
    if (offset_ist_mapped(ds_file, requested_offset_in_file)) {
        ds_file->request_offset_in_mapping =
            requested_offset_in_file - ds_file->mmap_offset_in_file;
        return CTF_MSG_ITER_MEDIUM_STATUS_OK;
    }

    /* Unmap old region */
    ctf_msg_iter_medium_status status = ds_file_munmap(ds_file);
    if (status != CTF_MSG_ITER_MEDIUM_STATUS_OK) {
        return status;
    }

    /*
     * Compute a mapping that has the required alignment properties and
     * contains `requested_offset_in_file`.
     */
    ds_file->request_offset_in_mapping =
        requested_offset_in_file % bt_mmap_get_offset_align_size(logCfg.logLevel());
    ds_file->mmap_offset_in_file = requested_offset_in_file - ds_file->request_offset_in_mapping;
    ds_file->mmap_len =
        MIN(ds_file->file->size - ds_file->mmap_offset_in_file, ds_file->mmap_max_len);

    BT_ASSERT(ds_file->mmap_len > 0);

    ds_file->mmap_addr =
        bt_mmap((void *) 0, ds_file->mmap_len, PROT_READ, MAP_PRIVATE,
                fileno(ds_file->file->fp.get()), ds_file->mmap_offset_in_file, logCfg.logLevel());
    if (ds_file->mmap_addr == MAP_FAILED) {
        BT_CLOGE("Cannot memory-map address (size %zu) of file \"%s\" (%p) at offset %jd: %s",
                 ds_file->mmap_len, ds_file->file->path.c_str(), ds_file->file->fp.get(),
                 (intmax_t) ds_file->mmap_offset_in_file, strerror(errno));
        return CTF_MSG_ITER_MEDIUM_STATUS_ERROR;
    }

    return CTF_MSG_ITER_MEDIUM_STATUS_OK;
}

/*
 * Change the mapping of the file to read the region that follows the current
 * mapping.
 *
 * If the file hasn't been mapped yet, then everything (mmap_offset_in_file,
 * mmap_len, request_offset_in_mapping) should have the value 0, which will
 * result in the beginning of the file getting mapped.
 *
 * return _EOF if the current mapping is the end of the file.
 */

static enum ctf_msg_iter_medium_status ds_file_mmap_next(struct ctf_fs_ds_file *ds_file)
{
    /*
     * If we're called, it's because more bytes are requested but we have
     * given all the bytes of the current mapping.
     */
    BT_ASSERT(ds_file->request_offset_in_mapping == ds_file->mmap_len);

    /*
     * If the current mapping coincides with the end of the file, there is
     * no next mapping.
     */
    if (ds_file->mmap_offset_in_file + ds_file->mmap_len == ds_file->file->size) {
        return CTF_MSG_ITER_MEDIUM_STATUS_EOF;
    }

    return ds_file_mmap(ds_file, ds_file->mmap_offset_in_file + ds_file->mmap_len);
}

static enum ctf_msg_iter_medium_status medop_request_bytes(size_t request_sz, uint8_t **buffer_addr,
                                                           size_t *buffer_sz, void *data)
{
    struct ctf_fs_ds_file *ds_file = (struct ctf_fs_ds_file *) data;
    const bt2_common::LogCfg& logCfg = ds_file->logCfg;

    BT_ASSERT(request_sz > 0);

    /*
     * Check if we have at least one memory-mapped byte left. If we don't,
     * mmap the next file.
     */
    if (remaining_mmap_bytes(ds_file) == 0) {
        /* Are we at the end of the file? */
        if (ds_file->mmap_offset_in_file >= ds_file->file->size) {
            BT_CLOGD("Reached end of file \"%s\" (%p)", ds_file->file->path.c_str(),
                     ds_file->file->fp.get());
            return CTF_MSG_ITER_MEDIUM_STATUS_EOF;
        }

        ctf_msg_iter_medium_status status = ds_file_mmap_next(ds_file);
        switch (status) {
        case CTF_MSG_ITER_MEDIUM_STATUS_OK:
            break;
        case CTF_MSG_ITER_MEDIUM_STATUS_EOF:
            return CTF_MSG_ITER_MEDIUM_STATUS_EOF;
        default:
            BT_CLOGE("Cannot memory-map next region of file \"%s\" (%p)",
                     ds_file->file->path.c_str(), ds_file->file->fp.get());
            return status;
        }
    }

    BT_ASSERT(remaining_mmap_bytes(ds_file) > 0);
    *buffer_sz = MIN(remaining_mmap_bytes(ds_file), request_sz);

    BT_ASSERT(ds_file->mmap_addr);
    *buffer_addr = ((uint8_t *) ds_file->mmap_addr) + ds_file->request_offset_in_mapping;

    ds_file->request_offset_in_mapping += *buffer_sz;

    return CTF_MSG_ITER_MEDIUM_STATUS_OK;
}

static bt_stream *medop_borrow_stream(bt_stream_class *stream_class, int64_t stream_id, void *data)
{
    struct ctf_fs_ds_file *ds_file = (struct ctf_fs_ds_file *) data;
    bt_stream_class *ds_file_stream_class;

    ds_file_stream_class = (*ds_file->stream)->cls().libObjPtr();

    if (stream_class != ds_file_stream_class) {
        /*
         * Not supported: two packets described by two different
         * stream classes within the same data stream file.
         */
        return nullptr;
    }

    return (*ds_file->stream)->libObjPtr();
}

static enum ctf_msg_iter_medium_status medop_seek(off_t offset, void *data)
{
    struct ctf_fs_ds_file *ds_file = (struct ctf_fs_ds_file *) data;

    BT_ASSERT(offset >= 0);
    BT_ASSERT(offset < ds_file->file->size);

    return ds_file_mmap(ds_file, offset);
}

BT_HIDDEN
struct ctf_msg_iter_medium_ops ctf_fs_ds_file_medops = {
    medop_request_bytes,
    medop_seek,
    nullptr,
    medop_borrow_stream,
};

struct ctf_fs_ds_group_medops_data
{
    explicit ctf_fs_ds_group_medops_data(const bt2_common::LogCfg& logCfgParam) noexcept :
        logCfg {logCfgParam}
    {
    }

    /* Weak, set once at creation time. */
    struct ctf_fs_ds_file_group *ds_file_group = nullptr;

    /*
     * Index (as in element rank) of the index entry of ds_file_groups'
     * index we will read next (so, the one after the one we are reading
     * right now).
     */
    guint next_index_entry_index = 0;

    /*
     * File we are currently reading.  Changes whenever we switch to
     * reading another data file.
     *
     * Owned by this.
     */
    ctf_fs_ds_file::UP file;

    /* Weak, for context / logging / appending causes. */
    bt_self_message_iterator *self_msg_iter = nullptr;
    const bt2_common::LogCfg logCfg;
};

static enum ctf_msg_iter_medium_status medop_group_request_bytes(size_t request_sz,
                                                                 uint8_t **buffer_addr,
                                                                 size_t *buffer_sz, void *void_data)
{
    struct ctf_fs_ds_group_medops_data *data = (struct ctf_fs_ds_group_medops_data *) void_data;

    /* Return bytes from the current file. */
    return medop_request_bytes(request_sz, buffer_addr, buffer_sz, data->file.get());
}

static bt_stream *medop_group_borrow_stream(bt_stream_class *stream_class, int64_t stream_id,
                                            void *void_data)
{
    struct ctf_fs_ds_group_medops_data *data = (struct ctf_fs_ds_group_medops_data *) void_data;

    return medop_borrow_stream(stream_class, stream_id, data->file.get());
}

/*
 * Set `data->file` to prepare it to read the packet described
 * by `index_entry`.
 */

static enum ctf_msg_iter_medium_status ctf_fs_ds_group_medops_set_file(
    struct ctf_fs_ds_group_medops_data *data, struct ctf_fs_ds_index_entry *index_entry,
    bt_self_message_iterator *self_msg_iter, const bt2_common::LogCfg& logCfg)
{
    BT_ASSERT(data);
    BT_ASSERT(index_entry);

    /* Check if that file is already the one mapped. */
    if (!data->file || strcmp(index_entry->path, data->file->file->path.c_str()) != 0) {
        /* Create the new file. */
        data->file = ctf_fs_ds_file_create(data->ds_file_group->ctf_fs_trace,
                                           data->ds_file_group->stream, index_entry->path, logCfg);

        if (!data->file) {
            BT_MSG_ITER_LOGE_APPEND_CAUSE(self_msg_iter, "failed to create ctf_fs_ds_file.");
            return CTF_MSG_ITER_MEDIUM_STATUS_ERROR;
        }
    }

    /*
     * Ensure the right portion of the file will be returned on the next
     * request_bytes call.
     */
    return ds_file_mmap(data->file.get(), index_entry->offset.bytes());
}

static enum ctf_msg_iter_medium_status medop_group_switch_packet(void *void_data)
{
    struct ctf_fs_ds_group_medops_data *data = (struct ctf_fs_ds_group_medops_data *) void_data;

    /* If we have gone through all index entries, we are done. */
    if (data->next_index_entry_index >= data->ds_file_group->index.entries.size()) {
        return CTF_MSG_ITER_MEDIUM_STATUS_EOF;
    }

    /*
     * Otherwise, look up the next index entry / packet and prepare it
     *  for reading.
     */
    ctf_fs_ds_index_entry& index_entry =
        data->ds_file_group->index.entries[data->next_index_entry_index];

    ctf_msg_iter_medium_status status =
        ctf_fs_ds_group_medops_set_file(data, &index_entry, data->self_msg_iter, data->logCfg);
    if (status != CTF_MSG_ITER_MEDIUM_STATUS_OK) {
        return status;
    }

    data->next_index_entry_index++;

    return CTF_MSG_ITER_MEDIUM_STATUS_OK;
}

void ctf_fs_ds_group_medops_data_deleter::operator()(ctf_fs_ds_group_medops_data *data)
{
    delete data;
}

enum ctf_msg_iter_medium_status ctf_fs_ds_group_medops_data_create(
    struct ctf_fs_ds_file_group *ds_file_group, bt_self_message_iterator *self_msg_iter,
    const bt2_common::LogCfg& logCfg, ctf_fs_ds_group_medops_data_up& out)
{
    BT_ASSERT(self_msg_iter);
    BT_ASSERT(ds_file_group);
    BT_ASSERT(!ds_file_group->index.entries.empty());

    out.reset(new ctf_fs_ds_group_medops_data {logCfg});

    out->ds_file_group = ds_file_group;
    out->self_msg_iter = self_msg_iter;

    /*
     * No need to prepare the first file.  ctf_msg_iter will call
     * switch_packet before reading the first packet, it will be
     * done then.
     */

    return CTF_MSG_ITER_MEDIUM_STATUS_OK;
}

void ctf_fs_ds_group_medops_data_reset(struct ctf_fs_ds_group_medops_data *data)
{
    data->next_index_entry_index = 0;
}

struct ctf_msg_iter_medium_ops ctf_fs_ds_group_medops = {
    .request_bytes = medop_group_request_bytes,

    /*
     * We don't support seeking using this medops.  It would probably be
     * possible, but it's not needed at the moment.
     */
    .seek = NULL,

    .switch_packet = medop_group_switch_packet,
    .borrow_stream = medop_group_borrow_stream,
};

static int convert_cycles_to_ns(struct ctf_clock_class *clock_class, uint64_t cycles, int64_t *ns)
{
    return bt_util_clock_cycles_to_ns_from_origin(cycles, clock_class->frequency,
                                                  clock_class->offset_seconds,
                                                  clock_class->offset_cycles, ns);
}

static nonstd::optional<ctf_fs_ds_index>
build_index_from_idx_file(struct ctf_fs_ds_file *ds_file, struct ctf_fs_ds_file_info *file_info,
                          struct ctf_msg_iter *msg_iter)
{
    const bt2_common::LogCfg& logCfg = ds_file->logCfg;

    BT_CLOGI("Building index from .idx file of stream file %s", ds_file->file->path.c_str());
    ctf_msg_iter_packet_properties props;
    int ret = ctf_msg_iter_get_packet_properties(msg_iter, &props);
    if (ret) {
        BT_CLOGI_STR("Cannot read first packet's header and context fields.");
        return nonstd::nullopt;
    }

    ctf_stream_class *sc =
        ctf_trace_class_borrow_stream_class_by_id(ds_file->metadata->tc, props.stream_class_id);
    BT_ASSERT(sc);
    if (!sc->default_clock_class) {
        BT_CLOGI_STR("Cannot find stream class's default clock class.");
        return nonstd::nullopt;
    }

    /* Look for index file in relative path index/name.idx. */
    bt2_common::GCharUP basename {g_path_get_basename(ds_file->file->path.c_str())};
    if (!basename) {
        BT_CLOGE("Cannot get the basename of datastream file %s", ds_file->file->path.c_str());
        return nonstd::nullopt;
    }

    bt2_common::GCharUP directory {g_path_get_dirname(ds_file->file->path.c_str())};
    if (!directory) {
        BT_CLOGE("Cannot get dirname of datastream file %s", ds_file->file->path.c_str());
        return nonstd::nullopt;
    }

    std::string index_basename = basename.get();
    index_basename += ".idx";

    bt2_common::GCharUP index_file_path {
        g_build_filename(directory.get(), "index", index_basename.c_str(), NULL)};
    bt2_common::GMappedFileUP mapped_file {g_mapped_file_new(index_file_path.get(), FALSE, NULL)};
    if (!mapped_file) {
        BT_CLOGD("Cannot create new mapped file %s", index_file_path.get());
        return nonstd::nullopt;
    }

    /*
     * The g_mapped_file API limits us to 4GB files on 32-bit.
     * Traces with such large indexes have never been seen in the wild,
     * but this would need to be adjusted to support them.
     */
    gsize filesize = g_mapped_file_get_length(mapped_file.get());
    if (filesize < sizeof(ctf_packet_index_file_hdr)) {
        BT_CLOGW("Invalid LTTng trace index file: "
                 "file size (%zu bytes) < header size (%zu bytes)",
                 filesize, sizeof(ctf_packet_index_file_hdr));
        return nonstd::nullopt;
    }

    const char *mmap_begin = g_mapped_file_get_contents(mapped_file.get());
    const ctf_packet_index_file_hdr *header = (const ctf_packet_index_file_hdr *) mmap_begin;

    const char *file_pos = g_mapped_file_get_contents(mapped_file.get()) + sizeof(*header);
    if (be32toh(header->magic) != CTF_INDEX_MAGIC) {
        BT_CLOGW_STR("Invalid LTTng trace index: \"magic\" field validation failed");
        return nonstd::nullopt;
    }

    uint32_t version_major = be32toh(header->index_major);
    uint32_t version_minor = be32toh(header->index_minor);
    if (version_major != 1) {
        BT_CLOGW("Unknown LTTng trace index version: "
                 "major=%" PRIu32 ", minor=%" PRIu32,
                 version_major, version_minor);
        return nonstd::nullopt;
    }

    size_t file_index_entry_size = be32toh(header->packet_index_len);
    if (file_index_entry_size < CTF_INDEX_1_0_SIZE) {
        BT_CLOGW(
            "Invalid `packet_index_len` in LTTng trace index file (`packet_index_len` < CTF index 1.0 index entry size): "
            "packet_index_len=%zu, CTF_INDEX_1_0_SIZE=%zu",
            file_index_entry_size, CTF_INDEX_1_0_SIZE);
        return nonstd::nullopt;
    }

    size_t file_entry_count = (filesize - sizeof(*header)) / file_index_entry_size;
    if ((filesize - sizeof(*header)) % file_index_entry_size) {
        BT_CLOGW("Invalid LTTng trace index: the index's size after the header "
                 "(%zu bytes) is not a multiple of the index entry size "
                 "(%zu bytes)",
                 (filesize - sizeof(*header)), sizeof(*header));
        return nonstd::nullopt;
    }

    ctf_fs_ds_index index;
    ctf_fs_ds_index_entry *prev_index_entry = nullptr;
    bt2_common::DataLen totalPacketsSize = bt2_common::DataLen::fromBytes(0);

    for (size_t i = 0; i < file_entry_count; i++) {
        struct ctf_packet_index *file_index = (struct ctf_packet_index *) file_pos;
        bt2_common::DataLen packetSize =
            bt2_common::DataLen::fromBits(be64toh(file_index->packet_size));

        if (packetSize.hasExtraBits()) {
            BT_CLOGW("Invalid packet size encountered in LTTng trace index file");
            return nonstd::nullopt;
        }

        bt2_common::DataLen offset = bt2_common::DataLen::fromBytes(be64toh(file_index->offset));
        if (i != 0 && offset < prev_index_entry->offset) {
            BT_CLOGW("Invalid, non-monotonic, packet offset encountered in LTTng trace index file: "
                     "previous offset=%llu bytes, current offset=%llu bytes",
                     prev_index_entry->offset.bytes(), offset.bytes());
            return nonstd::nullopt;
        }

        ctf_fs_ds_index_entry index_entry {file_info->path.c_str(), offset, packetSize};
        index_entry.timestamp_begin = be64toh(file_index->timestamp_begin);
        index_entry.timestamp_end = be64toh(file_index->timestamp_end);
        if (index_entry.timestamp_end < index_entry.timestamp_begin) {
            BT_CLOGW(
                "Invalid packet time bounds encountered in LTTng trace index file (begin > end): "
                "timestamp_begin=%" PRIu64 "timestamp_end=%" PRIu64,
                index_entry.timestamp_begin, index_entry.timestamp_end);
            return nonstd::nullopt;
        }

        /* Convert the packet's bound to nanoseconds since Epoch. */
        ret = convert_cycles_to_ns(sc->default_clock_class, index_entry.timestamp_begin,
                                   &index_entry.timestamp_begin_ns);
        if (ret) {
            BT_CLOGI_STR(
                "Failed to convert raw timestamp to nanoseconds since Epoch during index parsing");
            return nonstd::nullopt;
        }
        ret = convert_cycles_to_ns(sc->default_clock_class, index_entry.timestamp_end,
                                   &index_entry.timestamp_end_ns);
        if (ret) {
            BT_CLOGI_STR(
                "Failed to convert raw timestamp to nanoseconds since Epoch during LTTng trace index parsing");
            return nonstd::nullopt;
        }

        if (version_minor >= 1) {
            index_entry.packet_seq_num = be64toh(file_index->packet_seq_num);
        }

        totalPacketsSize += packetSize;
        file_pos += file_index_entry_size;

        index.entries.emplace_back(index_entry);

        prev_index_entry = &index.entries.back();
    }

    /* Validate that the index addresses the complete stream. */
    if (ds_file->file->size != totalPacketsSize.bytes()) {
        BT_CLOGW("Invalid LTTng trace index file; indexed size != stream file size: "
                 "file-size=%" PRIu64 " bytes, total-packets-size=%llu bytes",
                 ds_file->file->size, totalPacketsSize.bytes());
        return nonstd::nullopt;
    }

    return index;
}

static int init_index_entry(ctf_fs_ds_index_entry& entry, struct ctf_fs_ds_file *ds_file,
                            struct ctf_msg_iter_packet_properties *props)
{
    ctf_stream_class *sc =
        ctf_trace_class_borrow_stream_class_by_id(ds_file->metadata->tc, props->stream_class_id);
    BT_ASSERT(sc);
    const bt2_common::LogCfg& logCfg = ds_file->logCfg;

    if (props->snapshots.beginning_clock != UINT64_C(-1)) {
        entry.timestamp_begin = props->snapshots.beginning_clock;

        /* Convert the packet's bound to nanoseconds since Epoch. */
        int ret = convert_cycles_to_ns(sc->default_clock_class, props->snapshots.beginning_clock,
                                       &entry.timestamp_begin_ns);
        if (ret) {
            BT_CLOGI_STR("Failed to convert raw timestamp to nanoseconds since Epoch.");
            return ret;
        }
    } else {
        entry.timestamp_begin = UINT64_C(-1);
        entry.timestamp_begin_ns = UINT64_C(-1);
    }

    if (props->snapshots.end_clock != UINT64_C(-1)) {
        entry.timestamp_end = props->snapshots.end_clock;

        /* Convert the packet's bound to nanoseconds since Epoch. */
        int ret = convert_cycles_to_ns(sc->default_clock_class, props->snapshots.end_clock,
                                       &entry.timestamp_end_ns);
        if (ret) {
            BT_CLOGI_STR("Failed to convert raw timestamp to nanoseconds since Epoch.");
            return ret;
        }
    } else {
        entry.timestamp_end = UINT64_C(-1);
        entry.timestamp_end_ns = UINT64_C(-1);
    }

    return 0;
}

static nonstd::optional<ctf_fs_ds_index>
build_index_from_stream_file(struct ctf_fs_ds_file *ds_file, struct ctf_fs_ds_file_info *file_info,
                             struct ctf_msg_iter *msg_iter)
{
    const bt2_common::LogCfg& logCfg = ds_file->logCfg;

    BT_CLOGI("Indexing stream file %s", ds_file->file->path.c_str());

    ctf_fs_ds_index index;
    bt2_common::DataLen currentPacketOffset = bt2_common::DataLen::fromBytes(0);

    while (true) {
        struct ctf_msg_iter_packet_properties props;

        if (currentPacketOffset.bytes() > ds_file->file->size) {
            BT_CLOGE_STR("Unexpected current packet's offset (larger than file).");
            return nonstd::nullopt;
        } else if (currentPacketOffset.bytes() == ds_file->file->size) {
            /* No more data */
            break;
        }

        ctf_msg_iter_status iter_status = ctf_msg_iter_seek(msg_iter, currentPacketOffset.bytes());
        if (iter_status != CTF_MSG_ITER_STATUS_OK) {
            return nonstd::nullopt;
        }

        iter_status = ctf_msg_iter_get_packet_properties(msg_iter, &props);
        if (iter_status != CTF_MSG_ITER_STATUS_OK) {
            return nonstd::nullopt;
        }

        /*
         * Get the current packet size from the packet header, if set.  Else,
         * assume there is a single packet in the file, so take the file size
         * as the packet size.
         */
        bt2_common::DataLen currentPacketSize =
            props.exp_packet_total_size >= 0 ?
                bt2_common::DataLen::fromBits(props.exp_packet_total_size) :
                bt2_common::DataLen::fromBytes(ds_file->file->size);

        if ((currentPacketOffset + currentPacketSize).bytes() > ds_file->file->size) {
            BT_CLOGW("Invalid packet size reported in file: stream=\"%s\", "
                     "packet-offset-bytes=%llu, packet-size-bytes=%llu, "
                     "file-size-bytes=%jd",
                     ds_file->file->path.c_str(), currentPacketOffset.bytes(),
                     currentPacketSize.bytes(), (intmax_t) ds_file->file->size);
            return nonstd::nullopt;
        }

        ctf_fs_ds_index_entry index_entry {file_info->path.c_str(), currentPacketOffset,
                                           currentPacketSize};

        int ret = init_index_entry(index_entry, ds_file, &props);
        if (ret) {
            return nonstd::nullopt;
        }

        index.entries.emplace_back(std::move(index_entry));

        currentPacketOffset += currentPacketSize;
        BT_CLOGD("Seeking to next packet: current-packet-offset-bytes=%llu, "
                 "next-packet-offset-bytes=%llu",
                 (currentPacketOffset - currentPacketSize).bytes(), currentPacketOffset.bytes());
    }

    return index;
}

BT_HIDDEN
ctf_fs_ds_file::UP ctf_fs_ds_file_create(struct ctf_fs_trace *ctf_fs_trace,
                                         nonstd::optional<bt2::Stream::Shared> stream,
                                         const char *path, const bt2_common::LogCfg& logCfg)
{
    const size_t offset_align = bt_mmap_get_offset_align_size(logCfg.logLevel());
    ctf_fs_ds_file::UP ds_file = bt2_common::makeUnique<ctf_fs_ds_file>(logCfg);

    ds_file->file = bt2_common::makeUnique<ctf_fs_file>(logCfg);
    ds_file->stream = std::move(stream);
    ds_file->metadata = ctf_fs_trace->metadata.get();
    ds_file->file->path = path;
    int ret = ctf_fs_file_open(ds_file->file.get(), "rb");
    if (ret) {
        return nullptr;
    }

    ds_file->mmap_max_len = offset_align * 2048;

    return ds_file;
}

BT_HIDDEN
nonstd::optional<ctf_fs_ds_index> ctf_fs_ds_file_build_index(struct ctf_fs_ds_file *ds_file,
                                                             struct ctf_fs_ds_file_info *file_info,
                                                             struct ctf_msg_iter *msg_iter)
{
    const bt2_common::LogCfg& logCfg = ds_file->logCfg;

    nonstd::optional<ctf_fs_ds_index> index =
        build_index_from_idx_file(ds_file, file_info, msg_iter);
    if (index) {
        return index;
    }

    BT_CLOGI("Failed to build index from .index file; "
             "falling back to stream indexing.");
    return build_index_from_stream_file(ds_file, file_info, msg_iter);
}

ctf_fs_ds_file::~ctf_fs_ds_file()
{
    (void) ds_file_munmap(this);
}

BT_HIDDEN ctf_fs_ds_file_info::UP ctf_fs_ds_file_info_create(const char *path, int64_t begin_ns)
{
    ctf_fs_ds_file_info::UP ds_file_info = bt2_common::makeUnique<ctf_fs_ds_file_info>();

    ds_file_info->path = path;
    ds_file_info->begin_ns = begin_ns;

    return ds_file_info;
}

void ctf_fs_ds_file_group::insert_ds_file_info_sorted(ctf_fs_ds_file_info::UP ds_file_info)
{
    /* Find the spot where to insert this ds_file_info. */
    auto it = this->ds_file_infos.begin();

    for (; it != this->ds_file_infos.end(); ++it) {
        const ctf_fs_ds_file_info& other_ds_file_info = **it;

        if (ds_file_info->begin_ns < other_ds_file_info.begin_ns) {
            break;
        }
    }

    this->ds_file_infos.insert(it, std::move(ds_file_info));
}
