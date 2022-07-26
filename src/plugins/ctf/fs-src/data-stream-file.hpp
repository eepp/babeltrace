/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2016 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef CTF_FS_DS_FILE_H
#define CTF_FS_DS_FILE_H

#include <stdio.h>
#include <stdbool.h>
#include <glib.h>
#include <memory>
#include "common/macros.h"
#include <babeltrace2/babeltrace.h>

#include "../common/src/msg-iter/msg-iter.hpp"
#include "cpp-common/data-len.hpp"
#include "lttng-index.hpp"
#include "cpp-common/log-cfg.hpp"

struct ctf_fs_component;
struct ctf_fs_file;
struct ctf_fs_trace;
struct ctf_fs_ds_group_medops_data;

struct ctf_fs_ds_file_info
{
    /* Owned by this. */
    GString *path = nullptr;

    /* Guaranteed to be set, as opposed to the index. */
    int64_t begin_ns = 0;
};

struct ctf_fs_metadata;

struct ctf_fs_ds_file
{
    explicit ctf_fs_ds_file(const bt2_common::LogCfg& logCfgParam) noexcept : logCfg {logCfgParam}
    {
    }

    const bt2_common::LogCfg logCfg;

    /* Weak */
    struct ctf_fs_metadata *metadata = nullptr;

    /* Owned by this */
    struct ctf_fs_file *file = nullptr;

    /* Owned by this */
    bt_stream *stream = nullptr;

    void *mmap_addr = nullptr;

    /*
     * Max length of chunk to mmap() when updating the current mapping.
     * This value must be page-aligned.
     */
    size_t mmap_max_len = 0;

    /* Length of the current mapping. Never exceeds the file's length. */
    size_t mmap_len = 0;

    /* Offset in the file where the current mapping starts. */
    off_t mmap_offset_in_file = 0;

    /*
     * Offset, in the current mapping, of the address to return on the next
     * request.
     */
    off_t request_offset_in_mapping = 0;
};

struct ctf_fs_ds_index_entry
{
    ctf_fs_ds_index_entry(bt2_common::DataLen offsetParam, bt2_common::DataLen packetSizeParam) :
        offset(offsetParam), packetSize(packetSizeParam)
    {
    }

    /* Weak, belongs to ctf_fs_ds_file_info. */
    const char *path = nullptr;

    /* Position of the packet from the beginning of the file. */
    const bt2_common::DataLen offset;

    /* Size of the packet. */
    const bt2_common::DataLen packetSize;

    /*
     * Extracted from the packet context, relative to the respective fields'
     * mapped clock classes (in cycles).
     */
    uint64_t timestamp_begin = 0, timestamp_end = 0;

    /*
     * Converted from the packet context, relative to the trace's EPOCH
     * (in ns since EPOCH).
     */
    int64_t timestamp_begin_ns = 0, timestamp_end_ns = 0;

    /*
     * Packet sequence number, or UINT64_MAX if not present in the index.
     */
    uint64_t packet_seq_num = 0;
};

struct ctf_fs_ds_index
{
    /* Array of pointer to struct ctf_fs_ds_index_entry. */
    GPtrArray *entries = nullptr;
};

struct ctf_fs_ds_file_group_deleter
{
    void operator()(struct ctf_fs_ds_file_group *group);
};

struct ctf_fs_ds_file_group
{
    using UP = std::unique_ptr<ctf_fs_ds_file_group, ctf_fs_ds_file_group_deleter>;

    /*
     * Array of struct ctf_fs_ds_file_info, owned by this.
     *
     * This is an _ordered_ array of data stream file infos which
     * belong to this group (a single stream instance).
     *
     * You can call ctf_fs_ds_file_create() with one of those paths
     * and the trace IR stream below.
     */
    GPtrArray *ds_file_infos = nullptr;

    /* Owned by this */
    struct ctf_stream_class *sc = nullptr;

    /* Owned by this */
    bt_stream *stream = nullptr;

    /* Stream (instance) ID; -1ULL means none */
    uint64_t stream_id = 0;

    /* Weak, belongs to component */
    struct ctf_fs_trace *ctf_fs_trace = nullptr;

    /*
     * Owned by this.
     */
    struct ctf_fs_ds_index *index = nullptr;
};

struct ctf_fs_ds_file *ctf_fs_ds_file_create(struct ctf_fs_trace *ctf_fs_trace, bt_stream *stream,
                                             const char *path, const bt2_common::LogCfg& logCfg);

void ctf_fs_ds_file_destroy(struct ctf_fs_ds_file *stream);

struct ctf_fs_ds_index *ctf_fs_ds_file_build_index(struct ctf_fs_ds_file *ds_file,
                                                   struct ctf_fs_ds_file_info *ds_file_info,
                                                   struct ctf_msg_iter *msg_iter);

struct ctf_fs_ds_index *ctf_fs_ds_index_create(const bt2_common::LogCfg& logCfg);

void ctf_fs_ds_index_destroy(struct ctf_fs_ds_index *index);

BT_HIDDEN void ctf_fs_ds_file_info_destroy(struct ctf_fs_ds_file_info *ds_file_info);

BT_HIDDEN struct ctf_fs_ds_file_info *ctf_fs_ds_file_info_create(const char *path,
                                                                 int64_t begin_ns);

BT_HIDDEN ctf_fs_ds_file_group::UP ctf_fs_ds_file_group_create(struct ctf_fs_trace *ctf_fs_trace,
                                                               struct ctf_stream_class *sc,
                                                               uint64_t stream_instance_id,
                                                               struct ctf_fs_ds_index *index);

/*
 * Medium operations to iterate on a single ctf_fs_ds_file.
 *
 * The data pointer when using this must be a pointer to the ctf_fs_ds_file.
 */
extern struct ctf_msg_iter_medium_ops ctf_fs_ds_file_medops;

/*
 * Medium operations to iterate on the packet of a ctf_fs_ds_group.
 *
 * The iteration is done based on the index of the group.
 *
 * The data pointer when using these medops must be a pointer to a ctf_fs_ds
 * group_medops_data structure.
 */
extern struct ctf_msg_iter_medium_ops ctf_fs_ds_group_medops;

enum ctf_msg_iter_medium_status ctf_fs_ds_group_medops_data_create(
    struct ctf_fs_ds_file_group *ds_file_group, bt_self_message_iterator *self_msg_iter,
    const bt2_common::LogCfg& logCfg, struct ctf_fs_ds_group_medops_data **out);

void ctf_fs_ds_group_medops_data_reset(struct ctf_fs_ds_group_medops_data *data);

void ctf_fs_ds_group_medops_data_destroy(struct ctf_fs_ds_group_medops_data *data);

#endif /* CTF_FS_DS_FILE_H */
