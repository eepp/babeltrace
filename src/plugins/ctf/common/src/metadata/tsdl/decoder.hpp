/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2016-2017 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef _METADATA_DECODER_H
#define _METADATA_DECODER_H

#include <memory>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include <babeltrace2/babeltrace.h>

#include "common/macros.h"
#include "common/uuid.h"
#include "cpp-common/log-cfg.hpp"

struct ctf_trace_class;

/* A CTF metadata decoder object */
struct ctf_metadata_decoder;

/* CTF metadata decoder status */
enum ctf_metadata_decoder_status
{
    CTF_METADATA_DECODER_STATUS_OK = 0,
    CTF_METADATA_DECODER_STATUS_NONE = 1,
    CTF_METADATA_DECODER_STATUS_ERROR = -1,
    CTF_METADATA_DECODER_STATUS_INCOMPLETE = -2,
    CTF_METADATA_DECODER_STATUS_INVAL_VERSION = -3,
    CTF_METADATA_DECODER_STATUS_IR_VISITOR_ERROR = -4,
};

/* Decoding configuration */
struct ctf_metadata_decoder_config
{
    explicit ctf_metadata_decoder_config(const bt2_common::LogCfg& logCfgParam) noexcept :
        logCfg {logCfgParam}
    {
    }

    bt2_common::LogCfg logCfg;

    /* Weak, used to create a bt_trace_class, if not nullptr. */
    bt_self_component *self_comp = nullptr;

    /* Additional clock class offset to apply */
    int64_t clock_class_offset_s = 0;
    int64_t clock_class_offset_ns = 0;
    bool force_clock_class_origin_unix_epoch = false;

    /* True to create trace class objects */
    bool create_trace_class = false;

    /*
     * True to keep the plain text when content is appended with
     * ctf_metadata_decoder_append_content().
     */
    bool keep_plain_text = false;
};

struct ctf_metadata_decoder_deleter
{
    void operator()(ctf_metadata_decoder *decoder);
};

using ctf_metadata_decoder_up = std::unique_ptr<ctf_metadata_decoder, ctf_metadata_decoder_deleter>;

/*
 * Creates a CTF metadata decoder.
 *
 * Returns `NULL` on error.
 */
BT_HIDDEN
ctf_metadata_decoder_up
ctf_metadata_decoder_create(const struct ctf_metadata_decoder_config *config);

/*
 * Destroys a CTF metadata decoder that you created with
 * ctf_metadata_decoder_create().
 */
BT_HIDDEN
void ctf_metadata_decoder_destroy(struct ctf_metadata_decoder *metadata_decoder);

/*
 * Appends content to the metadata decoder.
 *
 * This function reads the metadata from the current position of `fp`
 * until the end of this file stream.
 *
 * The metadata can be packetized or not.
 *
 * The metadata chunk needs to be complete and lexically scannable, that
 * is, zero or more complete top-level blocks. If it's incomplete, this
 * function returns `CTF_METADATA_DECODER_STATUS_INCOMPLETE`. If this
 * function returns `CTF_METADATA_DECODER_STATUS_INCOMPLETE`, then you
 * need to call it again with the _same_ metadata and more to make it
 * complete. For example:
 *
 *     First call:  event { name = hell
 *     Second call: event { name = hello_world; ... };
 *
 * If everything goes as expected, this function returns
 * `CTF_METADATA_DECODER_STATUS_OK`.
 */
BT_HIDDEN
enum ctf_metadata_decoder_status
ctf_metadata_decoder_append_content(struct ctf_metadata_decoder *metadata_decoder, FILE *fp);

/*
 * Returns the trace IR trace class of this metadata decoder (new
 * reference).
 *
 * Returns `NULL` if there's none yet or if the metadata decoder is not
 * configured to create trace classes.
 */
BT_HIDDEN
bt_trace_class *ctf_metadata_decoder_get_ir_trace_class(struct ctf_metadata_decoder *mdec);

/*
 * Returns the CTF IR trace class of this metadata decoder.
 *
 * Returns `NULL` if there's none yet or if the metadata decoder is not
 * configured to create trace classes.
 */
BT_HIDDEN
struct ctf_trace_class *
ctf_metadata_decoder_borrow_ctf_trace_class(struct ctf_metadata_decoder *mdec);

/*
 * Checks whether or not a given metadata file stream `fp` is
 * packetized, setting `is_packetized` accordingly on success. On
 * success, also sets `*byte_order` to the byte order of the first
 * packet.
 *
 * This function uses `log_level` and `self_comp` for logging purposes.
 * `self_comp` can be `NULL` if not available.
 */
BT_HIDDEN
int ctf_metadata_decoder_is_packetized(FILE *fp, bool *is_packetized, int *byte_order,
                                       const bt2_common::LogCfg& logCfg);

/*
 * Returns the UUID of the decoder's trace class, if available.
 *
 * Returns:
 *
 * * `CTF_METADATA_DECODER_STATUS_OK`: success.
 * * `CTF_METADATA_DECODER_STATUS_NONE`: no UUID.
 * * `CTF_METADATA_DECODER_STATUS_INCOMPLETE`: missing metadata content.
 */
BT_HIDDEN
enum ctf_metadata_decoder_status
ctf_metadata_decoder_get_trace_class_uuid(struct ctf_metadata_decoder *mdec, bt_uuid_t uuid);

/*
 * Returns the metadata decoder's current metadata text.
 */
BT_HIDDEN
const char *ctf_metadata_decoder_get_text(struct ctf_metadata_decoder *mdec);

static inline bool ctf_metadata_decoder_is_packet_version_valid(unsigned int major,
                                                                unsigned int minor)
{
    return major == 1 && minor == 8;
}

#endif /* _METADATA_DECODER_H */
