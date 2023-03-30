/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Francis Deslauriers <francis.deslauriers@efficios.com>
 * Copyright 2016 Philippe Proulx <pproulx@efficios.com>
 * Copyright 2010-2011 EfficiOS Inc. and Linux Foundation
 */

#define BT_CLOG_CFG logCfg
#define BT_LOG_TAG  "PLUGIN/SRC.CTF.LTTNG-LIVE/META"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <glib.h>
#include "compat/memstream.h"
#include <babeltrace2/babeltrace.h>

#include "cpp-common/libc-up.hpp"

#include "metadata.hpp"
#include "../common/src/metadata/tsdl/ctf-meta-configure-ir-trace.hpp"
#include "cpp-common/cfg-logging.hpp"
#include "cpp-common/cfg-logging-error-reporting.hpp"

#define TSDL_MAGIC 0x75d11d57

struct packet_header
{
    uint32_t magic;
    uint8_t uuid[16];
    uint32_t checksum;
    uint32_t content_size;
    uint32_t packet_size;
    uint8_t compression_scheme;
    uint8_t encryption_scheme;
    uint8_t checksum_scheme;
    uint8_t major;
    uint8_t minor;
} __attribute__((__packed__));

static bool stream_classes_all_have_default_clock_class(bt2::ConstTraceClass tc,
                                                        const bt2_common::LogCfg& logCfg)
{
    for (std::uint64_t i = 0; i < tc.size(); ++i) {
        bt2::ConstStreamClass sc = tc[i];
        nonstd::optional<bt2::ConstClockClass> cc = sc.defaultClockClass();

        if (!cc) {
            BT_CLOGE_APPEND_CAUSE("Stream class doesn't have a default clock class: "
                                  "sc-id=%" PRIu64 ", sc-name=\"%s\"",
                                  sc.id(), sc.name()->c_str());
            return false;
        }
    }

    return true;
}
/*
 * Iterate over the stream classes and returns the first clock class
 * encountered. This is useful to create message iterator inactivity message as
 * we don't need a particular clock class.
 */
static bt2::ConstClockClass borrow_any_clock_class(bt2::ConstTraceClass tc)
{
    return *tc[0].defaultClockClass();
}

enum lttng_live_iterator_status lttng_live_metadata_update(struct lttng_live_trace *trace)
{
    struct lttng_live_session *session = trace->session;
    struct lttng_live_metadata *metadata = trace->metadata.get();
    bool keep_receiving;
    const bt2_common::LogCfg& logCfg = trace->logCfg;
    enum lttng_live_get_one_metadata_status metadata_status;

    BT_CLOGD("Updating metadata for trace: session-id=%" PRIu64 ", trace-id=%" PRIu64, session->id,
             trace->id);

    /* No metadata stream yet. */
    if (!metadata) {
        if (session->closed) {
            /*
             * The session is closed AND we never received any
             * metadata this indicates that we will never receive
             * any metadata.
             */
            return LTTNG_LIVE_ITERATOR_STATUS_END;
        } else if (session->new_streams_needed) {
            return LTTNG_LIVE_ITERATOR_STATUS_AGAIN;
        } else {
            session->new_streams_needed = true;
            return LTTNG_LIVE_ITERATOR_STATUS_CONTINUE;
        }
    }

    if (trace->metadata_stream_state != LTTNG_LIVE_METADATA_STREAM_STATE_NEEDED) {
        return LTTNG_LIVE_ITERATOR_STATUS_OK;
    }

    keep_receiving = true;
    /* Grab all available metadata. */
    std::vector<uint8_t> metadataBuf;
    while (keep_receiving) {
        /*
         * lttng_live_get_one_metadata_packet() asks the Relay Daemon
         * for new metadata. If new metadata is received, the function
         * writes it to the provided file handle and updates the
         * reply_len output parameter. We call this function in loop
         * until it returns _END meaning that no new metadata is
         * available.
         * We may receive a _CLOSED status if the metadata stream we
         * are requesting is no longer available on the relay.
         * If we receive an _ERROR status, it means there was a
         * networking, allocating, or some other unrecoverable error.
         */
        metadata_status = lttng_live_get_one_metadata_packet(trace, metadataBuf);

        switch (metadata_status) {
        case LTTNG_LIVE_GET_ONE_METADATA_STATUS_OK:
            break;
        case LTTNG_LIVE_GET_ONE_METADATA_STATUS_END:
            keep_receiving = false;
            break;
        case LTTNG_LIVE_GET_ONE_METADATA_STATUS_CLOSED:
            BT_CLOGD("Metadata stream was closed by the Relay, the trace is no longer active: "
                     "trace-id=%" PRIu64 ", metadata-stream-id=%" PRIu64,
                     trace->id, metadata->stream_id);
            /*
             * The stream was closed and we received everything
             * there was to receive for this metadata stream.
             * We go on with the decoding of what we received. So
             * that data stream can be decoded.
             */
            keep_receiving = false;
            trace->metadata_stream_state = LTTNG_LIVE_METADATA_STREAM_STATE_CLOSED;
            break;
        case LTTNG_LIVE_GET_ONE_METADATA_STATUS_ERROR:
            BT_CLOGE_APPEND_CAUSE("Error getting one trace metadata packet: "
                                  "trace-id=%" PRIu64,
                                  trace->id);
            return LTTNG_LIVE_ITERATOR_STATUS_ERROR;
        default:
            bt_common_abort();
        }
    }

    if (metadataBuf.empty()) {
        if (!trace->trace) {
            return LTTNG_LIVE_ITERATOR_STATUS_AGAIN;
        }

        /* The relay sent zero bytes of metdata. */
        trace->metadata_stream_state = LTTNG_LIVE_METADATA_STREAM_STATE_NOT_NEEDED;
        return LTTNG_LIVE_ITERATOR_STATUS_OK;
    }

    /*
     * The call to ctf_metadata_decoder_append_content() will append
     * new metadata to our current trace class.
     */
    BT_CLOGD("Appending new metadata to the ctf_trace class");
    metadata->parseSection(metadataBuf.data(), metadataBuf.data() + metadataBuf.size());
    if (!trace->trace) {
        const ctf::src::TraceCls *ctfTraceCls = metadata->traceCls();
        BT_ASSERT(ctfTraceCls);
        nonstd::optional<bt2::TraceClass> irTraceCls = ctfTraceCls->libCls();

        if (irTraceCls) {
            trace->trace = irTraceCls->instantiate();

            ctf_trace_class_configure_ir_trace(*ctfTraceCls, **trace->trace, logCfg);

            if (!stream_classes_all_have_default_clock_class((*trace->trace)->cls(), logCfg)) {
                /* Error logged in function. */
                return LTTNG_LIVE_ITERATOR_STATUS_ERROR;
            }

            trace->clock_class = borrow_any_clock_class((*trace->trace)->cls());
        }
    }

    /* The metadata was updated succesfully. */
    trace->metadata_stream_state = LTTNG_LIVE_METADATA_STREAM_STATE_NOT_NEEDED;

    return LTTNG_LIVE_ITERATOR_STATUS_OK;
}

int lttng_live_metadata_create_stream(struct lttng_live_session *session, uint64_t ctf_trace_id,
                                      uint64_t stream_id, const char *trace_name)
{
    const bt2_common::LogCfg& logCfg = session->logCfg;
    struct lttng_live_trace *trace;
    lttng_live_metadata::UP metadata =
        bt2_common::makeUnique<lttng_live_metadata>(session->self_comp, logCfg);

    metadata->stream_id = stream_id;

    trace = lttng_live_session_borrow_or_create_trace_by_id(session, ctf_trace_id);
    if (!trace) {
        BT_CLOGE_APPEND_CAUSE("Failed to borrow trace");
        return -1;
    }
    trace->metadata = std::move(metadata);
    return 0;
}
