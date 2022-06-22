/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Francis Deslauriers <francis.deslauriers@efficios.com>
 * Copyright 2016 Philippe Proulx <pproulx@efficios.com>
 * Copyright 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * Copyright 2010-2011 EfficiOS Inc. and Linux Foundation
 */

#define BT_COMP_LOG_SELF_COMP logCfg.selfComp()
#define BT_LOG_OUTPUT_LEVEL   logCfg.logLevel()
#define BT_LOG_TAG            "PLUGIN/SRC.CTF.LTTNG-LIVE/DS"
#include "logging/comp-logging.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sstream>

#include <glib.h>

#include <babeltrace2/babeltrace.h>

#include "../common/src/msg-iter/msg-iter.hpp"
#include "cpp-common/make-unique.hpp"
#include "common/assert.h"
#include "compat/mman.h"
#include "cpp-common/make-unique.hpp"
#include "data-stream.hpp"

#define STREAM_NAME_PREFIX "stream-"

static enum ctf_msg_iter_medium_status medop_request_bytes(size_t request_sz, uint8_t **buffer_addr,
                                                           size_t *buffer_sz, void *data)
{
    enum ctf_msg_iter_medium_status status = CTF_MSG_ITER_MEDIUM_STATUS_OK;
    lttng_live_stream_iterator *stream = (lttng_live_stream_iterator *) data;
    struct lttng_live_trace *trace = stream->trace;
    struct lttng_live_session *session = trace->session;
    struct lttng_live_msg_iter *live_msg_iter = session->lttng_live_msg_iter;
    uint64_t recv_len = 0;
    uint64_t len_left;
    uint64_t read_len;

    BT_ASSERT(request_sz);

    if (stream->has_stream_hung_up) {
        status = CTF_MSG_ITER_MEDIUM_STATUS_EOF;
        goto end;
    }

    len_left = stream->base_offset + stream->len - stream->offset;
    if (!len_left) {
        lttng_live_stream_iterator_set_state(stream, LTTNG_LIVE_STREAM_ACTIVE_NO_DATA);
        status = CTF_MSG_ITER_MEDIUM_STATUS_AGAIN;
        goto end;
    }

    read_len = MIN(request_sz, stream->buf.size());
    read_len = MIN(read_len, len_left);
    status = lttng_live_get_stream_bytes(live_msg_iter, stream, stream->buf.data(), stream->offset,
                                         read_len, &recv_len);
    *buffer_addr = stream->buf.data();
    *buffer_sz = recv_len;
    stream->offset += recv_len;
end:
    return status;
}

static bt_stream *medop_borrow_stream(bt_stream_class *stream_class, int64_t stream_id, void *data)
{
    lttng_live_stream_iterator *lttng_live_stream = (lttng_live_stream_iterator *) data;
    const bt2_common::LogCfg& logCfg = lttng_live_stream->logCfg;

    if (!lttng_live_stream->stream) {
        uint64_t stream_class_id = bt_stream_class_get_id(stream_class);

        BT_COMP_LOGI("Creating stream %s (ID: %" PRIu64 ") out of stream "
                     "class %" PRId64,
                     lttng_live_stream->name.c_str(), stream_id, stream_class_id);

        bt_stream *stream;

        if (stream_id < 0) {
            /*
             * No stream instance ID in the stream. It's possible
             * to encounter this situation with older version of
             * LTTng. In these cases, use the viewer_stream_id that
             * is unique for a live viewer session.
             */
            stream = bt_stream_create_with_id(stream_class,
                                              (*lttng_live_stream->trace->trace)->libObjPtr(),
                                              lttng_live_stream->viewer_stream_id);
        } else {
            stream = bt_stream_create_with_id(stream_class,
                                              (*lttng_live_stream->trace->trace)->libObjPtr(),
                                              (uint64_t) stream_id);
        }

        if (!stream) {
            BT_COMP_LOGE_APPEND_CAUSE(logCfg.selfComp(),
                                      "Cannot create stream %s (stream class ID "
                                      "%" PRId64 ", stream ID %" PRIu64 ")",
                                      lttng_live_stream->name.c_str(), stream_class_id, stream_id);
            return nullptr;
        }

        lttng_live_stream->stream = bt2::Stream::Shared::createWithoutRef(stream);

        (*lttng_live_stream->stream)->name(lttng_live_stream->name);
    }

    return (*lttng_live_stream->stream)->libObjPtr();
}

static struct ctf_msg_iter_medium_ops medops = {
    medop_request_bytes,
    nullptr,
    nullptr,
    medop_borrow_stream,
};

BT_HIDDEN
enum lttng_live_iterator_status lttng_live_lazy_msg_init(struct lttng_live_session *session,
                                                         bt_self_message_iterator *self_msg_iter)
{
    struct lttng_live_component *lttng_live = session->lttng_live_msg_iter->lttng_live_comp;
    uint64_t trace_idx, stream_iter_idx;
    const bt2_common::LogCfg& logCfg = session->logCfg;

    if (!session->lazy_stream_msg_init) {
        return LTTNG_LIVE_ITERATOR_STATUS_OK;
    }

    BT_COMP_LOGD("Lazily initializing self message iterator for live session: "
                 "session-id=%" PRIu64 ", self-msg-iter-addr=%p",
                 session->id, self_msg_iter);

    for (trace_idx = 0; trace_idx < session->traces->len; trace_idx++) {
        struct lttng_live_trace *trace =
            (lttng_live_trace *) g_ptr_array_index(session->traces, trace_idx);

        for (stream_iter_idx = 0; stream_iter_idx < trace->stream_iterators.size();
             stream_iter_idx++) {
            struct ctf_trace_class *ctf_tc;
            lttng_live_stream_iterator *stream_iter =
                trace->stream_iterators[stream_iter_idx].get();

            if (stream_iter->msg_iter) {
                continue;
            }
            ctf_tc = ctf_metadata_decoder_borrow_ctf_trace_class(trace->metadata->decoder.get());
            BT_COMP_LOGD("Creating CTF message iterator: "
                         "session-id=%" PRIu64 ", ctf-tc-addr=%p, "
                         "stream-iter-name=%s, self-msg-iter-addr=%p",
                         session->id, ctf_tc, stream_iter->name.c_str(), self_msg_iter);
            stream_iter->msg_iter = ctf_msg_iter_create(ctf_tc, lttng_live->max_query_size, medops,
                                                        stream_iter, self_msg_iter, logCfg);
            if (!stream_iter->msg_iter) {
                BT_COMP_LOGE_APPEND_CAUSE(logCfg.selfComp(),
                                          "Failed to create CTF message iterator");
                goto error;
            }
        }
    }

    session->lazy_stream_msg_init = false;

    return LTTNG_LIVE_ITERATOR_STATUS_OK;

error:
    return LTTNG_LIVE_ITERATOR_STATUS_ERROR;
}

BT_HIDDEN
struct lttng_live_stream_iterator *
lttng_live_stream_iterator_create(struct lttng_live_session *session, uint64_t ctf_trace_id,
                                  uint64_t stream_id, bt_self_message_iterator *self_msg_iter)
{
    struct lttng_live_component *lttng_live;
    struct lttng_live_trace *trace;
    std::stringstream nameSs;

    BT_ASSERT(session);
    BT_ASSERT(session->lttng_live_msg_iter);
    BT_ASSERT(session->lttng_live_msg_iter->lttng_live_comp);

    const bt2_common::LogCfg& logCfg = session->logCfg;

    lttng_live = session->lttng_live_msg_iter->lttng_live_comp;

    lttng_live_stream_iterator::UP stream_iter =
        bt2_common::makeUnique<lttng_live_stream_iterator>(logCfg);
    trace = lttng_live_session_borrow_or_create_trace_by_id(session, ctf_trace_id);
    if (!trace) {
        BT_COMP_LOGE_APPEND_CAUSE(logCfg.selfComp(), "Failed to borrow CTF trace.");
        return nullptr;
    }

    stream_iter->trace = trace;
    stream_iter->state = LTTNG_LIVE_STREAM_ACTIVE_NO_DATA;
    stream_iter->viewer_stream_id = stream_id;

    stream_iter->ctf_stream_class_id.is_set = false;
    stream_iter->ctf_stream_class_id.value = UINT64_MAX;

    stream_iter->last_inactivity_ts.is_set = false;
    stream_iter->last_inactivity_ts.value = 0;

    if (trace->trace) {
        struct ctf_trace_class *ctf_tc =
            ctf_metadata_decoder_borrow_ctf_trace_class(trace->metadata->decoder.get());
        BT_ASSERT(!stream_iter->msg_iter);
        stream_iter->msg_iter = ctf_msg_iter_create(ctf_tc, lttng_live->max_query_size, medops,
                                                    stream_iter.get(), self_msg_iter, logCfg);
        if (!stream_iter->msg_iter) {
            BT_COMP_LOGE_APPEND_CAUSE(logCfg.selfComp(), "Failed to create CTF message iterator");
            return nullptr;
        }
    }
    stream_iter->buf.resize(lttng_live->max_query_size);

    nameSs << STREAM_NAME_PREFIX << stream_iter->viewer_stream_id;
    stream_iter->name = nameSs.str();

    lttng_live_stream_iterator *ret = stream_iter.get();
    trace->stream_iterators.emplace_back(std::move(stream_iter));

    /* Track the number of active stream iterator. */
    session->lttng_live_msg_iter->active_stream_iter++;

    return ret;
}

lttng_live_stream_iterator::~lttng_live_stream_iterator()
{
    /* Track the number of active stream iterator. */
    this->trace->session->lttng_live_msg_iter->active_stream_iter--;
}