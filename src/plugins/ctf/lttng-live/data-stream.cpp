/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Francis Deslauriers <francis.deslauriers@efficios.com>
 * Copyright 2016 Philippe Proulx <pproulx@efficios.com>
 * Copyright 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * Copyright 2010-2011 EfficiOS Inc. and Linux Foundation
 */

#define BT_CLOG_CFG logCfg
#define BT_LOG_TAG  "PLUGIN/SRC.CTF.LTTNG-LIVE/DS"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sstream>

#include <glib.h>

#include <babeltrace2/babeltrace.h>

#include "cpp-common/make-unique.hpp"
#include "common/assert.h"
#include "compat/mman.h"
#include "../common/src/pkt-props.hpp"
#include "cpp-common/make-unique.hpp"
#include "data-stream.hpp"
#include "cpp-common/exc.hpp"
#include "cpp-common/cfg-logging-error-reporting.hpp"
#include "cpp-common/cfg-logging-error-reporting-throw.hpp"

#define STREAM_NAME_PREFIX "stream-"

namespace ctf {
namespace src {
namespace live {

Buf CtfLiveMedium::buf(bt2_common::DataLen requestedOffsetInStream, bt2_common::DataLen minSize)
{
    const bt2_common::LogCfg& logCfg = _mLiveStreamIter.logCfg;
    BT_CLOGD("CtfLiveMedium::buf called: stream-id=%" PRId64
             ", offset-bytes=%llu, min-size-bytes=%llu",
             _mLiveStreamIter.stream ? (*_mLiveStreamIter.stream)->id() : -1,
             requestedOffsetInStream.bytes(), minSize.bytes());

    if (_mLiveStreamIter.has_stream_hung_up)
        throw NoData {};

    BT_ASSERT(requestedOffsetInStream >= _mCurPktBegOffsetInStream);
    bt2_common::DataLen requestedOffsetInPacket =
        requestedOffsetInStream - _mCurPktBegOffsetInStream;

    BT_ASSERT(_mLiveStreamIter.curPktInfo);

    if (requestedOffsetInPacket == _mLiveStreamIter.curPktInfo->len) {
        _mCurPktBegOffsetInStream += _mLiveStreamIter.curPktInfo->len;
        _mLiveStreamIter.curPktInfo.reset();
        lttng_live_stream_iterator_set_state(&_mLiveStreamIter, LTTNG_LIVE_STREAM_ACTIVE_NO_DATA);
        throw bt2_common::TryAgain {};
    }

    bt2_common::DataLen requestedOffsetInRelay =
        _mLiveStreamIter.curPktInfo->offsetInRelay + requestedOffsetInPacket;
    bt2_common::DataLen lenUntilEndOfPacket =
        _mLiveStreamIter.curPktInfo->len - requestedOffsetInPacket;

    bt2_common::DataLen maxReqLen = bt2_common::DataLen::fromBytes(
        _mLiveStreamIter.trace->session->lttng_live_msg_iter->lttng_live_comp->max_query_size);
    bt2_common::DataLen reqLen = std::min(lenUntilEndOfPacket, maxReqLen);
    uint64_t recvLen;

    _mBuf.resize(reqLen.bytes());

    lttng_live_get_stream_bytes_status status = lttng_live_get_stream_bytes(
        _mLiveStreamIter.trace->session->lttng_live_msg_iter, &_mLiveStreamIter, _mBuf.data(),
        requestedOffsetInRelay.bytes(), reqLen.bytes(), &recvLen);
    switch (status) {
    case LTTNG_LIVE_GET_STREAM_BYTES_STATUS_OK:
        _mBuf.resize(recvLen);
        break;

    case LTTNG_LIVE_GET_STREAM_BYTES_STATUS_AGAIN:
        BT_CLOGD("CtfLiveMedium::buf try again");
        throw bt2_common::TryAgain();

    case LTTNG_LIVE_GET_STREAM_BYTES_STATUS_EOF:
        BT_CLOGD("CtfLiveMedium::buf eof");
        throw NoData();

    case LTTNG_LIVE_GET_STREAM_BYTES_STATUS_ERROR:
        BT_CLOGD("CtfLiveMedium::buf error");
        throw bt2_common::Error();
    }

    Buf buf {_mBuf.data(), bt2_common::DataLen::fromBytes(_mBuf.size())};

    BT_CLOGD("CtfLiveMedium::buf returns: stream-id=%" PRId64 ", buf-addr=%p, buf-size-bytes=%llu",
             _mLiveStreamIter.stream ? (*_mLiveStreamIter.stream)->id() : -1, buf.addr(),
             buf.size().bytes());

    return buf;
}

} /* namespace live */
} /* namespace src */
} /* namespace ctf */

lttng_live_iterator_status
lttng_live_stream_iterator_create_msg_iter(lttng_live_stream_iterator *liveStreamIter)
{
    BT_ASSERT(!liveStreamIter->msg_iter);
    BT_ASSERT(!liveStreamIter->stream);
    lttng_live_trace *trace = liveStreamIter->trace;
    lttng_live_msg_iter *liveMsgIter = trace->session->lttng_live_msg_iter;

    ctf::src::Medium::UP tempMedium =
        bt2_common::makeUnique<ctf::src::live::CtfLiveMedium>(*liveStreamIter);
    const ctf::src::TraceCls *ctfTc = liveStreamIter->trace->metadata->traceCls();
    BT_ASSERT(ctfTc);
    ctf::src::PktProps pktProps = ctf::src::readPktProps(
        *ctfTc, std::move(tempMedium), bt2_common::DataLen::fromBytes(0), liveStreamIter->logCfg);

    nonstd::optional<bt2::TraceClass> tc = ctfTc->libCls();
    BT_ASSERT(tc);
    BT_ASSERT(liveStreamIter->ctf_stream_class_id.is_set);
    BT_ASSERT(trace->trace);

    const bt2_common::LogCfg& logCfg = liveStreamIter->logCfg;
    nonstd::optional<bt2::StreamClass> sc =
        tc->streamClassById(liveStreamIter->ctf_stream_class_id.value);
    if (!sc) {
        BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2::Error, "No stream class with id %" PRId64,
                                        liveStreamIter->ctf_stream_class_id.value);
    }

    // FIXME: in the original, there is a fall back if the data stream id is not available.
    bt_stream *streamPtr = bt_stream_create_with_id(sc->libObjPtr(), (*trace->trace)->libObjPtr(),
                                                    *pktProps.dataStreamId);
    BT_ASSERT(streamPtr);
    liveStreamIter->stream = bt2::Stream::Shared::createWithoutRef(streamPtr);
    (*liveStreamIter->stream)->name(liveStreamIter->name);

    ctf::src::Medium::UP medium =
        bt2_common::makeUnique<ctf::src::live::CtfLiveMedium>(*liveStreamIter);
    liveStreamIter->msg_iter.emplace(
        liveMsgIter->self_msg_iter, *ctfTc, liveStreamIter->trace->metadata->metadataStreamUuid(),
        **liveStreamIter->stream, std::move(medium), ctf::src::MsgIterQuirks {}, logCfg);
    return LTTNG_LIVE_ITERATOR_STATUS_OK;
}

enum lttng_live_iterator_status lttng_live_lazy_msg_init(struct lttng_live_session *session,
                                                         bt_self_message_iterator *self_msg_iter)
{
    const bt2_common::LogCfg& logCfg = session->logCfg;

    if (!session->lazy_stream_msg_init) {
        return LTTNG_LIVE_ITERATOR_STATUS_OK;
    }

    BT_CLOGD("Lazily initializing self message iterator for live session: "
             "session-id=%" PRIu64 ", self-msg-iter-addr=%p",
             session->id, self_msg_iter);

    for (lttng_live_trace::UP& trace : session->traces) {
        for (lttng_live_stream_iterator::UP& stream_iter : trace->stream_iterators) {
            if (stream_iter->msg_iter) {
                continue;
            }

            const ctf::src::TraceCls *ctfTraceCls = trace->metadata->traceCls();
            BT_CLOGD("Creating CTF message iterator: "
                     "session-id=%" PRIu64 ", ctf-tc-addr=%p, "
                     "stream-iter-name=%s, self-msg-iter-addr=%p",
                     session->id, ctfTraceCls, stream_iter->name.c_str(), self_msg_iter);
        }
    }

    session->lazy_stream_msg_init = false;

    return LTTNG_LIVE_ITERATOR_STATUS_OK;
}

struct lttng_live_stream_iterator *
lttng_live_stream_iterator_create(struct lttng_live_session *session, uint64_t ctf_trace_id,
                                  uint64_t stream_id, bt_self_message_iterator *self_msg_iter)
{
    struct lttng_live_trace *trace;
    std::stringstream nameSs;

    BT_ASSERT(session);
    BT_ASSERT(session->lttng_live_msg_iter);
    BT_ASSERT(session->lttng_live_msg_iter->lttng_live_comp);

    const bt2_common::LogCfg& logCfg = session->logCfg;

    lttng_live_stream_iterator::UP stream_iter =
        bt2_common::makeUnique<lttng_live_stream_iterator>(logCfg);
    trace = lttng_live_session_borrow_or_create_trace_by_id(session, ctf_trace_id);
    if (!trace) {
        BT_CLOGE_APPEND_CAUSE("Failed to borrow CTF trace.");
        return nullptr;
    }

    stream_iter->trace = trace;
    stream_iter->state = LTTNG_LIVE_STREAM_ACTIVE_NO_DATA;
    stream_iter->viewer_stream_id = stream_id;

    stream_iter->ctf_stream_class_id.is_set = false;
    stream_iter->ctf_stream_class_id.value = UINT64_MAX;

    stream_iter->last_inactivity_ts.is_set = false;
    stream_iter->last_inactivity_ts.value = 0;

    nameSs << STREAM_NAME_PREFIX << stream_iter->viewer_stream_id;
    stream_iter->name = nameSs.str();

    lttng_live_stream_iterator *ret = stream_iter.get();
    trace->stream_iterators.emplace_back(std::move(stream_iter));

    /* Track the number of active stream iterator. */
    session->lttng_live_msg_iter->active_stream_iter++;

    return ret;
}

void lttng_live_stream_iterator_set_stream_class(lttng_live_stream_iterator *streamIter,
                                                 uint64_t ctfStreamClsId)
{
    if (streamIter->ctf_stream_class_id.is_set) {
        BT_ASSERT(streamIter->ctf_stream_class_id.value == ctfStreamClsId);
        return;
    } else {
        streamIter->ctf_stream_class_id.value = ctfStreamClsId;
        streamIter->ctf_stream_class_id.is_set = true;
    }
}

lttng_live_stream_iterator::~lttng_live_stream_iterator()
{
    /* Track the number of active stream iterator. */
    this->trace->session->lttng_live_msg_iter->active_stream_iter--;
}
