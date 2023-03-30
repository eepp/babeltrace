/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2016 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef LTTNG_LIVE_DATA_STREAM_H
#define LTTNG_LIVE_DATA_STREAM_H

#include <stdio.h>
#include <stdint.h>

#include <glib.h>

#include "lttng-live.hpp"

enum lttng_live_iterator_status lttng_live_lazy_msg_init(struct lttng_live_session *session,
                                                         bt_self_message_iterator *self_msg_iter);

struct lttng_live_stream_iterator *
lttng_live_stream_iterator_create(struct lttng_live_session *session, uint64_t ctf_trace_id,
                                  uint64_t stream_id, bt_self_message_iterator *self_msg_iter);

namespace ctf {
namespace src {
namespace live {

struct CtfLiveMedium : Medium
{
    CtfLiveMedium(lttng_live_stream_iterator& liveStreamIter) : _mLiveStreamIter(liveStreamIter)
    {
    }

    Buf buf(bt2_common::DataLen offset, bt2_common::DataLen minSize) override;

private:
    lttng_live_stream_iterator& _mLiveStreamIter;

    bt2_common::DataLen _mCurPktBegOffsetInStream = bt2_common::DataLen::fromBits(0);
    std::vector<uint8_t> _mBuf;
};

} /* namespace live */
} /* namespace src */
} /* namespace ctf */

lttng_live_iterator_status
lttng_live_stream_iterator_create_msg_iter(lttng_live_stream_iterator *liveStreamIter);

#endif /* LTTNG_LIVE_DATA_STREAM_H */
