/*
 * Babeltrace - CTF notification iterator
 *
 * Copyright (c) 2015-2018 EfficiOS Inc. and Linux Foundation
 * Copyright (c) 2015-2018 Philippe Proulx <pproulx@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#define BT_LOG_TAG "PLUGIN-CTF-NOTIF-ITER"
#include "logging.h"

#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <babeltrace/assert-internal.h>
#include <string.h>
#include <babeltrace/babeltrace.h>
#include <babeltrace/common-internal.h>
#include <glib.h>
#include <stdlib.h>

#include "notif-iter.h"
#include "../btr/btr.h"

struct bt_notif_iter;

/* A visit stack entry */
struct stack_entry {
	/*
	 * Current base field, one of:
	 *
	 *   * string
	 *   * structure
	 *   * array
	 *   * sequence
	 *   * variant
	 *
	 * Field is borrowed.
	 */
	struct bt_field *base;

	/* Index of next field to set */
	size_t index;
};

/* Visit stack */
struct stack {
	/* Entries (struct stack_entry) */
	GArray *entries;

	/* Number of active entries */
	size_t size;
};

/* State */
enum state {
	STATE_INIT,
	STATE_DSCOPE_TRACE_PACKET_HEADER_BEGIN,
	STATE_DSCOPE_TRACE_PACKET_HEADER_CONTINUE,
	STATE_AFTER_TRACE_PACKET_HEADER,
	STATE_DSCOPE_STREAM_PACKET_CONTEXT_BEGIN,
	STATE_DSCOPE_STREAM_PACKET_CONTEXT_CONTINUE,
	STATE_AFTER_STREAM_PACKET_CONTEXT,
	STATE_EMIT_NOTIF_NEW_STREAM,
	STATE_EMIT_NOTIF_NEW_PACKET,
	STATE_DSCOPE_EVENT_HEADER_BEGIN,
	STATE_DSCOPE_EVENT_HEADER_CONTINUE,
	STATE_AFTER_EVENT_HEADER,
	STATE_DSCOPE_EVENT_COMMON_CONTEXT_BEGIN,
	STATE_DSCOPE_EVENT_COMMON_CONTEXT_CONTINUE,
	STATE_DSCOPE_EVENT_SPEC_CONTEXT_BEGIN,
	STATE_DSCOPE_EVENT_SPEC_CONTEXT_CONTINUE,
	STATE_DSCOPE_EVENT_PAYLOAD_BEGIN,
	STATE_DSCOPE_EVENT_PAYLOAD_CONTINUE,
	STATE_EMIT_NOTIF_EVENT,
	STATE_EMIT_NOTIF_END_OF_PACKET,
	STATE_DONE,
	STATE_SKIP_PACKET_PADDING,
};

/* CTF notification iterator */
struct bt_notif_iter {
	/* Visit stack */
	struct stack *stack;

	/* Current notification iterator to create notifications (weak) */
	struct bt_private_connection_private_notification_iterator *notif_iter;

	/*
	 * Current dynamic scope field pointer.
	 *
	 * This is set by read_dscope_begin_state() and contains the
	 * value of one of the pointers in `dscopes` below.
	 */
	struct bt_field *cur_dscope_field;

	/*
	 * True if we're done filling a string field from a text
	 * array/sequence payload.
	 */
	bool done_filling_string;

	/* Trace and classes */
	struct {
		struct ctf_trace_class *tc;
		struct ctf_stream_class *sc;
		struct ctf_event_class *ec;
	} meta;

	/* Current packet header field wrapper (NULL if not created yet) */
	struct bt_packet_header_field *packet_header_field;

	/* Current packet header field wrapper (NULL if not created yet) */
	struct bt_packet_context_field *packet_context_field;

	/* Current event header field (NULL if not created yet) */
	struct bt_event_header_field *event_header_field;

	/* Current packet (NULL if not created yet) */
	struct bt_packet *packet;

	/* Current stream (NULL if not set yet) */
	struct bt_stream *stream;

	/* Current event (NULL if not created yet) */
	struct bt_event *event;

	/* Current event notification (NULL if not created yet) */
	struct bt_notification *event_notif;

	/* Database of current dynamic scopes */
	struct {
		struct bt_field *trace_packet_header;
		struct bt_field *stream_packet_context;
		struct bt_field *event_header;
		struct bt_field *event_common_context;
		struct bt_field *event_spec_context;
		struct bt_field *event_payload;
	} dscopes;

	/* Current state */
	enum state state;

	/* Current medium buffer data */
	struct {
		/* Last address provided by medium */
		const uint8_t *addr;

		/* Buffer size provided by medium (bytes) */
		size_t sz;

		/* Offset within whole packet of addr (bits) */
		size_t packet_offset;

		/* Current position from addr (bits) */
		size_t at;

		/* Position of the last event header from addr (bits) */
		size_t last_eh_at;
	} buf;

	/* Binary type reader */
	struct bt_btr *btr;

	/* Current medium data */
	struct {
		struct bt_notif_iter_medium_ops medops;
		size_t max_request_sz;
		void *data;
	} medium;

	/* Stream beginning was emitted */
	bool stream_begin_emitted;

	/* Current packet size (bits) (-1 if unknown) */
	int64_t cur_exp_packet_total_size;

	/* Current content size (bits) (-1 if unknown) */
	int64_t cur_exp_packet_content_size;

	/* Current stream class ID */
	int64_t cur_stream_class_id;

	/* Current event class ID */
	int64_t cur_event_class_id;

	/* Current data stream ID */
	int64_t cur_data_stream_id;

	/*
	 * Offset, in the underlying media, of the current packet's
	 * start (-1 if unknown).
	 */
	off_t cur_packet_offset;

	/* Default clock's current value */
	uint64_t default_clock_val;

	/* End of packet snapshots */
	struct {
		uint64_t discarded_events;
		uint64_t packets;
		uint64_t beginning_clock;
		uint64_t end_clock;
	} snapshots;

	/* Stored values (for sequence lengths, variant tags) */
	GArray *stored_values;
};

static inline
const char *state_string(enum state state)
{
	switch (state) {
	case STATE_INIT:
		return "STATE_INIT";
	case STATE_DSCOPE_TRACE_PACKET_HEADER_BEGIN:
		return "STATE_DSCOPE_TRACE_PACKET_HEADER_BEGIN";
	case STATE_DSCOPE_TRACE_PACKET_HEADER_CONTINUE:
		return "STATE_DSCOPE_TRACE_PACKET_HEADER_CONTINUE";
	case STATE_AFTER_TRACE_PACKET_HEADER:
		return "STATE_AFTER_TRACE_PACKET_HEADER";
	case STATE_DSCOPE_STREAM_PACKET_CONTEXT_BEGIN:
		return "STATE_DSCOPE_STREAM_PACKET_CONTEXT_BEGIN";
	case STATE_DSCOPE_STREAM_PACKET_CONTEXT_CONTINUE:
		return "STATE_DSCOPE_STREAM_PACKET_CONTEXT_CONTINUE";
	case STATE_AFTER_STREAM_PACKET_CONTEXT:
		return "STATE_AFTER_STREAM_PACKET_CONTEXT";
	case STATE_EMIT_NOTIF_NEW_PACKET:
		return "STATE_EMIT_NOTIF_NEW_PACKET";
	case STATE_EMIT_NOTIF_NEW_STREAM:
		return "STATE_EMIT_NOTIF_NEW_STREAM";
	case STATE_DSCOPE_EVENT_HEADER_BEGIN:
		return "STATE_DSCOPE_EVENT_HEADER_BEGIN";
	case STATE_DSCOPE_EVENT_HEADER_CONTINUE:
		return "STATE_DSCOPE_EVENT_HEADER_CONTINUE";
	case STATE_AFTER_EVENT_HEADER:
		return "STATE_AFTER_EVENT_HEADER";
	case STATE_DSCOPE_EVENT_COMMON_CONTEXT_BEGIN:
		return "STATE_DSCOPE_EVENT_COMMON_CONTEXT_BEGIN";
	case STATE_DSCOPE_EVENT_COMMON_CONTEXT_CONTINUE:
		return "STATE_DSCOPE_EVENT_COMMON_CONTEXT_CONTINUE";
	case STATE_DSCOPE_EVENT_SPEC_CONTEXT_BEGIN:
		return "STATE_DSCOPE_EVENT_SPEC_CONTEXT_BEGIN";
	case STATE_DSCOPE_EVENT_SPEC_CONTEXT_CONTINUE:
		return "STATE_DSCOPE_EVENT_SPEC_CONTEXT_CONTINUE";
	case STATE_DSCOPE_EVENT_PAYLOAD_BEGIN:
		return "STATE_DSCOPE_EVENT_PAYLOAD_BEGIN";
	case STATE_DSCOPE_EVENT_PAYLOAD_CONTINUE:
		return "STATE_DSCOPE_EVENT_PAYLOAD_CONTINUE";
	case STATE_EMIT_NOTIF_EVENT:
		return "STATE_EMIT_NOTIF_EVENT";
	case STATE_EMIT_NOTIF_END_OF_PACKET:
		return "STATE_EMIT_NOTIF_END_OF_PACKET";
	case STATE_DONE:
		return "STATE_DONE";
	case STATE_SKIP_PACKET_PADDING:
		return "STATE_SKIP_PACKET_PADDING";
	default:
		return "(unknown)";
	}
}

static
int bt_notif_iter_switch_packet(struct bt_notif_iter *notit);

static
struct stack *stack_new(struct bt_notif_iter *notit)
{
	struct stack *stack = NULL;

	stack = g_new0(struct stack, 1);
	if (!stack) {
		BT_LOGE_STR("Failed to allocate one stack.");
		goto error;
	}

	stack->entries = g_array_new(FALSE, TRUE, sizeof(struct stack_entry));
	if (!stack->entries) {
		BT_LOGE_STR("Failed to allocate a GArray.");
		goto error;
	}

	BT_LOGD("Created stack: notit-addr=%p, stack-addr=%p", notit, stack);
	goto end;

error:
	g_free(stack);
	stack = NULL;

end:
	return stack;
}

static
void stack_destroy(struct stack *stack)
{
	BT_ASSERT(stack);
	BT_LOGD("Destroying stack: addr=%p", stack);

	if (stack->entries) {
		g_array_free(stack->entries, TRUE);
	}

	g_free(stack);
}

static
void stack_push(struct stack *stack, struct bt_field *base)
{
	struct stack_entry *entry;

	BT_ASSERT(stack);
	BT_ASSERT(base);
	BT_LOGV("Pushing base field on stack: stack-addr=%p, "
		"stack-size-before=%zu, stack-size-after=%zu",
		stack, stack->size, stack->size + 1);

	if (stack->entries->len == stack->size) {
		g_array_set_size(stack->entries, stack->size + 1);
	}

	entry = &g_array_index(stack->entries, struct stack_entry, stack->size);
	entry->base = base;
	entry->index = 0;
	stack->size++;
}

static inline
unsigned int stack_size(struct stack *stack)
{
	BT_ASSERT(stack);
	return stack->size;
}

static
void stack_pop(struct stack *stack)
{
	BT_ASSERT(stack);
	BT_ASSERT(stack_size(stack));
	BT_LOGV("Popping from stack: "
		"stack-addr=%p, stack-size-before=%zu, stack-size-after=%zu",
		stack, stack->size, stack->size - 1);
	stack->size--;
}

static inline
struct stack_entry *stack_top(struct stack *stack)
{
	BT_ASSERT(stack);
	BT_ASSERT(stack_size(stack));
	return &g_array_index(stack->entries, struct stack_entry,
		stack->size - 1);
}

static inline
bool stack_empty(struct stack *stack)
{
	return stack_size(stack) == 0;
}

static
void stack_clear(struct stack *stack)
{
	BT_ASSERT(stack);
	stack->size = 0;
}

static inline
enum bt_notif_iter_status notif_iter_status_from_m_status(
		enum bt_notif_iter_medium_status m_status)
{
	/* They are the same */
	return (int) m_status;
}

static inline
size_t buf_size_bits(struct bt_notif_iter *notit)
{
	return notit->buf.sz * 8;
}

static inline
size_t buf_available_bits(struct bt_notif_iter *notit)
{
	return buf_size_bits(notit) - notit->buf.at;
}

static inline
size_t packet_at(struct bt_notif_iter *notit)
{
	return notit->buf.packet_offset + notit->buf.at;
}

static inline
void buf_consume_bits(struct bt_notif_iter *notit, size_t incr)
{
	BT_LOGV("Advancing cursor: notit-addr=%p, cur-before=%zu, cur-after=%zu",
		notit, notit->buf.at, notit->buf.at + incr);
	notit->buf.at += incr;
}

static
enum bt_notif_iter_status request_medium_bytes(
		struct bt_notif_iter *notit)
{
	uint8_t *buffer_addr = NULL;
	size_t buffer_sz = 0;
	enum bt_notif_iter_medium_status m_status;

	BT_LOGV("Calling user function (request bytes): notit-addr=%p, "
		"request-size=%zu", notit, notit->medium.max_request_sz);
	m_status = notit->medium.medops.request_bytes(
		notit->medium.max_request_sz, &buffer_addr,
		&buffer_sz, notit->medium.data);
	BT_LOGV("User function returned: status=%s, buf-addr=%p, buf-size=%zu",
		bt_notif_iter_medium_status_string(m_status),
		buffer_addr, buffer_sz);
	if (m_status == BT_NOTIF_ITER_MEDIUM_STATUS_OK) {
		BT_ASSERT(buffer_sz != 0);

		/* New packet offset is old one + old size (in bits) */
		notit->buf.packet_offset += buf_size_bits(notit);

		/* Restart at the beginning of the new medium buffer */
		notit->buf.at = 0;
		notit->buf.last_eh_at = SIZE_MAX;

		/* New medium buffer size */
		notit->buf.sz = buffer_sz;

		/* New medium buffer address */
		notit->buf.addr = buffer_addr;

		BT_LOGV("User function returned new bytes: "
			"packet-offset=%zu, cur=%zu, size=%zu, addr=%p",
			notit->buf.packet_offset, notit->buf.at,
			notit->buf.sz, notit->buf.addr);
		BT_LOGV_MEM(buffer_addr, buffer_sz, "Returned bytes at %p:",
			buffer_addr);
	} else if (m_status == BT_NOTIF_ITER_MEDIUM_STATUS_EOF) {
		/*
		 * User returned end of stream: validate that we're not
		 * in the middle of a packet header, packet context, or
		 * event.
		 */
		if (notit->cur_exp_packet_total_size >= 0) {
			if (packet_at(notit) ==
					notit->cur_exp_packet_total_size) {
				goto end;
			}
		} else {
			if (packet_at(notit) == 0) {
				goto end;
			}

			if (notit->buf.last_eh_at != SIZE_MAX &&
					notit->buf.at == notit->buf.last_eh_at) {
				goto end;
			}
		}

		/* All other states are invalid */
		BT_LOGW("User function returned %s, but notification iterator is in an unexpected state: "
			"state=%s, cur-packet-size=%" PRId64 ", cur=%zu, "
			"packet-cur=%zu, last-eh-at=%zu",
			bt_notif_iter_medium_status_string(m_status),
			state_string(notit->state),
			notit->cur_exp_packet_total_size,
			notit->buf.at, packet_at(notit),
			notit->buf.last_eh_at);
		m_status = BT_NOTIF_ITER_MEDIUM_STATUS_ERROR;
	} else if (m_status < 0) {
		BT_LOGW("User function failed: status=%s",
			bt_notif_iter_medium_status_string(m_status));
	}

end:
	return notif_iter_status_from_m_status(m_status);
}

static inline
enum bt_notif_iter_status buf_ensure_available_bits(
		struct bt_notif_iter *notit)
{
	enum bt_notif_iter_status status = BT_NOTIF_ITER_STATUS_OK;

	if (unlikely(buf_available_bits(notit) == 0)) {
		/*
		 * This _cannot_ return BT_NOTIF_ITER_STATUS_OK
		 * _and_ no bits.
		 */
		status = request_medium_bytes(notit);
	}

	return status;
}

static
enum bt_notif_iter_status read_dscope_begin_state(
		struct bt_notif_iter *notit,
		struct ctf_field_type *dscope_ft,
		enum state done_state, enum state continue_state,
		struct bt_field *dscope_field)
{
	enum bt_notif_iter_status status = BT_NOTIF_ITER_STATUS_OK;
	enum bt_btr_status btr_status;
	size_t consumed_bits;

	notit->cur_dscope_field = dscope_field;
	BT_LOGV("Starting BTR: notit-addr=%p, btr-addr=%p, ft-addr=%p",
		notit, notit->btr, dscope_ft);
	consumed_bits = bt_btr_start(notit->btr, dscope_ft,
		notit->buf.addr, notit->buf.at, packet_at(notit),
		notit->buf.sz, &btr_status);
	BT_LOGV("BTR consumed bits: size=%zu", consumed_bits);

	switch (btr_status) {
	case BT_BTR_STATUS_OK:
		/* type was read completely */
		BT_LOGV_STR("Field was completely decoded.");
		notit->state = done_state;
		break;
	case BT_BTR_STATUS_EOF:
		BT_LOGV_STR("BTR needs more data to decode field completely.");
		notit->state = continue_state;
		break;
	default:
		BT_LOGW("BTR failed to start: notit-addr=%p, btr-addr=%p, "
			"status=%s", notit, notit->btr,
			bt_btr_status_string(btr_status));
		status = BT_NOTIF_ITER_STATUS_ERROR;
		goto end;
	}

	/* Consume bits now since we know we're not in an error state */
	buf_consume_bits(notit, consumed_bits);

end:
	return status;
}

static
enum bt_notif_iter_status read_dscope_continue_state(
		struct bt_notif_iter *notit, enum state done_state)
{
	enum bt_notif_iter_status status = BT_NOTIF_ITER_STATUS_OK;
	enum bt_btr_status btr_status;
	size_t consumed_bits;

	BT_LOGV("Continuing BTR: notit-addr=%p, btr-addr=%p",
		notit, notit->btr);

	status = buf_ensure_available_bits(notit);
	if (status != BT_NOTIF_ITER_STATUS_OK) {
		if (status < 0) {
			BT_LOGW("Cannot ensure that buffer has at least one byte: "
				"notif-addr=%p, status=%s",
				notit, bt_notif_iter_status_string(status));
		} else {
			BT_LOGV("Cannot ensure that buffer has at least one byte: "
				"notif-addr=%p, status=%s",
				notit, bt_notif_iter_status_string(status));
		}

		goto end;
	}

	consumed_bits = bt_btr_continue(notit->btr, notit->buf.addr,
		notit->buf.sz, &btr_status);
	BT_LOGV("BTR consumed bits: size=%zu", consumed_bits);

	switch (btr_status) {
	case BT_BTR_STATUS_OK:
		/* Type was read completely. */
		BT_LOGV_STR("Field was completely decoded.");
		notit->state = done_state;
		break;
	case BT_BTR_STATUS_EOF:
		/* Stay in this continue state. */
		BT_LOGV_STR("BTR needs more data to decode field completely.");
		break;
	default:
		BT_LOGW("BTR failed to continue: notit-addr=%p, btr-addr=%p, "
			"status=%s", notit, notit->btr,
			bt_btr_status_string(btr_status));
		status = BT_NOTIF_ITER_STATUS_ERROR;
		goto end;
	}

	/* Consume bits now since we know we're not in an error state. */
	buf_consume_bits(notit, consumed_bits);
end:
	return status;
}

static
void release_event_dscopes(struct bt_notif_iter *notit)
{
	notit->dscopes.event_header = NULL;

	if (notit->event_header_field) {
		bt_event_header_field_release(notit->event_header_field);
		notit->event_header_field = NULL;
	}

	notit->dscopes.event_common_context = NULL;
	notit->dscopes.event_spec_context = NULL;
	notit->dscopes.event_payload = NULL;
}

static
void release_all_dscopes(struct bt_notif_iter *notit)
{
	notit->dscopes.trace_packet_header = NULL;

	if (notit->packet_header_field) {
		bt_packet_header_field_release(notit->packet_header_field);
		notit->packet_header_field = NULL;
	}

	notit->dscopes.stream_packet_context = NULL;

	if (notit->packet_context_field) {
		bt_packet_context_field_release(notit->packet_context_field);
		notit->packet_context_field = NULL;
	}

	release_event_dscopes(notit);
}

static
enum bt_notif_iter_status read_packet_header_begin_state(
		struct bt_notif_iter *notit)
{
	struct ctf_field_type *packet_header_ft = NULL;
	enum bt_notif_iter_status ret = BT_NOTIF_ITER_STATUS_OK;

	if (bt_notif_iter_switch_packet(notit)) {
		BT_LOGW("Cannot switch packet: notit-addr=%p", notit);
		ret = BT_NOTIF_ITER_STATUS_ERROR;
		goto end;
	}

	/* Packet header type is common to the whole trace. */
	packet_header_ft = notit->meta.tc->packet_header_ft;
	if (!packet_header_ft) {
		notit->state = STATE_AFTER_TRACE_PACKET_HEADER;
		goto end;
	}

	BT_ASSERT(!notit->packet_header_field);

	if (packet_header_ft->in_ir) {
		/*
		 * Create free packet header field from trace. This
		 * field is going to be moved to the packet once we
		 * create it. We cannot create the packet now because:
		 *
		 * 1. A packet is created from a stream.
		 * 2. A stream is created from a stream class.
		 * 3. We need the packet header field's content to know
		 *    the ID of the stream class to select.
		 */
		notit->packet_header_field = bt_packet_header_field_create(
			notit->meta.tc->ir_tc);
		if (!notit->packet_header_field) {
			BT_LOGE_STR("Cannot create packet header field wrapper from trace.");
			ret = BT_NOTIF_ITER_STATUS_ERROR;
			goto end;
		}

		notit->dscopes.trace_packet_header =
			bt_packet_header_field_borrow_field(notit->packet_header_field);
		BT_ASSERT(notit->dscopes.trace_packet_header);
	}

	notit->cur_stream_class_id = -1;
	notit->cur_event_class_id = -1;
	notit->cur_data_stream_id = -1;
	BT_LOGV("Decoding packet header field:"
		"notit-addr=%p, trace-addr=%p, trace-name=\"%s\", ft-addr=%p",
		notit, notit->meta.tc,
		notit->meta.tc->name->str, packet_header_ft);
	ret = read_dscope_begin_state(notit, packet_header_ft,
		STATE_AFTER_TRACE_PACKET_HEADER,
		STATE_DSCOPE_TRACE_PACKET_HEADER_CONTINUE,
		notit->dscopes.trace_packet_header);
	if (ret < 0) {
		BT_LOGW("Cannot decode packet header field: "
			"notit-addr=%p, trace-addr=%p, "
			"trace-name=\"%s\", ft-addr=%p",
			notit, notit->meta.tc,
			notit->meta.tc->name->str,
			packet_header_ft);
	}

end:
	return ret;
}

static
enum bt_notif_iter_status read_packet_header_continue_state(
		struct bt_notif_iter *notit)
{
	return read_dscope_continue_state(notit,
		STATE_AFTER_TRACE_PACKET_HEADER);
}

static inline
enum bt_notif_iter_status set_current_stream_class(struct bt_notif_iter *notit)
{
	enum bt_notif_iter_status status = BT_NOTIF_ITER_STATUS_OK;
	struct ctf_stream_class *new_stream_class = NULL;

	if (notit->cur_stream_class_id == -1) {
		/*
		 * No current stream class ID field, therefore only one
		 * stream class.
		 */
		if (notit->meta.tc->stream_classes->len != 1) {
			BT_LOGW("Need exactly one stream class since there's "
				"no stream class ID field: "
				"notit-addr=%p, trace-name=\"%s\"",
				notit, notit->meta.tc->name->str);
			status = BT_NOTIF_ITER_STATUS_ERROR;
			goto end;
		}

		new_stream_class = notit->meta.tc->stream_classes->pdata[0];
		notit->cur_stream_class_id = new_stream_class->id;
		goto end;
	}

	new_stream_class = ctf_trace_class_borrow_stream_class_by_id(
		notit->meta.tc, notit->cur_stream_class_id);
	if (!new_stream_class) {
		BT_LOGW("No stream class with ID of stream class ID to use in trace: "
			"notit-addr=%p, stream-class-id=%" PRIu64 ", "
			"trace-addr=%p, trace-name=\"%s\"",
			notit, notit->cur_stream_class_id, notit->meta.tc,
			notit->meta.tc->name->str);
		status = BT_NOTIF_ITER_STATUS_ERROR;
		goto end;
	}

	if (notit->meta.sc) {
		if (new_stream_class != notit->meta.sc) {
			BT_LOGW("Two packets refer to two different stream classes within the same packet sequence: "
				"notit-addr=%p, prev-stream-class-addr=%p, "
				"prev-stream-class-id=%" PRId64 ", "
				"next-stream-class-addr=%p, "
				"next-stream-class-id=%" PRId64 ", "
				"trace-addr=%p, trace-name=\"%s\"",
				notit, notit->meta.sc,
				notit->meta.sc->id,
				new_stream_class,
				new_stream_class->id,
				notit->meta.tc,
				notit->meta.tc->name->str);
			status = BT_NOTIF_ITER_STATUS_ERROR;
			goto end;
		}
	} else {
		notit->meta.sc = new_stream_class;
	}

	BT_LOGV("Set current stream class: "
		"notit-addr=%p, stream-class-addr=%p, "
		"stream-class-id=%" PRId64,
		notit, notit->meta.sc, notit->meta.sc->id);

end:
	return status;
}

static inline
enum bt_notif_iter_status set_current_stream(struct bt_notif_iter *notit)
{
	enum bt_notif_iter_status status = BT_NOTIF_ITER_STATUS_OK;
	struct bt_stream *stream = NULL;

	BT_LOGV("Calling user function (get stream): notit-addr=%p, "
		"stream-class-addr=%p, stream-class-id=%" PRId64,
		notit, notit->meta.sc,
		notit->meta.sc->id);
	stream = bt_get(notit->medium.medops.borrow_stream(
		notit->meta.sc->ir_sc, notit->cur_data_stream_id,
		notit->medium.data));
	BT_LOGV("User function returned: stream-addr=%p", stream);
	if (!stream) {
		BT_LOGW_STR("User function failed to return a stream object "
			"for the given stream class.");
		status = BT_NOTIF_ITER_STATUS_ERROR;
		goto end;
	}

	if (notit->stream && stream != notit->stream) {
		BT_LOGW("User function returned a different stream than the "
			"previous one for the same sequence of packets.");
		status = BT_NOTIF_ITER_STATUS_ERROR;
		goto end;
	}

	BT_MOVE(notit->stream, stream);

end:
	bt_put(stream);
	return status;
}

static inline
enum bt_notif_iter_status set_current_packet(struct bt_notif_iter *notit)
{
	enum bt_notif_iter_status status = BT_NOTIF_ITER_STATUS_OK;
	struct bt_packet *packet = NULL;

	BT_LOGV("Creating packet for packet notification: "
		"notit-addr=%p", notit);
	BT_LOGV("Creating packet from stream: "
		"notit-addr=%p, stream-addr=%p, "
		"stream-class-addr=%p, "
		"stream-class-id=%" PRId64,
		notit, notit->stream, notit->meta.sc,
		notit->meta.sc->id);

	/* Create packet */
	BT_ASSERT(notit->stream);
	packet = bt_packet_create(notit->stream);
	if (!packet) {
		BT_LOGE("Cannot create packet from stream: "
			"notit-addr=%p, stream-addr=%p, "
			"stream-class-addr=%p, "
			"stream-class-id=%" PRId64,
			notit, notit->stream, notit->meta.sc,
			notit->meta.sc->id);
		goto error;
	}

	goto end;

error:
	BT_PUT(packet);
	status = BT_NOTIF_ITER_STATUS_ERROR;

end:
	BT_MOVE(notit->packet, packet);
	return status;
}

static
enum bt_notif_iter_status after_packet_header_state(
		struct bt_notif_iter *notit)
{
	enum bt_notif_iter_status status;

	status = set_current_stream_class(notit);
	if (status != BT_NOTIF_ITER_STATUS_OK) {
		goto end;
	}

	notit->state = STATE_DSCOPE_STREAM_PACKET_CONTEXT_BEGIN;

end:
	return status;
}

static
enum bt_notif_iter_status read_packet_context_begin_state(
		struct bt_notif_iter *notit)
{
	enum bt_notif_iter_status status = BT_NOTIF_ITER_STATUS_OK;
	struct ctf_field_type *packet_context_ft;

	BT_ASSERT(notit->meta.sc);
	packet_context_ft = notit->meta.sc->packet_context_ft;
	if (!packet_context_ft) {
		BT_LOGV("No packet packet context field type in stream class: continuing: "
			"notit-addr=%p, stream-class-addr=%p, "
			"stream-class-id=%" PRId64,
			notit, notit->meta.sc,
			notit->meta.sc->id);
		notit->state = STATE_AFTER_STREAM_PACKET_CONTEXT;
		goto end;
	}

	BT_ASSERT(!notit->packet_context_field);

	if (packet_context_ft->in_ir) {
		/*
		 * Create free packet context field from stream class.
		 * This field is going to be moved to the packet once we
		 * create it. We cannot create the packet now because a
		 * packet is created from a stream, and this API must be
		 * able to return the packet header and context fields
		 * without creating a stream
		 * (bt_notif_iter_borrow_packet_header_context_fields()).
		 */
		notit->packet_context_field =
			bt_packet_context_field_create(notit->meta.sc->ir_sc);
		if (!notit->packet_context_field) {
			BT_LOGE_STR("Cannot create packet context field wrapper from stream class.");
			status = BT_NOTIF_ITER_STATUS_ERROR;
			goto end;
		}

		notit->dscopes.stream_packet_context =
			bt_packet_context_field_borrow_field(notit->packet_context_field);
		BT_ASSERT(notit->dscopes.stream_packet_context);
	}

	BT_LOGV("Decoding packet context field: "
		"notit-addr=%p, stream-class-addr=%p, "
		"stream-class-id=%" PRId64 ", ft-addr=%p",
		notit, notit->meta.sc,
		notit->meta.sc->id, packet_context_ft);
	status = read_dscope_begin_state(notit, packet_context_ft,
		STATE_AFTER_STREAM_PACKET_CONTEXT,
		STATE_DSCOPE_STREAM_PACKET_CONTEXT_CONTINUE,
		notit->dscopes.stream_packet_context);
	if (status < 0) {
		BT_LOGW("Cannot decode packet context field: "
			"notit-addr=%p, stream-class-addr=%p, "
			"stream-class-id=%" PRId64 ", ft-addr=%p",
			notit, notit->meta.sc,
			notit->meta.sc->id,
			packet_context_ft);
	}

end:
	return status;
}

static
enum bt_notif_iter_status read_packet_context_continue_state(
		struct bt_notif_iter *notit)
{
	return read_dscope_continue_state(notit,
			STATE_AFTER_STREAM_PACKET_CONTEXT);
}

static
enum bt_notif_iter_status set_current_packet_content_sizes(
		struct bt_notif_iter *notit)
{
	enum bt_notif_iter_status status = BT_NOTIF_ITER_STATUS_OK;

	if (notit->cur_exp_packet_total_size == -1) {
		if (notit->cur_exp_packet_content_size != -1) {
			BT_LOGW("Content size is set, but packet size is not: "
				"notit-addr=%p, packet-context-field-addr=%p, "
				"packet-size=%" PRId64 ", content-size=%" PRId64,
				notit, notit->dscopes.stream_packet_context,
				notit->cur_exp_packet_total_size,
				notit->cur_exp_packet_content_size);
			status = BT_NOTIF_ITER_STATUS_ERROR;
			goto end;
		}
	} else {
		if (notit->cur_exp_packet_content_size == -1) {
			notit->cur_exp_packet_content_size =
				notit->cur_exp_packet_total_size;
		}
	}

	if (notit->cur_exp_packet_content_size >
			notit->cur_exp_packet_total_size) {
		BT_LOGW("Invalid packet or content size: "
			"content size is greater than packet size: "
			"notit-addr=%p, packet-context-field-addr=%p, "
			"packet-size=%" PRId64 ", content-size=%" PRId64,
			notit, notit->dscopes.stream_packet_context,
			notit->cur_exp_packet_total_size,
			notit->cur_exp_packet_content_size);
		status = BT_NOTIF_ITER_STATUS_ERROR;
		goto end;
	}

	BT_LOGV("Set current packet and content sizes: "
		"notit-addr=%p, packet-size=%" PRIu64 ", content-size=%" PRIu64,
		notit, notit->cur_exp_packet_total_size,
		notit->cur_exp_packet_content_size);
end:
	return status;
}

static
enum bt_notif_iter_status after_packet_context_state(
		struct bt_notif_iter *notit)
{
	enum bt_notif_iter_status status;

	status = set_current_packet_content_sizes(notit);
	if (status != BT_NOTIF_ITER_STATUS_OK) {
		goto end;
	}

	if (notit->stream_begin_emitted) {
		notit->state = STATE_EMIT_NOTIF_NEW_PACKET;
	} else {
		notit->state = STATE_EMIT_NOTIF_NEW_STREAM;
	}

end:
	return status;
}

static
enum bt_notif_iter_status read_event_header_begin_state(
		struct bt_notif_iter *notit)
{
	enum bt_notif_iter_status status = BT_NOTIF_ITER_STATUS_OK;
	struct ctf_field_type *event_header_ft = NULL;

	/* Reset the position of the last event header */
	notit->buf.last_eh_at = notit->buf.at;
	notit->cur_event_class_id = -1;

	/* Check if we have some content left */
	if (notit->cur_exp_packet_content_size >= 0) {
		if (unlikely(packet_at(notit) ==
				notit->cur_exp_packet_content_size)) {
			/* No more events! */
			BT_LOGV("Reached end of packet: notit-addr=%p, "
				"cur=%zu", notit, packet_at(notit));
			notit->state = STATE_EMIT_NOTIF_END_OF_PACKET;
			goto end;
		} else if (unlikely(packet_at(notit) >
				notit->cur_exp_packet_content_size)) {
			/* That's not supposed to happen */
			BT_LOGV("Before decoding event header field: cursor is passed the packet's content: "
				"notit-addr=%p, content-size=%" PRId64 ", "
				"cur=%zu", notit,
				notit->cur_exp_packet_content_size,
				packet_at(notit));
			status = BT_NOTIF_ITER_STATUS_ERROR;
			goto end;
		}
	} else {
		/*
		 * "Infinite" content: we're done when the medium has
		 * nothing else for us.
		 */
		status = buf_ensure_available_bits(notit);
		if (status != BT_NOTIF_ITER_STATUS_OK) {
			/*
			 * If this function returns
			 * `BT_NOTIF_ITER_STATUS_EOF`:
			 *
			 * 1. bt_notif_iter_get_next_notification()
			 *    emits a "packet end" notification. This
			 *    resets the current packet. The state
			 *    remains unchanged otherwise.
			 * 2. This function is called again. It returns
			 *    `BT_NOTIF_ITER_STATUS_EOF` again.
			 * 3. bt_notif_iter_get_next_notification()
			 *    emits a "stream end" notification because
			 *    there's no current packet. It sets the
			 *    current state to `STATE_DONE`.
			 */
			goto end;
		}
	}

	release_event_dscopes(notit);
	BT_ASSERT(notit->meta.sc);
	event_header_ft = notit->meta.sc->event_header_ft;
	if (!event_header_ft) {
		notit->state = STATE_AFTER_EVENT_HEADER;
		goto end;
	}

	if (event_header_ft->in_ir) {
		BT_ASSERT(!notit->event_header_field);
		notit->event_header_field = bt_event_header_field_create(
			notit->meta.sc->ir_sc);
		if (!notit->event_header_field) {
			BT_LOGE_STR("Cannot create event header field wrapper from trace.");
			status = BT_NOTIF_ITER_STATUS_ERROR;
			goto end;
		}

		notit->dscopes.event_header =
			bt_event_header_field_borrow_field(notit->event_header_field);
		BT_ASSERT(notit->dscopes.event_header);
	}

	BT_LOGV("Decoding event header field: "
		"notit-addr=%p, stream-class-addr=%p, "
		"stream-class-id=%" PRId64 ", "
		"ft-addr=%p",
		notit, notit->meta.sc,
		notit->meta.sc->id,
		event_header_ft);
	status = read_dscope_begin_state(notit, event_header_ft,
		STATE_AFTER_EVENT_HEADER,
		STATE_DSCOPE_EVENT_HEADER_CONTINUE,
		notit->dscopes.event_header);
	if (status < 0) {
		BT_LOGW("Cannot decode event header field: "
			"notit-addr=%p, stream-class-addr=%p, "
			"stream-class-id=%" PRId64 ", ft-addr=%p",
			notit, notit->meta.sc,
			notit->meta.sc->id,
			event_header_ft);
	}

end:
	return status;
}

static
enum bt_notif_iter_status read_event_header_continue_state(
		struct bt_notif_iter *notit)
{
	return read_dscope_continue_state(notit,
		STATE_AFTER_EVENT_HEADER);
}

static inline
enum bt_notif_iter_status set_current_event_class(struct bt_notif_iter *notit)
{
	enum bt_notif_iter_status status = BT_NOTIF_ITER_STATUS_OK;

	struct ctf_event_class *new_event_class = NULL;

	if (notit->cur_event_class_id == -1) {
		/*
		 * No current event class ID field, therefore only one
		 * event class.
		 */
		if (notit->meta.sc->event_classes->len != 1) {
			BT_LOGW("Need exactly one event class since there's "
				"no event class ID field: "
				"notit-addr=%p, trace-name=\"%s\"",
				notit, notit->meta.tc->name->str);
			status = BT_NOTIF_ITER_STATUS_ERROR;
			goto end;
		}

		new_event_class = notit->meta.sc->event_classes->pdata[0];
		notit->cur_event_class_id = new_event_class->id;
		goto end;
	}

	new_event_class = ctf_stream_class_borrow_event_class_by_id(
		notit->meta.sc, notit->cur_event_class_id);
	if (!new_event_class) {
		BT_LOGW("No event class with ID of event class ID to use in stream class: "
			"notit-addr=%p, stream-class-id=%" PRIu64 ", "
			"event-class-id=%" PRIu64 ", "
			"trace-addr=%p, trace-name=\"%s\"",
			notit, notit->meta.sc->id, notit->cur_event_class_id,
			notit->meta.tc, notit->meta.tc->name->str);
		status = BT_NOTIF_ITER_STATUS_ERROR;
		goto end;
	}

	notit->meta.ec = new_event_class;
	BT_LOGV("Set current event class: "
		"notit-addr=%p, event-class-addr=%p, "
		"event-class-id=%" PRId64 ", "
		"event-class-name=\"%s\"",
		notit, notit->meta.ec, notit->meta.ec->id,
		notit->meta.ec->name->str);

end:
	return status;
}

static inline
enum bt_notif_iter_status set_current_event_notification(
		struct bt_notif_iter *notit)
{
	enum bt_notif_iter_status status = BT_NOTIF_ITER_STATUS_OK;
	struct bt_notification *notif = NULL;

	BT_ASSERT(notit->meta.ec);
	BT_ASSERT(notit->packet);
	BT_LOGV("Creating event notification from event class and packet: "
		"notit-addr=%p, ec-addr=%p, ec-name=\"%s\", packet-addr=%p",
		notit, notit->meta.ec,
		notit->meta.ec->name->str,
		notit->packet);
	BT_ASSERT(notit->notif_iter);
	notif = bt_notification_event_create(notit->notif_iter,
		notit->meta.ec->ir_ec, notit->packet);
	if (!notif) {
		BT_LOGE("Cannot create event notification: "
			"notit-addr=%p, ec-addr=%p, ec-name=\"%s\", "
			"packet-addr=%p",
			notit, notit->meta.ec,
			notit->meta.ec->name->str,
			notit->packet);
		goto error;
	}

	goto end;

error:
	BT_PUT(notif);
	status = BT_NOTIF_ITER_STATUS_ERROR;

end:
	BT_MOVE(notit->event_notif, notif);
	return status;
}

static
enum bt_notif_iter_status after_event_header_state(
		struct bt_notif_iter *notit)
{
	enum bt_notif_iter_status status;

	status = set_current_event_class(notit);
	if (status != BT_NOTIF_ITER_STATUS_OK) {
		goto end;
	}

	status = set_current_event_notification(notit);
	if (status != BT_NOTIF_ITER_STATUS_OK) {
		goto end;
	}

	notit->event = bt_notification_event_borrow_event(notit->event_notif);
	BT_ASSERT(notit->event);

	if (notit->event_header_field) {
		int ret;

		BT_ASSERT(notit->event);
		ret = bt_event_move_header(notit->event,
			notit->event_header_field);
		if (ret) {
			status = BT_NOTIF_ITER_STATUS_ERROR;
			goto end;
		}

		notit->event_header_field = NULL;

		/*
		 * At this point notit->dscopes.event_header has
		 * the same value as the event header field within
		 * notit->event.
		 */
		BT_ASSERT(bt_event_borrow_header_field(notit->event) ==
			notit->dscopes.event_header);
	}

	notit->state = STATE_DSCOPE_EVENT_COMMON_CONTEXT_BEGIN;

end:
	return status;
}

static
enum bt_notif_iter_status read_event_common_context_begin_state(
		struct bt_notif_iter *notit)
{
	enum bt_notif_iter_status status = BT_NOTIF_ITER_STATUS_OK;
	struct ctf_field_type *event_common_context_ft;

	event_common_context_ft = notit->meta.sc->event_common_context_ft;
	if (!event_common_context_ft) {
		notit->state = STATE_DSCOPE_EVENT_SPEC_CONTEXT_BEGIN;
		goto end;
	}

	if (event_common_context_ft->in_ir) {
		BT_ASSERT(!notit->dscopes.event_common_context);
		notit->dscopes.event_common_context =
			bt_event_borrow_common_context_field(notit->event);
		BT_ASSERT(notit->dscopes.event_common_context);
	}

	BT_LOGV("Decoding event common context field: "
		"notit-addr=%p, stream-class-addr=%p, "
		"stream-class-id=%" PRId64 ", "
		"ft-addr=%p",
		notit, notit->meta.sc,
		notit->meta.sc->id,
		event_common_context_ft);
	status = read_dscope_begin_state(notit, event_common_context_ft,
		STATE_DSCOPE_EVENT_SPEC_CONTEXT_BEGIN,
		STATE_DSCOPE_EVENT_COMMON_CONTEXT_CONTINUE,
		notit->dscopes.event_common_context);
	if (status < 0) {
		BT_LOGW("Cannot decode event common context field: "
			"notit-addr=%p, stream-class-addr=%p, "
			"stream-class-id=%" PRId64 ", ft-addr=%p",
			notit, notit->meta.sc,
			notit->meta.sc->id,
			event_common_context_ft);
	}

end:
	return status;
}

static
enum bt_notif_iter_status read_event_common_context_continue_state(
		struct bt_notif_iter *notit)
{
	return read_dscope_continue_state(notit,
		STATE_DSCOPE_EVENT_SPEC_CONTEXT_BEGIN);
}

static
enum bt_notif_iter_status read_event_spec_context_begin_state(
		struct bt_notif_iter *notit)
{
	enum bt_notif_iter_status status = BT_NOTIF_ITER_STATUS_OK;
	struct ctf_field_type *event_spec_context_ft;

	event_spec_context_ft = notit->meta.ec->spec_context_ft;
	if (!event_spec_context_ft) {
		notit->state = STATE_DSCOPE_EVENT_PAYLOAD_BEGIN;
		goto end;
	}

	if (event_spec_context_ft->in_ir) {
		BT_ASSERT(!notit->dscopes.event_spec_context);
		notit->dscopes.event_spec_context = bt_event_borrow_specific_context_field(
			notit->event);
		BT_ASSERT(notit->dscopes.event_spec_context);
	}

	BT_LOGV("Decoding event specific context field: "
		"notit-addr=%p, event-class-addr=%p, "
		"event-class-name=\"%s\", event-class-id=%" PRId64 ", "
		"ft-addr=%p",
		notit, notit->meta.ec,
		notit->meta.ec->name->str,
		notit->meta.ec->id,
		event_spec_context_ft);
	status = read_dscope_begin_state(notit, event_spec_context_ft,
		STATE_DSCOPE_EVENT_PAYLOAD_BEGIN,
		STATE_DSCOPE_EVENT_SPEC_CONTEXT_CONTINUE,
		notit->dscopes.event_spec_context);
	if (status < 0) {
		BT_LOGW("Cannot decode event specific context field: "
			"notit-addr=%p, event-class-addr=%p, "
			"event-class-name=\"%s\", "
			"event-class-id=%" PRId64 ", ft-addr=%p",
			notit, notit->meta.ec,
			notit->meta.ec->name->str,
			notit->meta.ec->id,
			event_spec_context_ft);
	}

end:
	return status;
}

static
enum bt_notif_iter_status read_event_spec_context_continue_state(
		struct bt_notif_iter *notit)
{
	return read_dscope_continue_state(notit,
		STATE_DSCOPE_EVENT_PAYLOAD_BEGIN);
}

static
enum bt_notif_iter_status read_event_payload_begin_state(
		struct bt_notif_iter *notit)
{
	enum bt_notif_iter_status status = BT_NOTIF_ITER_STATUS_OK;
	struct ctf_field_type *event_payload_ft;

	event_payload_ft = notit->meta.ec->payload_ft;
	if (!event_payload_ft) {
		notit->state = STATE_EMIT_NOTIF_EVENT;
		goto end;
	}

	if (event_payload_ft->in_ir) {
		BT_ASSERT(!notit->dscopes.event_payload);
		notit->dscopes.event_payload = bt_event_borrow_payload_field(
			notit->event);
		BT_ASSERT(notit->dscopes.event_payload);
	}

	BT_LOGV("Decoding event payload field: "
		"notit-addr=%p, event-class-addr=%p, "
		"event-class-name=\"%s\", event-class-id=%" PRId64 ", "
		"ft-addr=%p",
		notit, notit->meta.ec,
		notit->meta.ec->name->str,
		notit->meta.ec->id,
		event_payload_ft);
	status = read_dscope_begin_state(notit, event_payload_ft,
		STATE_EMIT_NOTIF_EVENT,
		STATE_DSCOPE_EVENT_PAYLOAD_CONTINUE,
		notit->dscopes.event_payload);
	if (status < 0) {
		BT_LOGW("Cannot decode event payload field: "
			"notit-addr=%p, event-class-addr=%p, "
			"event-class-name=\"%s\", "
			"event-class-id=%" PRId64 ", ft-addr=%p",
			notit, notit->meta.ec,
			notit->meta.ec->name->str,
			notit->meta.ec->id,
			event_payload_ft);
	}

end:
	return status;
}

static
enum bt_notif_iter_status read_event_payload_continue_state(
		struct bt_notif_iter *notit)
{
	return read_dscope_continue_state(notit, STATE_EMIT_NOTIF_EVENT);
}

static
enum bt_notif_iter_status skip_packet_padding_state(
		struct bt_notif_iter *notit)
{
	enum bt_notif_iter_status status = BT_NOTIF_ITER_STATUS_OK;
	size_t bits_to_skip;

	BT_ASSERT(notit->cur_exp_packet_total_size > 0);
	bits_to_skip = notit->cur_exp_packet_total_size - packet_at(notit);
	if (bits_to_skip == 0) {
		notit->state = STATE_DSCOPE_TRACE_PACKET_HEADER_BEGIN;
		goto end;
	} else {
		size_t bits_to_consume;

		BT_LOGV("Trying to skip %zu bits of padding: notit-addr=%p, size=%zu",
			bits_to_skip, notit, bits_to_skip);
		status = buf_ensure_available_bits(notit);
		if (status != BT_NOTIF_ITER_STATUS_OK) {
			goto end;
		}

		bits_to_consume = MIN(buf_available_bits(notit), bits_to_skip);
		BT_LOGV("Skipping %zu bits of padding: notit-addr=%p, size=%zu",
			bits_to_consume, notit, bits_to_consume);
		buf_consume_bits(notit, bits_to_consume);
		bits_to_skip = notit->cur_exp_packet_total_size -
			packet_at(notit);
		if (bits_to_skip == 0) {
			notit->state = STATE_DSCOPE_TRACE_PACKET_HEADER_BEGIN;
			goto end;
		}
	}

end:
	return status;
}

static inline
enum bt_notif_iter_status handle_state(struct bt_notif_iter *notit)
{
	enum bt_notif_iter_status status = BT_NOTIF_ITER_STATUS_OK;
	const enum state state = notit->state;

	BT_LOGV("Handling state: notit-addr=%p, state=%s",
		notit, state_string(state));

	// TODO: optimalize!
	switch (state) {
	case STATE_INIT:
		notit->state = STATE_DSCOPE_TRACE_PACKET_HEADER_BEGIN;
		break;
	case STATE_DSCOPE_TRACE_PACKET_HEADER_BEGIN:
		status = read_packet_header_begin_state(notit);
		break;
	case STATE_DSCOPE_TRACE_PACKET_HEADER_CONTINUE:
		status = read_packet_header_continue_state(notit);
		break;
	case STATE_AFTER_TRACE_PACKET_HEADER:
		status = after_packet_header_state(notit);
		break;
	case STATE_DSCOPE_STREAM_PACKET_CONTEXT_BEGIN:
		status = read_packet_context_begin_state(notit);
		break;
	case STATE_DSCOPE_STREAM_PACKET_CONTEXT_CONTINUE:
		status = read_packet_context_continue_state(notit);
		break;
	case STATE_AFTER_STREAM_PACKET_CONTEXT:
		status = after_packet_context_state(notit);
		break;
	case STATE_EMIT_NOTIF_NEW_STREAM:
		notit->state = STATE_EMIT_NOTIF_NEW_PACKET;
		break;
	case STATE_EMIT_NOTIF_NEW_PACKET:
		notit->state = STATE_DSCOPE_EVENT_HEADER_BEGIN;
		break;
	case STATE_DSCOPE_EVENT_HEADER_BEGIN:
		status = read_event_header_begin_state(notit);
		break;
	case STATE_DSCOPE_EVENT_HEADER_CONTINUE:
		status = read_event_header_continue_state(notit);
		break;
	case STATE_AFTER_EVENT_HEADER:
		status = after_event_header_state(notit);
		break;
	case STATE_DSCOPE_EVENT_COMMON_CONTEXT_BEGIN:
		status = read_event_common_context_begin_state(notit);
		break;
	case STATE_DSCOPE_EVENT_COMMON_CONTEXT_CONTINUE:
		status = read_event_common_context_continue_state(notit);
		break;
	case STATE_DSCOPE_EVENT_SPEC_CONTEXT_BEGIN:
		status = read_event_spec_context_begin_state(notit);
		break;
	case STATE_DSCOPE_EVENT_SPEC_CONTEXT_CONTINUE:
		status = read_event_spec_context_continue_state(notit);
		break;
	case STATE_DSCOPE_EVENT_PAYLOAD_BEGIN:
		status = read_event_payload_begin_state(notit);
		break;
	case STATE_DSCOPE_EVENT_PAYLOAD_CONTINUE:
		status = read_event_payload_continue_state(notit);
		break;
	case STATE_EMIT_NOTIF_EVENT:
		notit->state = STATE_DSCOPE_EVENT_HEADER_BEGIN;
		break;
	case STATE_SKIP_PACKET_PADDING:
		status = skip_packet_padding_state(notit);
		break;
	case STATE_EMIT_NOTIF_END_OF_PACKET:
		notit->state = STATE_SKIP_PACKET_PADDING;
		break;
	default:
		BT_LOGD("Unknown CTF plugin notification iterator state: "
			"notit-addr=%p, state=%d", notit, notit->state);
		abort();
	}

	BT_LOGV("Handled state: notit-addr=%p, status=%s, "
		"prev-state=%s, cur-state=%s",
		notit, bt_notif_iter_status_string(status),
		state_string(state), state_string(notit->state));
	return status;
}

/**
 * Resets the internal state of a CTF notification iterator.
 */
BT_HIDDEN
void bt_notif_iter_reset(struct bt_notif_iter *notit)
{
	BT_ASSERT(notit);
	BT_LOGD("Resetting notification iterator: addr=%p", notit);
	stack_clear(notit->stack);
	notit->meta.sc = NULL;
	notit->meta.ec = NULL;
	BT_PUT(notit->packet);
	BT_PUT(notit->stream);
	BT_PUT(notit->event_notif);
	release_all_dscopes(notit);
	notit->cur_dscope_field = NULL;

	if (notit->packet_header_field) {
		bt_packet_header_field_release(notit->packet_header_field);
		notit->packet_header_field = NULL;
	}

	if (notit->packet_context_field) {
		bt_packet_context_field_release(notit->packet_context_field);
		notit->packet_context_field = NULL;
	}

	if (notit->event_header_field) {
		bt_event_header_field_release(notit->event_header_field);
		notit->event_header_field = NULL;
	}

	notit->buf.addr = NULL;
	notit->buf.sz = 0;
	notit->buf.at = 0;
	notit->buf.last_eh_at = SIZE_MAX;
	notit->buf.packet_offset = 0;
	notit->state = STATE_INIT;
	notit->cur_exp_packet_content_size = -1;
	notit->cur_exp_packet_total_size = -1;
	notit->cur_packet_offset = -1;
	notit->cur_stream_class_id = -1;
	notit->cur_event_class_id = -1;
	notit->cur_data_stream_id = -1;
	notit->stream_begin_emitted = false;
}

static
int bt_notif_iter_switch_packet(struct bt_notif_iter *notit)
{
	int ret = 0;

	/*
	 * We don't put the stream class here because we need to make
	 * sure that all the packets processed by the same notification
	 * iterator refer to the same stream class (the first one).
	 */
	BT_ASSERT(notit);

	if (notit->cur_exp_packet_total_size != -1) {
		notit->cur_packet_offset += notit->cur_exp_packet_total_size;
	}

	BT_LOGV("Switching packet: notit-addr=%p, cur=%zu, "
		"packet-offset=%" PRId64, notit, notit->buf.at,
		notit->cur_packet_offset);
	stack_clear(notit->stack);
	notit->meta.ec = NULL;
	BT_PUT(notit->packet);
	BT_PUT(notit->event_notif);
	release_all_dscopes(notit);
	notit->cur_dscope_field = NULL;

	/*
	 * Adjust current buffer so that addr points to the beginning of the new
	 * packet.
	 */
	if (notit->buf.addr) {
		size_t consumed_bytes = (size_t) (notit->buf.at / CHAR_BIT);

		/* Packets are assumed to start on a byte frontier. */
		if (notit->buf.at % CHAR_BIT) {
			BT_LOGW("Cannot switch packet: current position is not a multiple of 8: "
				"notit-addr=%p, cur=%zu", notit, notit->buf.at);
			ret = -1;
			goto end;
		}

		notit->buf.addr += consumed_bytes;
		notit->buf.sz -= consumed_bytes;
		notit->buf.at = 0;
		notit->buf.packet_offset = 0;
		BT_LOGV("Adjusted buffer: addr=%p, size=%zu",
			notit->buf.addr, notit->buf.sz);
	}

	notit->cur_exp_packet_content_size = -1;
	notit->cur_exp_packet_total_size = -1;
	notit->cur_stream_class_id = -1;
	notit->cur_event_class_id = -1;
	notit->cur_data_stream_id = -1;
	notit->snapshots.discarded_events = UINT64_C(-1);
	notit->snapshots.packets = UINT64_C(-1);
	notit->snapshots.beginning_clock = UINT64_C(-1);
	notit->snapshots.end_clock = UINT64_C(-1);

end:
	return ret;
}

static
struct bt_field *borrow_next_field(struct bt_notif_iter *notit)
{
	struct bt_field *next_field = NULL;
	struct bt_field *base_field;
	struct bt_field_type *base_ft;
	size_t index;

	BT_ASSERT(!stack_empty(notit->stack));
	index = stack_top(notit->stack)->index;
	base_field = stack_top(notit->stack)->base;
	BT_ASSERT(base_field);
	base_ft = bt_field_borrow_type(base_field);
	BT_ASSERT(base_ft);

	switch (bt_field_type_get_type_id(base_ft)) {
	case BT_FIELD_TYPE_ID_STRUCTURE:
	{
		BT_ASSERT(index <
			bt_field_type_structure_get_member_count(
				bt_field_borrow_type(base_field)));
		next_field = bt_field_structure_borrow_member_field_by_index(
			base_field, index);
		break;
	}
	case BT_FIELD_TYPE_ID_STATIC_ARRAY:
	case BT_FIELD_TYPE_ID_DYNAMIC_ARRAY:
		BT_ASSERT(index < bt_field_array_get_length(base_field));
		next_field = bt_field_array_borrow_element_field_by_index(
			base_field, index);
		break;
	case BT_FIELD_TYPE_ID_VARIANT:
		BT_ASSERT(index == 0);
		next_field = bt_field_variant_borrow_selected_option_field(
			base_field);
		break;
	default:
		abort();
	}

	BT_ASSERT(next_field);
	return next_field;
}

static
void update_default_clock(struct bt_notif_iter *notit, uint64_t new_val,
		uint64_t new_val_size)
{
	uint64_t new_val_mask;
	uint64_t cur_value_masked;

	BT_ASSERT(new_val_size > 0);

	/*
	 * Special case for a 64-bit new value, which is the limit
	 * of a clock value as of this version: overwrite the
	 * current value directly.
	 */
	if (new_val_size == 64) {
		notit->default_clock_val = new_val;
		goto end;
	}

	new_val_mask = (1ULL << new_val_size) - 1;
	cur_value_masked = notit->default_clock_val & new_val_mask;

	if (new_val < cur_value_masked) {
		/*
		 * It looks like a wrap happened on the number of bits
		 * of the requested new value. Assume that the clock
		 * value wrapped only one time.
		 */
		notit->default_clock_val += new_val_mask + 1;
	}

	/* Clear the low bits of the current clock value. */
	notit->default_clock_val &= ~new_val_mask;

	/* Set the low bits of the current clock value. */
	notit->default_clock_val |= new_val;

end:
	BT_LOGV("Updated default clock's value from integer field's value: "
		"value=%" PRIu64, notit->default_clock_val);
}

static
enum bt_btr_status btr_unsigned_int_cb(uint64_t value,
		struct ctf_field_type *ft, void *data)
{
	struct bt_notif_iter *notit = data;
	enum bt_btr_status status = BT_BTR_STATUS_OK;
	struct bt_field *field = NULL;
	struct ctf_field_type_int *int_ft = (void *) ft;

	BT_LOGV("Unsigned integer function called from BTR: "
		"notit-addr=%p, btr-addr=%p, ft-addr=%p, "
		"ft-id=%d, ft-in-ir=%d, value=%" PRIu64,
		notit, notit->btr, ft, ft->id, ft->in_ir, value);

	if (likely(int_ft->meaning == CTF_FIELD_TYPE_MEANING_NONE)) {
		goto update_def_clock;
	}

	switch (int_ft->meaning) {
	case CTF_FIELD_TYPE_MEANING_EVENT_CLASS_ID:
		notit->cur_event_class_id = value;
		break;
	case CTF_FIELD_TYPE_MEANING_DATA_STREAM_ID:
		notit->cur_data_stream_id = value;
		break;
	case CTF_FIELD_TYPE_MEANING_PACKET_BEGINNING_TIME:
		notit->snapshots.beginning_clock = value;
		break;
	case CTF_FIELD_TYPE_MEANING_PACKET_END_TIME:
		notit->snapshots.end_clock = value;
		break;
	case CTF_FIELD_TYPE_MEANING_STREAM_CLASS_ID:
		notit->cur_stream_class_id = value;
		break;
	case CTF_FIELD_TYPE_MEANING_MAGIC:
		if (value != 0xc1fc1fc1) {
			BT_LOGW("Invalid CTF magic number: notit-addr=%p, "
				"magic=%" PRIx64, notit, value);
			status = BT_BTR_STATUS_ERROR;
			goto end;
		}

		break;
	case CTF_FIELD_TYPE_MEANING_PACKET_COUNTER_SNAPSHOT:
		notit->snapshots.packets = value;
		break;
	case CTF_FIELD_TYPE_MEANING_DISC_EV_REC_COUNTER_SNAPSHOT:
		notit->snapshots.discarded_events = value;
		break;
	case CTF_FIELD_TYPE_MEANING_EXP_PACKET_TOTAL_SIZE:
		notit->cur_exp_packet_total_size = value;
		break;
	case CTF_FIELD_TYPE_MEANING_EXP_PACKET_CONTENT_SIZE:
		notit->cur_exp_packet_content_size = value;
		break;
	default:
		abort();
	}

update_def_clock:
	if (unlikely(int_ft->mapped_clock_class)) {
		update_default_clock(notit, value, int_ft->base.size);
	}

	if (unlikely(int_ft->storing_index >= 0)) {
		g_array_index(notit->stored_values, uint64_t,
			(uint64_t) int_ft->storing_index) = value;
	}

	if (unlikely(!ft->in_ir)) {
		goto end;
	}

	field = borrow_next_field(notit);
	BT_ASSERT(field);
	BT_ASSERT(bt_field_borrow_type(field) == ft->ir_ft);
	BT_ASSERT(bt_field_get_type_id(field) == BT_FIELD_TYPE_ID_UNSIGNED_INTEGER ||
		bt_field_get_type_id(field) == BT_FIELD_TYPE_ID_UNSIGNED_ENUMERATION);
	bt_field_unsigned_integer_set_value(field, value);
	stack_top(notit->stack)->index++;

end:
	return status;
}

static
enum bt_btr_status btr_unsigned_int_char_cb(uint64_t value,
		struct ctf_field_type *ft, void *data)
{
	int ret;
	struct bt_notif_iter *notit = data;
	enum bt_btr_status status = BT_BTR_STATUS_OK;
	struct bt_field *string_field = NULL;
	struct ctf_field_type_int *int_ft = (void *) ft;
	char str[2] = {'\0', '\0'};

	BT_LOGV("Unsigned integer character function called from BTR: "
		"notit-addr=%p, btr-addr=%p, ft-addr=%p, "
		"ft-id=%d, ft-in-ir=%d, value=%" PRIu64,
		notit, notit->btr, ft, ft->id, ft->in_ir, value);
	BT_ASSERT(int_ft->meaning == CTF_FIELD_TYPE_MEANING_NONE);
	BT_ASSERT(!int_ft->mapped_clock_class);
	BT_ASSERT(int_ft->storing_index < 0);

	if (unlikely(!ft->in_ir)) {
		goto end;
	}

	if (notit->done_filling_string) {
		goto end;
	}

	if (value == 0) {
		notit->done_filling_string = true;
		goto end;
	}

	string_field = stack_top(notit->stack)->base;
	BT_ASSERT(bt_field_get_type_id(string_field) == BT_FIELD_TYPE_ID_STRING);

	/* Append character */
	str[0] = (char) value;
	ret = bt_field_string_append_with_length(string_field, str, 1);
	if (ret) {
		BT_LOGE("Cannot append character to string field's value: "
			"notit-addr=%p, field-addr=%p, ret=%d",
			notit, string_field, ret);
		status = BT_BTR_STATUS_ERROR;
		goto end;
	}

end:
	return status;
}

static
enum bt_btr_status btr_signed_int_cb(int64_t value,
		struct ctf_field_type *ft, void *data)
{
	enum bt_btr_status status = BT_BTR_STATUS_OK;
	struct bt_field *field = NULL;
	struct bt_notif_iter *notit = data;
	struct ctf_field_type_int *int_ft = (void *) ft;

	BT_LOGV("Signed integer function called from BTR: "
		"notit-addr=%p, btr-addr=%p, ft-addr=%p, "
		"ft-id=%d, ft-in-ir=%d, value=%" PRId64,
		notit, notit->btr, ft, ft->id, ft->in_ir, value);
	BT_ASSERT(int_ft->meaning == CTF_FIELD_TYPE_MEANING_NONE);

	if (unlikely(int_ft->storing_index >= 0)) {
		g_array_index(notit->stored_values, uint64_t,
			(uint64_t) int_ft->storing_index) = (uint64_t) value;
	}

	if (unlikely(!ft->in_ir)) {
		goto end;
	}

	field = borrow_next_field(notit);
	BT_ASSERT(field);
	BT_ASSERT(bt_field_borrow_type(field) == ft->ir_ft);
	BT_ASSERT(bt_field_get_type_id(field) == BT_FIELD_TYPE_ID_SIGNED_INTEGER ||
		bt_field_get_type_id(field) == BT_FIELD_TYPE_ID_SIGNED_ENUMERATION);
	bt_field_signed_integer_set_value(field, value);
	stack_top(notit->stack)->index++;

end:
	return status;
}

static
enum bt_btr_status btr_floating_point_cb(double value,
		struct ctf_field_type *ft, void *data)
{
	enum bt_btr_status status = BT_BTR_STATUS_OK;
	struct bt_field *field = NULL;
	struct bt_notif_iter *notit = data;

	BT_LOGV("Floating point number function called from BTR: "
		"notit-addr=%p, btr-addr=%p, ft-addr=%p, "
		"ft-id=%d, ft-in-ir=%d, value=%f",
		notit, notit->btr, ft, ft->id, ft->in_ir, value);
	BT_ASSERT(ft->in_ir);
	field = borrow_next_field(notit);
	BT_ASSERT(field);
	BT_ASSERT(bt_field_borrow_type(field) == ft->ir_ft);
	BT_ASSERT(bt_field_get_type_id(field) == BT_FIELD_TYPE_ID_REAL);
	bt_field_real_set_value(field, value);
	stack_top(notit->stack)->index++;
	return status;
}

static
enum bt_btr_status btr_string_begin_cb(
		struct ctf_field_type *ft, void *data)
{
	struct bt_field *field = NULL;
	struct bt_notif_iter *notit = data;
	int ret;

	BT_LOGV("String (beginning) function called from BTR: "
		"notit-addr=%p, btr-addr=%p, ft-addr=%p, "
		"ft-id=%d, ft-in-ir=%d",
		notit, notit->btr, ft, ft->id, ft->in_ir);

	BT_ASSERT(ft->in_ir);
	field = borrow_next_field(notit);
	BT_ASSERT(field);
	BT_ASSERT(bt_field_borrow_type(field) == ft->ir_ft);
	BT_ASSERT(bt_field_get_type_id(field) == BT_FIELD_TYPE_ID_STRING);
	ret = bt_field_string_clear(field);
	BT_ASSERT(ret == 0);

	/*
	 * Push on stack. Not a compound type per se, but we know that
	 * only btr_string_cb() may be called between this call and a
	 * subsequent call to btr_string_end_cb().
	 */
	stack_push(notit->stack, field);
	return BT_BTR_STATUS_OK;
}

static
enum bt_btr_status btr_string_cb(const char *value,
		size_t len, struct ctf_field_type *ft, void *data)
{
	enum bt_btr_status status = BT_BTR_STATUS_OK;
	struct bt_field *field = NULL;
	struct bt_notif_iter *notit = data;
	int ret;

	BT_LOGV("String (substring) function called from BTR: "
		"notit-addr=%p, btr-addr=%p, ft-addr=%p, "
		"ft-id=%d, ft-in-ir=%d, string-length=%zu",
		notit, notit->btr, ft, ft->id, ft->in_ir,
		len);
	BT_ASSERT(ft->in_ir);
	field = stack_top(notit->stack)->base;
	BT_ASSERT(field);

	/* Append current substring */
	ret = bt_field_string_append_with_length(field, value, len);
	if (ret) {
		BT_LOGE("Cannot append substring to string field's value: "
			"notit-addr=%p, field-addr=%p, string-length=%zu, "
			"ret=%d", notit, field, len, ret);
		status = BT_BTR_STATUS_ERROR;
		goto end;
	}

end:
	return status;
}

static
enum bt_btr_status btr_string_end_cb(
		struct ctf_field_type *ft, void *data)
{
	struct bt_notif_iter *notit = data;

	BT_LOGV("String (end) function called from BTR: "
		"notit-addr=%p, btr-addr=%p, ft-addr=%p, "
		"ft-id=%d, ft-in-ir=%d",
		notit, notit->btr, ft, ft->id, ft->in_ir);
	BT_ASSERT(ft->in_ir);

	/* Pop string field */
	stack_pop(notit->stack);

	/* Go to next field */
	stack_top(notit->stack)->index++;
	return BT_BTR_STATUS_OK;
}

enum bt_btr_status btr_compound_begin_cb(
		struct ctf_field_type *ft, void *data)
{
	struct bt_notif_iter *notit = data;
	struct bt_field *field;

	BT_LOGV("Compound (beginning) function called from BTR: "
		"notit-addr=%p, btr-addr=%p, ft-addr=%p, "
		"ft-id=%d, ft-in-ir=%d",
		notit, notit->btr, ft, ft->id, ft->in_ir);

	if (!ft->in_ir) {
		goto end;
	}

	/* Borrow field */
	if (stack_empty(notit->stack)) {
		/* Root: already set by read_dscope_begin_state() */
		field = notit->cur_dscope_field;
	} else {
		field = borrow_next_field(notit);
		BT_ASSERT(field);
	}

	/* Push field */
	BT_ASSERT(field);
	BT_ASSERT(bt_field_borrow_type(field) == ft->ir_ft);
	stack_push(notit->stack, field);

	/*
	 * Change BTR "unsigned int" callback if it's a text
	 * array/sequence.
	 */
	if (ft->id == CTF_FIELD_TYPE_ID_ARRAY ||
			ft->id == CTF_FIELD_TYPE_ID_SEQUENCE) {
		struct ctf_field_type_array_base *array_ft = (void *) ft;

		if (array_ft->is_text) {
			int ret;

			BT_ASSERT(bt_field_get_type_id(field) ==
				BT_FIELD_TYPE_ID_STRING);
			notit->done_filling_string = false;
			ret = bt_field_string_clear(field);
			BT_ASSERT(ret == 0);
			bt_btr_set_unsigned_int_cb(notit->btr,
				btr_unsigned_int_char_cb);
		}
	}

end:
	return BT_BTR_STATUS_OK;
}

enum bt_btr_status btr_compound_end_cb(
		struct ctf_field_type *ft, void *data)
{
	struct bt_notif_iter *notit = data;

	BT_LOGV("Compound (end) function called from BTR: "
		"notit-addr=%p, btr-addr=%p, ft-addr=%p, "
		"ft-id=%d, ft-in-ir=%d",
		notit, notit->btr, ft, ft->id, ft->in_ir);

	if (!ft->in_ir) {
		goto end;
	}

	BT_ASSERT(!stack_empty(notit->stack));
	BT_ASSERT(bt_field_borrow_type(stack_top(notit->stack)->base) ==
		ft->ir_ft);

	/*
	 * Reset BTR "unsigned int" callback if it's a text
	 * array/sequence.
	 */
	if (ft->id == CTF_FIELD_TYPE_ID_ARRAY ||
			ft->id == CTF_FIELD_TYPE_ID_SEQUENCE) {
		struct ctf_field_type_array_base *array_ft = (void *) ft;

		if (array_ft->is_text) {
			BT_ASSERT(bt_field_get_type_id(
				stack_top(notit->stack)->base) ==
					BT_FIELD_TYPE_ID_STRING);
			bt_btr_set_unsigned_int_cb(notit->btr,
				btr_unsigned_int_cb);
		}
	}

	/* Pop stack */
	stack_pop(notit->stack);

	/* If the stack is not empty, increment the base's index */
	if (!stack_empty(notit->stack)) {
		stack_top(notit->stack)->index++;
	}

end:
	return BT_BTR_STATUS_OK;
}

static
int64_t btr_get_sequence_length_cb(struct ctf_field_type *ft, void *data)
{
	struct bt_field *seq_field;
	struct bt_notif_iter *notit = data;
	struct ctf_field_type_sequence *seq_ft = (void *) ft;
	int64_t length = -1;
	int ret;

	length = (uint64_t) g_array_index(notit->stored_values, uint64_t,
		seq_ft->stored_length_index);
	seq_field = stack_top(notit->stack)->base;
	BT_ASSERT(seq_field);
	ret = bt_field_dynamic_array_set_length(seq_field, (uint64_t) length);
	if (ret) {
		BT_LOGE("Cannot set dynamic array field's length field: "
			"notit-addr=%p, field-addr=%p, "
			"length=%" PRIu64, notit, seq_field, length);
	}

	return length;
}

static
struct ctf_field_type *btr_borrow_variant_selected_field_type_cb(
		struct ctf_field_type *ft, void *data)
{
	int ret;
	uint64_t i;
	int64_t option_index = -1;
	struct bt_notif_iter *notit = data;
	struct ctf_field_type_variant *var_ft = (void *) ft;
	struct ctf_named_field_type *selected_option = NULL;
	struct ctf_field_type *ret_ft = NULL;
	union {
		uint64_t u;
		int64_t i;
	} tag;

	/* Get variant's tag */
	tag.u = g_array_index(notit->stored_values, uint64_t,
		var_ft->stored_tag_index);

	/*
	 * Check each range to find the selected option's index.
	 */
	if (var_ft->tag_ft->base.is_signed) {
		for (i = 0; i < var_ft->ranges->len; i++) {
			struct ctf_field_type_variant_range *range =
				ctf_field_type_variant_borrow_range_by_index(
					var_ft, i);

			if (tag.i >= range->range.lower.i &&
					tag.i <= range->range.upper.i) {
				option_index = (int64_t) range->option_index;
				break;
			}
		}
	} else {
		for (i = 0; i < var_ft->ranges->len; i++) {
			struct ctf_field_type_variant_range *range =
				ctf_field_type_variant_borrow_range_by_index(
					var_ft, i);

			if (tag.u >= range->range.lower.u &&
					tag.u <= range->range.upper.u) {
				option_index = (int64_t) range->option_index;
				break;
			}
		}
	}

	if (option_index < 0) {
		BT_LOGW("Cannot find variant field type's option: "
			"notit-addr=%p, var-ft-addr=%p, u-tag=%" PRIu64 ", "
			"i-tag=%" PRId64, notit, var_ft, tag.u, tag.i);
		goto end;
	}

	selected_option = ctf_field_type_variant_borrow_option_by_index(
		var_ft, (uint64_t) option_index);

	if (selected_option->ft->in_ir) {
		struct bt_field *var_field = stack_top(notit->stack)->base;

		ret = bt_field_variant_select_option_field(var_field,
			option_index);
		if (ret) {
			BT_LOGW("Cannot select variant field's option field: "
				"notit-addr=%p, var-field-addr=%p, "
				"opt-index=%" PRId64, notit, var_field,
				option_index);
			goto end;
		}
	}

	ret_ft = selected_option->ft;

end:
	return ret_ft;
}

static
void set_event_default_clock_value(struct bt_notif_iter *notit)
{
	struct bt_event *event = bt_notification_event_borrow_event(
		notit->event_notif);
	struct bt_stream_class *sc = notit->meta.sc->ir_sc;

	BT_ASSERT(event);

	if (bt_stream_class_borrow_default_clock_class(sc)) {
		int ret = bt_event_set_default_clock_value(event,
			notit->default_clock_val);

		BT_ASSERT(ret == 0);
	}
}

static
void notify_new_stream(struct bt_notif_iter *notit,
		struct bt_notification **notification)
{
	enum bt_notif_iter_status status;
	struct bt_notification *ret = NULL;

	status = set_current_stream(notit);
	if (status != BT_NOTIF_ITER_STATUS_OK) {
		BT_PUT(ret);
		goto end;
	}

	BT_ASSERT(notit->stream);
	BT_ASSERT(notit->notif_iter);
	ret = bt_notification_stream_begin_create(notit->notif_iter,
		notit->stream);
	if (!ret) {
		BT_LOGE("Cannot create stream beginning notification: "
			"notit-addr=%p, stream-addr=%p",
			notit, notit->stream);
		return;
	}

end:
	*notification = ret;
}

static
void notify_end_of_stream(struct bt_notif_iter *notit,
		struct bt_notification **notification)
{
	struct bt_notification *ret;

	if (!notit->stream) {
		BT_LOGE("Cannot create stream for stream notification: "
			"notit-addr=%p", notit);
		return;
	}

	BT_ASSERT(notit->notif_iter);
	ret = bt_notification_stream_end_create(notit->notif_iter,
		notit->stream);
	if (!ret) {
		BT_LOGE("Cannot create stream beginning notification: "
			"notit-addr=%p, stream-addr=%p",
			notit, notit->stream);
		return;
	}
	*notification = ret;
}

static
void notify_new_packet(struct bt_notif_iter *notit,
		struct bt_notification **notification)
{
	int ret;
	enum bt_notif_iter_status status;
	struct bt_notification *notif = NULL;
	struct bt_stream_class *sc;

	status = set_current_packet(notit);
	if (status != BT_NOTIF_ITER_STATUS_OK) {
		goto end;
	}

	BT_ASSERT(notit->packet);
	sc = notit->meta.sc->ir_sc;
	BT_ASSERT(sc);

	if (bt_stream_class_packets_have_discarded_event_counter_snapshot(sc)) {
		BT_ASSERT(notit->snapshots.discarded_events != UINT64_C(-1));
		ret = bt_packet_set_discarded_event_counter_snapshot(
			notit->packet, notit->snapshots.discarded_events);
		BT_ASSERT(ret == 0);
	}

	if (bt_stream_class_packets_have_packet_counter_snapshot(sc)) {
		BT_ASSERT(notit->snapshots.packets != UINT64_C(-1));
		ret = bt_packet_set_packet_counter_snapshot(
			notit->packet, notit->snapshots.packets);
		BT_ASSERT(ret == 0);
	}

	if (bt_stream_class_packets_have_default_beginning_clock_value(sc)) {
		BT_ASSERT(notit->snapshots.beginning_clock != UINT64_C(-1));
		ret = bt_packet_set_default_beginning_clock_value(
			notit->packet, notit->snapshots.beginning_clock);
		BT_ASSERT(ret == 0);
	}

	if (bt_stream_class_packets_have_default_end_clock_value(sc)) {
		BT_ASSERT(notit->snapshots.end_clock != UINT64_C(-1));
		ret = bt_packet_set_default_end_clock_value(
			notit->packet, notit->snapshots.end_clock);
		BT_ASSERT(ret == 0);
	}

	if (notit->packet_header_field) {
		ret = bt_packet_move_header_field(notit->packet,
			notit->packet_header_field);
		if (ret) {
			goto end;
		}

		notit->packet_header_field = NULL;

		/*
		 * At this point notit->dscopes.trace_packet_header has
		 * the same value as the packet header field within
		 * notit->packet.
		 */
		BT_ASSERT(bt_packet_borrow_header_field(notit->packet) ==
			notit->dscopes.trace_packet_header);
	}

	if (notit->packet_context_field) {
		ret = bt_packet_move_context_field(notit->packet,
			notit->packet_context_field);
		if (ret) {
			goto end;
		}

		notit->packet_context_field = NULL;

		/*
		 * At this point notit->dscopes.trace_packet_header has
		 * the same value as the packet header field within
		 * notit->packet.
		 */
		BT_ASSERT(bt_packet_borrow_context_field(notit->packet) ==
			notit->dscopes.stream_packet_context);
	}

	BT_ASSERT(notit->notif_iter);
	notif = bt_notification_packet_begin_create(notit->notif_iter,
		notit->packet);
	if (!notif) {
		BT_LOGE("Cannot create packet beginning notification: "
			"notit-addr=%p, packet-addr=%p",
			notit, notit->packet);
		goto end;
	}

	*notification = notif;

end:
	return;
}

static
void notify_end_of_packet(struct bt_notif_iter *notit,
		struct bt_notification **notification)
{
	struct bt_notification *notif;

	if (!notit->packet) {
		return;
	}

	/* Update default clock from packet's end time */
	if (notit->snapshots.end_clock != UINT64_C(-1)) {
		notit->default_clock_val = notit->snapshots.end_clock;
	}

	BT_ASSERT(notit->notif_iter);
	notif = bt_notification_packet_end_create(notit->notif_iter,
		notit->packet);
	if (!notif) {
		BT_LOGE("Cannot create packet end notification: "
			"notit-addr=%p, packet-addr=%p",
			notit, notit->packet);
		return;

	}

	BT_PUT(notit->packet);
	*notification = notif;
}

BT_HIDDEN
struct bt_notif_iter *bt_notif_iter_create(struct ctf_trace_class *tc,
		size_t max_request_sz,
		struct bt_notif_iter_medium_ops medops, void *data)
{
	struct bt_notif_iter *notit = NULL;
	struct bt_btr_cbs cbs = {
		.types = {
			.signed_int = btr_signed_int_cb,
			.unsigned_int = btr_unsigned_int_cb,
			.floating_point = btr_floating_point_cb,
			.string_begin = btr_string_begin_cb,
			.string = btr_string_cb,
			.string_end = btr_string_end_cb,
			.compound_begin = btr_compound_begin_cb,
			.compound_end = btr_compound_end_cb,
		},
		.query = {
			.get_sequence_length = btr_get_sequence_length_cb,
			.borrow_variant_selected_field_type = btr_borrow_variant_selected_field_type_cb,
		},
	};

	BT_ASSERT(tc);
	BT_ASSERT(medops.request_bytes);
	BT_ASSERT(medops.borrow_stream);
	BT_LOGD("Creating CTF plugin notification iterator: "
		"trace-addr=%p, trace-name=\"%s\", max-request-size=%zu, "
		"data=%p", tc, tc->name->str, max_request_sz, data);
	notit = g_new0(struct bt_notif_iter, 1);
	if (!notit) {
		BT_LOGE_STR("Failed to allocate one CTF plugin notification iterator.");
		goto end;
	}
	notit->meta.tc = tc;
	notit->medium.medops = medops;
	notit->medium.max_request_sz = max_request_sz;
	notit->medium.data = data;
	notit->stack = stack_new(notit);
	notit->stored_values = g_array_new(FALSE, TRUE, sizeof(uint64_t));
	g_array_set_size(notit->stored_values, tc->stored_value_count);

	if (!notit->stack) {
		BT_LOGE_STR("Failed to create field stack.");
		goto error;
	}

	notit->btr = bt_btr_create(cbs, notit);
	if (!notit->btr) {
		BT_LOGE_STR("Failed to create binary type reader (BTR).");
		goto error;
	}

	bt_notif_iter_reset(notit);
	BT_LOGD("Created CTF plugin notification iterator: "
		"trace-addr=%p, trace-name=\"%s\", max-request-size=%zu, "
		"data=%p, notit-addr=%p",
		tc, tc->name->str, max_request_sz, data,
		notit);
	notit->cur_packet_offset = 0;

end:
	return notit;

error:
	bt_notif_iter_destroy(notit);
	notit = NULL;
	goto end;
}

void bt_notif_iter_destroy(struct bt_notif_iter *notit)
{
	BT_PUT(notit->packet);
	BT_PUT(notit->stream);
	release_all_dscopes(notit);

	BT_LOGD("Destroying CTF plugin notification iterator: addr=%p", notit);

	if (notit->stack) {
		BT_LOGD_STR("Destroying field stack.");
		stack_destroy(notit->stack);
	}

	if (notit->btr) {
		BT_LOGD("Destroying BTR: btr-addr=%p", notit->btr);
		bt_btr_destroy(notit->btr);
	}

	if (notit->stored_values) {
		g_array_free(notit->stored_values, TRUE);
	}

	g_free(notit);
}

enum bt_notif_iter_status bt_notif_iter_get_next_notification(
		struct bt_notif_iter *notit,
		struct bt_private_connection_private_notification_iterator *notif_iter,
		struct bt_notification **notification)
{
	enum bt_notif_iter_status status = BT_NOTIF_ITER_STATUS_OK;

	BT_ASSERT(notit);
	BT_ASSERT(notification);

	if (notit->state == STATE_DONE) {
		status = BT_NOTIF_ITER_STATUS_EOF;
		goto end;
	}

	notit->notif_iter = notif_iter;

	BT_LOGV("Getting next notification: notit-addr=%p", notit);

	while (true) {
		status = handle_state(notit);
		if (status == BT_NOTIF_ITER_STATUS_AGAIN) {
			BT_LOGV_STR("Medium returned BT_NOTIF_ITER_STATUS_AGAIN.");
			goto end;
		}

		if (status != BT_NOTIF_ITER_STATUS_OK) {
			if (status == BT_NOTIF_ITER_STATUS_EOF) {
				enum state next_state = notit->state;

				BT_LOGV_STR("Medium returned BT_NOTIF_ITER_STATUS_EOF.");

				if (notit->packet) {
					notify_end_of_packet(notit,
						notification);
				} else {
					notify_end_of_stream(notit,
						notification);
					next_state = STATE_DONE;
				}

				if (!*notification) {
					status = BT_NOTIF_ITER_STATUS_ERROR;
					goto end;
				}

				status = BT_NOTIF_ITER_STATUS_OK;
				notit->state = next_state;
			} else {
				BT_LOGW("Cannot handle state: "
					"notit-addr=%p, state=%s",
					notit, state_string(notit->state));
			}

			goto end;
		}

		switch (notit->state) {
		case STATE_EMIT_NOTIF_NEW_STREAM:
			/* notify_new_stream() logs errors */
			notify_new_stream(notit, notification);

			if (!*notification) {
				status = BT_NOTIF_ITER_STATUS_ERROR;
			}

			notit->stream_begin_emitted = true;
			goto end;
		case STATE_EMIT_NOTIF_NEW_PACKET:
			/* notify_new_packet() logs errors */
			notify_new_packet(notit, notification);

			if (!*notification) {
				status = BT_NOTIF_ITER_STATUS_ERROR;
			}

			goto end;
		case STATE_EMIT_NOTIF_EVENT:
			BT_ASSERT(notit->event_notif);
			set_event_default_clock_value(notit);
			*notification = notit->event_notif;
			notit->event_notif = NULL;
			goto end;
		case STATE_EMIT_NOTIF_END_OF_PACKET:
			/* notify_end_of_packet() logs errors */
			notify_end_of_packet(notit, notification);

			if (!*notification) {
				status = BT_NOTIF_ITER_STATUS_ERROR;
			}

			goto end;
		default:
			/* Non-emitting state: continue */
			break;
		}
	}

end:
	return status;
}

BT_HIDDEN
enum bt_notif_iter_status bt_notif_iter_borrow_packet_header_context_fields(
		struct bt_notif_iter *notit,
		struct bt_field **packet_header_field,
		struct bt_field **packet_context_field)
{
	int ret;
	enum bt_notif_iter_status status = BT_NOTIF_ITER_STATUS_OK;

	BT_ASSERT(notit);

	if (notit->state == STATE_EMIT_NOTIF_NEW_PACKET) {
		/* We're already there */
		goto set_fields;
	}

	while (true) {
		status = handle_state(notit);
		if (status == BT_NOTIF_ITER_STATUS_AGAIN) {
			BT_LOGV_STR("Medium returned BT_NOTIF_ITER_STATUS_AGAIN.");
			goto end;
		}
		if (status != BT_NOTIF_ITER_STATUS_OK) {
			if (status == BT_NOTIF_ITER_STATUS_EOF) {
				BT_LOGV_STR("Medium returned BT_NOTIF_ITER_STATUS_EOF.");
			} else {
				BT_LOGW("Cannot handle state: "
					"notit-addr=%p, state=%s",
					notit, state_string(notit->state));
			}
			goto end;
		}

		switch (notit->state) {
		case STATE_EMIT_NOTIF_NEW_PACKET:
			/*
			 * Packet header and context fields are
			 * potentially decoded (or they don't exist).
			 */
			goto set_fields;
		case STATE_INIT:
		case STATE_EMIT_NOTIF_NEW_STREAM:
		case STATE_DSCOPE_TRACE_PACKET_HEADER_BEGIN:
		case STATE_DSCOPE_TRACE_PACKET_HEADER_CONTINUE:
		case STATE_AFTER_TRACE_PACKET_HEADER:
		case STATE_DSCOPE_STREAM_PACKET_CONTEXT_BEGIN:
		case STATE_DSCOPE_STREAM_PACKET_CONTEXT_CONTINUE:
		case STATE_AFTER_STREAM_PACKET_CONTEXT:
			/* Non-emitting state: continue */
			break;
		default:
			/*
			 * We should never get past the
			 * STATE_EMIT_NOTIF_NEW_PACKET state.
			 */
			BT_LOGF("Unexpected state: notit-addr=%p, state=%s",
				notit, state_string(notit->state));
			abort();
		}
	}

set_fields:
	ret = set_current_packet_content_sizes(notit);
	if (ret) {
		status = BT_NOTIF_ITER_STATUS_ERROR;
		goto end;
	}

	if (packet_header_field) {
		*packet_header_field = notit->dscopes.trace_packet_header;
	}

	if (packet_context_field) {
		*packet_context_field = notit->dscopes.stream_packet_context;
	}

end:
	return status;
}

BT_HIDDEN
void bt_notif_iter_set_medops_data(struct bt_notif_iter *notit,
		void *medops_data)
{
	BT_ASSERT(notit);
	notit->medium.data = medops_data;
}

BT_HIDDEN
enum bt_notif_iter_status bt_notif_iter_seek(
		struct bt_notif_iter *notit, off_t offset)
{
	enum bt_notif_iter_status ret = BT_NOTIF_ITER_STATUS_OK;
	enum bt_notif_iter_medium_status medium_status;

	BT_ASSERT(notit);
	if (offset < 0) {
		BT_LOGE("Cannot seek to negative offset: offset=%jd", offset);
		ret = BT_NOTIF_ITER_STATUS_INVAL;
		goto end;
	}

	if (!notit->medium.medops.seek) {
		ret = BT_NOTIF_ITER_STATUS_UNSUPPORTED;
		BT_LOGD("Aborting seek as the iterator's underlying media does not implement seek support.");
		goto end;
	}

	medium_status = notit->medium.medops.seek(
		BT_NOTIF_ITER_SEEK_WHENCE_SET, offset, notit->medium.data);
	if (medium_status != BT_NOTIF_ITER_MEDIUM_STATUS_OK) {
		if (medium_status == BT_NOTIF_ITER_MEDIUM_STATUS_EOF) {
			ret = BT_NOTIF_ITER_STATUS_EOF;
		} else {
			ret = BT_NOTIF_ITER_STATUS_ERROR;
			goto end;
		}
	}

	bt_notif_iter_reset(notit);
	notit->cur_packet_offset = offset;

end:
	return ret;
}

BT_HIDDEN
off_t bt_notif_iter_get_current_packet_offset(struct bt_notif_iter *notit)
{
	BT_ASSERT(notit);
	return notit->cur_packet_offset;
}

BT_HIDDEN
off_t bt_notif_iter_get_current_packet_size(
		struct bt_notif_iter *notit)
{
	BT_ASSERT(notit);
	return notit->cur_exp_packet_total_size;
}

BT_HIDDEN
void bt_notif_trace_class_changed(struct bt_notif_iter *notit)
{
	if (notit->meta.tc->stored_value_count > notit->stored_values->len) {
		g_array_set_size(notit->stored_values,
			notit->meta.tc->stored_value_count);
	}
}

BT_HIDDEN
enum bt_notif_iter_status bt_notif_iter_get_packet_properties(
		struct bt_notif_iter *notit,
		struct bt_notif_iter_packet_properties *props)
{
	BT_ASSERT(notit);
	BT_ASSERT(props);

	props->exp_packet_total_size =
		(uint64_t) notit->cur_exp_packet_total_size;
	props->exp_packet_content_size =
		(uint64_t) notit->cur_exp_packet_content_size;
	BT_ASSERT(props->stream_class_id >= 0);
	props->stream_class_id = (uint64_t) notit->cur_stream_class_id;
	props->data_stream_id = notit->cur_data_stream_id;
	props->snapshots.discarded_events = notit->snapshots.discarded_events;
	props->snapshots.packets = notit->snapshots.packets;
	props->snapshots.beginning_clock = notit->snapshots.beginning_clock;
	props->snapshots.end_clock = notit->snapshots.end_clock;
	return BT_NOTIF_ITER_STATUS_OK;
}
