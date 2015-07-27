/*
 * Babeltrace - CTF notification iterator
 *                  ¯¯¯          ¯¯
 * Copyright (c) 2015 EfficiOS Inc. and Linux Foundation
 * Copyright (c) 2015 Philippe Proulx <pproulx@efficios.com>
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

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <babeltrace/ctf-ir/ctf-notit.h>
#include <babeltrace/ctf-ir/ctf-btr.h>
#include <babeltrace/ctf-ir/event-types.h>
#include <babeltrace/ctf-ir/event-types-internal.h>
#include <babeltrace/ctf-ir/event-fields.h>
#include <babeltrace/ctf-ir/stream-class.h>
#include <babeltrace/ctf-ir/ref.h>
#include <glib.h>

#define BYTES_TO_BITS(x)		((x) * 8)

/* a visit stack entry */
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
	 * Field is owned by this.
	 */
	struct bt_ctf_field *base;

	/* index of next field to set */
	size_t index;
};

/* visit stack */
struct stack {
	/* entries (struct stack_entry *) (top is last element) */
	GPtrArray *entries;
};

/* state */
enum state {
	STATE_INIT,
	STATE_DSCOPE_TRACE_PACKET_HEADER_BEGIN,
	STATE_DSCOPE_TRACE_PACKET_HEADER_CONTINUE,
	STATE_AFTER_TRACE_PACKET_HEADER,
	STATE_DSCOPE_STREAM_PACKET_CONTEXT_BEGIN,
	STATE_DSCOPE_STREAM_PACKET_CONTEXT_CONTINUE,
	STATE_AFTER_STREAM_PACKET_CONTEXT,
	STATE_EMIT_NOTIF_NEW_PACKET,
	STATE_DSCOPE_STREAM_EVENT_HEADER_BEGIN,
	STATE_DSCOPE_STREAM_EVENT_HEADER_CONTINUE,
	STATE_AFTER_STREAM_EVENT_HEADER,
	STATE_DSCOPE_STREAM_EVENT_CONTEXT_BEGIN,
	STATE_DSCOPE_STREAM_EVENT_CONTEXT_CONTINUE,
	STATE_DSCOPE_EVENT_CONTEXT_BEGIN,
	STATE_DSCOPE_EVENT_CONTEXT_CONTINUE,
	STATE_DSCOPE_EVENT_PAYLOAD_BEGIN,
	STATE_DSCOPE_EVENT_PAYLOAD_CONTINUE,
	STATE_EMIT_NOTIF_EVENT,
	STATE_EMIT_NOTIF_END_PACKET,
	STATE_SKIP_PACKET_PADDING,
};

/* CTF notification iterator */
struct bt_ctf_notit {
	/* visit stack */
	struct stack *stack;

	/*
	 * Current dynamic scope field pointer.
	 *
	 * This is set when a dynamic scope field is first created by
	 * btr_compound_begin_cb(). It points to one of the fields in
	 * dscopes below.
	 */
	struct bt_ctf_field **cur_dscope_field;

	/* trace and classes (owned by this) */
	struct {
		struct bt_ctf_trace *trace;
		struct bt_ctf_stream_class *stream_class;
		struct bt_ctf_event_class *event_class;
	} meta;

	/* database of current dynamic scopes (owned by this) */
	struct {
		struct bt_ctf_field *trace_packet_header;
		struct bt_ctf_field *stream_packet_context;
		struct bt_ctf_field *stream_event_header;
		struct bt_ctf_field *stream_event_context;
		struct bt_ctf_field *event_context;
		struct bt_ctf_field *event_payload;
	} dscopes;

	/* current state */
	enum state state;

	/* user buffer stuff */
	struct {
		/* last address provided by medium */
		const uint8_t *addr;

		/* buffer size provided by medium (bytes) */
		size_t sz;

		/* offset within whole packet of addr (bits) */
		size_t packet_offset;

		/* current position from addr (bits) */
		size_t at;
	} buf;

	/* binary type reader */
	struct bt_ctf_btr *btr;

	/* medium stuff */
	struct {
		struct bt_ctf_notit_medium_ops medops;
		size_t max_request_sz;
		void *data;
	} medium;

	/* current packet size (bits) (-1 if unknown) */
	size_t cur_packet_size;

	/* current content size (bits) (-1 if unknown) */
	size_t cur_content_size;
};

static
void stack_entry_free_func(gpointer data)
{
	struct stack_entry *entry = data;

	bt_ctf_put(entry->base);
	g_free(entry);
}

static
struct stack *stack_new(void)
{
	struct stack *stack = NULL;

	stack = g_new0(struct stack, 1);

	if (!stack) {
		goto error;
	}

	stack->entries = g_ptr_array_new_with_free_func(stack_entry_free_func);

	if (!stack->entries) {
		goto error;
	}

	return stack;

error:
	g_free(stack);

	return NULL;
}

static
void stack_destroy(struct stack *stack)
{
	assert(stack);
	g_ptr_array_free(stack->entries, TRUE);
	g_free(stack);
}

static
int stack_push(struct stack *stack, struct bt_ctf_field *base)
{
	int ret = 0;
	struct stack_entry *entry;

	assert(stack);
	assert(base);
	entry = g_new0(struct stack_entry, 1);

	if (!entry) {
		ret = -1;
		goto end;
	}

	entry->base = base;
	bt_ctf_field_get(entry->base);

end:
	return ret;
}

static inline
unsigned int stack_size(struct stack *stack)
{
	assert(stack);

	return stack->entries->len;
}

static
void stack_pop(struct stack *stack)
{
	assert(stack);
	assert(stack_size(stack));
	g_ptr_array_remove_index(stack->entries, stack->entries->len - 1);
}

static inline
struct stack_entry *stack_top(struct stack *stack)
{
	assert(stack);
	assert(stack_size(stack));

	return g_ptr_array_index(stack->entries, stack->entries->len - 1);
}

static inline
bool stack_empty(struct stack *stack)
{
	return stack_size(stack) == 0;
}

static
void stack_clear(struct stack *stack)
{
	assert(stack);

	if (!stack_empty(stack)) {
		g_ptr_array_remove_range(stack->entries, 0, stack_size(stack));
	}

	assert(stack_empty(stack));
}

static inline
enum bt_ctf_notit_status notit_status_from_m_status(
	enum bt_ctf_notit_medium_status m_status)
{
	return m_status;
}

static inline
size_t buf_size_bits(struct bt_ctf_notit *notit)
{
	return BYTES_TO_BITS(notit->buf.sz);
}

static inline
size_t buf_available_bits(struct bt_ctf_notit *notit)
{
	return buf_size_bits(notit) - notit->buf.at;
}

static inline
size_t packet_at(struct bt_ctf_notit *notit)
{
	return notit->buf.packet_offset + notit->buf.at;
}

static inline
size_t remaining_content_bits(struct bt_ctf_notit *notit)
{
	if (notit->cur_content_size == -1) {
		return -1;
	}

	return notit->cur_content_size - packet_at(notit);
}

static inline
size_t remaining_packet_bits(struct bt_ctf_notit *notit)
{
	if (notit->cur_packet_size == -1) {
		return -1;
	}

	return notit->cur_packet_size - packet_at(notit);
}

static inline
void buf_consume_bits(struct bt_ctf_notit *notit, size_t incr)
{
	notit->buf.at += incr;
}

static inline
bool buf_has_enough_bits(struct bt_ctf_notit *notit, size_t sz)
{
	return buf_available_bits(notit) >= sz;
}

static
enum bt_ctf_notit_status request_medium_bytes(struct bt_ctf_notit *notit)
{
	uint8_t *buffer_addr;
	size_t buffer_sz;
	enum bt_ctf_notit_medium_status m_status;

	m_status = notit->medium.medops.request_bytes(
		notit->medium.max_request_sz, &buffer_addr,
		&buffer_sz, notit->medium.data);

	if (m_status == BT_CTF_NOTIT_MEDIUM_STATUS_OK) {
		assert(buffer_sz != 0);

		/* new packet offset is old one + old size (in bits) */
		notit->buf.packet_offset += buf_size_bits(notit);

		/* restart at the beginning of the new medium buffer */
		notit->buf.at = 0;

		/* new medium buffer size */
		notit->buf.sz = buffer_sz;

		/* new medium buffer address */
		notit->buf.addr = buffer_addr;
	}

	return notit_status_from_m_status(m_status);
}

static inline
enum bt_ctf_notit_status buf_ensure_available_bits(
	struct bt_ctf_notit *notit)
{
	enum bt_ctf_notit_status status = BT_CTF_NOTIT_STATUS_OK;

	if (buf_available_bits(notit) == 0) {
		/*
		 * This _cannot_ return BT_CTF_NOTIT_STATUS_OK
		 * _and_ no bits.
		 */
		status = request_medium_bytes(notit);
	}

	return status;
}

static
enum bt_ctf_notit_status read_dscope_begin_state(
	struct bt_ctf_notit *notit, struct bt_ctf_field_type *dscope_field_type,
	enum state done_state, enum state continue_state,
	struct bt_ctf_field **dscope_field)
{
	enum bt_ctf_notit_status status = BT_CTF_NOTIT_STATUS_OK;
	enum bt_ctf_btr_status btr_status;
	size_t consumed_bits;

	status = buf_ensure_available_bits(notit);

	if (status != BT_CTF_NOTIT_STATUS_OK) {
		goto end;
	}

	bt_ctf_put(*dscope_field);
	notit->cur_dscope_field = dscope_field;
	consumed_bits = bt_ctf_btr_start(notit->btr, dscope_field_type,
		notit->buf.addr, notit->buf.at, packet_at(notit),
		notit->buf.sz, &btr_status);

	switch (btr_status) {
	case BT_CTF_BTR_STATUS_OK:
		/* type was read completely */
		notit->state = done_state;
		break;

	case BT_CTF_BTR_STATUS_EOF:
		notit->state = continue_state;
		break;

	default:
		status = BT_CTF_NOTIT_STATUS_ERROR;
		goto end;
	}

	/* consume bits now since we know we're not in error state */
	buf_consume_bits(notit, consumed_bits);

end:
	return status;
}

static
enum bt_ctf_notit_status read_dscope_continue_state(
	struct bt_ctf_notit *notit, enum state done_state)
{
	enum bt_ctf_notit_status status = BT_CTF_NOTIT_STATUS_OK;
	enum bt_ctf_btr_status btr_status;
	size_t consumed_bits;

	status = buf_ensure_available_bits(notit);

	if (status != BT_CTF_NOTIT_STATUS_OK) {
		goto end;
	}

	consumed_bits = bt_ctf_btr_continue(notit->btr, notit->buf.addr,
		notit->buf.sz, &btr_status);

	switch (btr_status) {
	case BT_CTF_BTR_STATUS_OK:
		/* type was read completely */
		notit->state = done_state;
		break;

	case BT_CTF_BTR_STATUS_EOF:
		/* stay in this continue state */
		break;

	default:
		status = BT_CTF_NOTIT_STATUS_ERROR;
		goto end;
	}

	/* consume bits now since we know we're not in error state */
	buf_consume_bits(notit, consumed_bits);

end:
	return status;
}

static
void put_event_dscopes(struct bt_ctf_notit *notit)
{
	BT_CTF_PUT(notit->dscopes.stream_event_header);
	BT_CTF_PUT(notit->dscopes.stream_event_context);
	BT_CTF_PUT(notit->dscopes.event_context);
	BT_CTF_PUT(notit->dscopes.event_payload);
}

static
void put_all_dscopes(struct bt_ctf_notit *notit)
{
	BT_CTF_PUT(notit->dscopes.trace_packet_header);
	BT_CTF_PUT(notit->dscopes.stream_packet_context);
	put_event_dscopes(notit);
}

static
enum bt_ctf_notit_status read_packet_header_begin_state(
	struct bt_ctf_notit *notit)
{
	enum bt_ctf_notit_status status = BT_CTF_NOTIT_STATUS_OK;
	struct bt_ctf_field_type *packet_header_type;

	/* reset all dynamic scopes since we're reading a new packet */
	put_all_dscopes(notit);
	BT_CTF_PUT(notit->meta.stream_class);
	BT_CTF_PUT(notit->meta.event_class);

	/* packet header type is common to the whole trace */
	packet_header_type = bt_ctf_trace_get_packet_header_type(
		notit->meta.trace);

	if (!packet_header_type) {
		status = BT_CTF_NOTIT_STATUS_ERROR;
		goto end;
	}

	status = read_dscope_begin_state(notit, packet_header_type,
		STATE_AFTER_TRACE_PACKET_HEADER,
		STATE_DSCOPE_TRACE_PACKET_HEADER_CONTINUE,
		&notit->dscopes.trace_packet_header);

end:
	BT_CTF_PUT(packet_header_type);

	return status;
}

static
enum bt_ctf_notit_status read_packet_header_continue_state(
	struct bt_ctf_notit *notit)
{
	return read_dscope_continue_state(notit,
		STATE_AFTER_TRACE_PACKET_HEADER);
}

static inline
bool is_struct_type(struct bt_ctf_field_type *field_type)
{
	return bt_ctf_field_type_get_type_id(field_type) == CTF_TYPE_STRUCT;
}

static inline
bool is_variant_type(struct bt_ctf_field_type *field_type)
{
	return bt_ctf_field_type_get_type_id(field_type) == CTF_TYPE_VARIANT;
}

static inline
enum bt_ctf_notit_status set_current_stream_class(struct bt_ctf_notit *notit)
{
	enum bt_ctf_notit_status status = BT_CTF_NOTIT_STATUS_OK;
	struct bt_ctf_field_type *packet_header_type;
	struct bt_ctf_field_type *stream_id_field_type = NULL;
	uint64_t stream_id;

	/* is there any "stream_id" field in the packet header? */
	packet_header_type = bt_ctf_trace_get_packet_header_type(
		notit->meta.trace);

	if (!packet_header_type) {
		status = BT_CTF_NOTIT_STATUS_ERROR;
		goto end;
	}

	assert(is_struct_type(packet_header_type));
	stream_id_field_type =
		bt_ctf_field_type_structure_get_field_type_by_name(
			packet_header_type, "stream_id");

	if (stream_id_field_type) {
		/* find appropriate stream class using current stream ID */
		struct bt_ctf_field *stream_id_field = NULL;
		int ret;

		assert(notit->dscopes.trace_packet_header);
		stream_id_field = bt_ctf_field_structure_get_field(
			notit->dscopes.trace_packet_header, "stream_id");
		assert(stream_id_field);
		ret = bt_ctf_field_unsigned_integer_get_value(
			stream_id_field, &stream_id);
		assert(!ret);
		BT_CTF_PUT(stream_id_field);
	} else {
		/* only one stream: pick the first stream class */
		assert(bt_ctf_trace_get_stream_class_count(
			notit->meta.trace) == 1);
		stream_id = 0;
	}

	BT_CTF_PUT(notit->meta.stream_class);

	// TODO: get by ID
	notit->meta.stream_class = bt_ctf_trace_get_stream_class(
		notit->meta.trace, stream_id);

	if (!notit->meta.stream_class) {
		status = BT_CTF_NOTIT_STATUS_ERROR;
		goto end;
	}

end:
	BT_CTF_PUT(packet_header_type);
	BT_CTF_PUT(stream_id_field_type);

	return status;
}

static
enum bt_ctf_notit_status after_packet_header_state(
	struct bt_ctf_notit *notit)
{
	enum bt_ctf_notit_status status;

	status = set_current_stream_class(notit);

	if (status == BT_CTF_NOTIT_STATUS_OK) {
		notit->state = STATE_DSCOPE_STREAM_PACKET_CONTEXT_BEGIN;
	}

	return status;
}

static
enum bt_ctf_notit_status read_packet_context_begin_state(
	struct bt_ctf_notit *notit)
{
	enum bt_ctf_notit_status status = BT_CTF_NOTIT_STATUS_OK;
	struct bt_ctf_field_type *packet_context_type;

	assert(notit->meta.stream_class);
	packet_context_type = bt_ctf_stream_class_get_packet_context_type(
		notit->meta.stream_class);

	if (!packet_context_type) {
		status = BT_CTF_NOTIT_STATUS_ERROR;
		goto end;
	}

	status = read_dscope_begin_state(notit, packet_context_type,
		STATE_AFTER_STREAM_PACKET_CONTEXT,
		STATE_DSCOPE_STREAM_PACKET_CONTEXT_CONTINUE,
		&notit->dscopes.stream_packet_context);

end:
	BT_CTF_PUT(packet_context_type);

	return status;
}

static
enum bt_ctf_notit_status read_packet_context_continue_state(
	struct bt_ctf_notit *notit)
{
	return read_dscope_continue_state(notit,
		STATE_AFTER_STREAM_PACKET_CONTEXT);
}

static inline
enum bt_ctf_notit_status set_current_packet_content_sizes(
	struct bt_ctf_notit *notit)
{
	enum bt_ctf_notit_status status;
	struct bt_ctf_field *packet_size_field = NULL;
	struct bt_ctf_field *content_size_field = NULL;
	uint64_t content_size = -1, packet_size = -1;

	assert(notit->dscopes.stream_packet_context);
	packet_size_field = bt_ctf_field_structure_get_field(
		notit->dscopes.stream_packet_context, "packet_size");
	content_size_field = bt_ctf_field_structure_get_field(
		notit->dscopes.stream_packet_context, "content_size");

	if (packet_size_field) {
		int ret = bt_ctf_field_unsigned_integer_get_value(
			packet_size_field, &packet_size);
		assert(!ret);

		if (packet_size == 0 || (packet_size % 8) != 0) {
			status = BT_CTF_NOTIT_STATUS_ERROR;
			goto end;
		}
	}

	if (content_size_field) {
		int ret = bt_ctf_field_unsigned_integer_get_value(
			content_size_field, &content_size);
		assert(!ret);
	} else {
		content_size = packet_size;
	}

	notit->cur_packet_size = packet_size;
	notit->cur_content_size = content_size;

end:
	BT_CTF_PUT(packet_size_field);
	BT_CTF_PUT(content_size_field);

	return status;
}

static
enum bt_ctf_notit_status after_packet_context_state(
	struct bt_ctf_notit *notit)
{
	enum bt_ctf_notit_status status;

	status = set_current_packet_content_sizes(notit);

	if (status == BT_CTF_NOTIT_STATUS_OK) {
		notit->state = STATE_EMIT_NOTIF_NEW_PACKET;
	}

	return status;
}

static
enum bt_ctf_notit_status read_event_header_begin_state(
	struct bt_ctf_notit *notit)
{
	enum bt_ctf_notit_status status = BT_CTF_NOTIT_STATUS_OK;
	struct bt_ctf_field_type *event_header_type;

	/* check if we have some content left */
	if (notit->cur_content_size >= 0) {
		if (packet_at(notit) == notit->cur_content_size) {
			/* no more events! */
			notit->state = STATE_SKIP_PACKET_PADDING;
			goto end;
		} else if (packet_at(notit) > notit->cur_content_size) {
			/* that's not supposed to happen */
			status = BT_CTF_NOTIT_STATUS_ERROR;
			goto end;
		}
	}

	event_header_type = bt_ctf_stream_class_get_event_header_type(
		notit->meta.stream_class);

	if (!event_header_type) {
		status = BT_CTF_NOTIT_STATUS_ERROR;
		goto end;
	}

	status = read_dscope_begin_state(notit, event_header_type,
		STATE_AFTER_STREAM_EVENT_HEADER,
		STATE_DSCOPE_STREAM_EVENT_HEADER_CONTINUE,
		&notit->dscopes.stream_packet_context);

end:
	BT_CTF_PUT(event_header_type);

	return status;
}

static
enum bt_ctf_notit_status read_event_header_continue_state(
	struct bt_ctf_notit *notit)
{
	return read_dscope_continue_state(notit,
		STATE_AFTER_STREAM_EVENT_HEADER);
}

static inline
enum bt_ctf_notit_status set_current_event_class(struct bt_ctf_notit *notit)
{
	enum bt_ctf_notit_status status = BT_CTF_NOTIT_STATUS_OK;
	struct bt_ctf_field_type *event_header_type;
	struct bt_ctf_field_type *id_field_type = NULL;
	uint64_t event_id;

	/* is there any "id" field in the event header? */
	event_header_type = bt_ctf_stream_class_get_event_header_type(
		notit->meta.stream_class);

	if (!event_header_type) {
		status = BT_CTF_NOTIT_STATUS_ERROR;
		goto end;
	}

	assert(is_struct_type(event_header_type));
	id_field_type = bt_ctf_field_type_structure_get_field_type_by_name(
		event_header_type, "id");

	if (id_field_type) {
		/* find appropriate stream class using current stream ID */
		struct bt_ctf_field *id_field = NULL;
		int ret;

		assert(notit->dscopes.stream_event_header);
		id_field = bt_ctf_field_structure_get_field(
			notit->dscopes.stream_event_header, "id");
		assert(id_field);
		ret = bt_ctf_field_unsigned_integer_get_value(
			id_field, &event_id);
		assert(!ret);
		BT_CTF_PUT(id_field);
	} else {
		// TODO: LTTng event header with variant

		/* single event */
		assert(bt_ctf_stream_class_get_event_class_count(
			notit->meta.stream_class) == 1);
		event_id = 0;
	}

	BT_CTF_PUT(notit->meta.event_class);
	notit->meta.event_class = bt_ctf_stream_class_get_event_class_by_id(
		notit->meta.stream_class, event_id);

	if (!notit->meta.event_class) {
		status = BT_CTF_NOTIT_STATUS_ERROR;
		goto end;
	}

end:
	BT_CTF_PUT(event_header_type);
	BT_CTF_PUT(id_field_type);

	return status;
}

static
enum bt_ctf_notit_status after_event_header_state(
	struct bt_ctf_notit *notit)
{
	enum bt_ctf_notit_status status;

	status = set_current_packet_content_sizes(notit);

	if (status == BT_CTF_NOTIT_STATUS_OK) {
		notit->state = STATE_DSCOPE_STREAM_EVENT_CONTEXT_BEGIN;
	}

	return status;
}

static
enum bt_ctf_notit_status read_stream_event_context_begin_state(
	struct bt_ctf_notit *notit)
{
	enum bt_ctf_notit_status status = BT_CTF_NOTIT_STATUS_OK;
	struct bt_ctf_field_type *stream_event_context_type;

	if (status != BT_CTF_NOTIT_STATUS_OK) {
		goto end;
	}

	stream_event_context_type = bt_ctf_stream_class_get_event_context_type(
		notit->meta.stream_class);

	if (!stream_event_context_type) {
		status = BT_CTF_NOTIT_STATUS_ERROR;
		goto end;
	}

	status = read_dscope_begin_state(notit, stream_event_context_type,
		STATE_DSCOPE_EVENT_CONTEXT_BEGIN,
		STATE_DSCOPE_STREAM_EVENT_CONTEXT_CONTINUE,
		&notit->dscopes.stream_event_context);

end:
	BT_CTF_PUT(stream_event_context_type);

	return status;
}

static
enum bt_ctf_notit_status read_stream_event_context_continue_state(
	struct bt_ctf_notit *notit)
{
	return read_dscope_continue_state(notit,
		STATE_DSCOPE_EVENT_CONTEXT_BEGIN);
}

static
enum bt_ctf_notit_status read_event_context_begin_state(
	struct bt_ctf_notit *notit)
{
	enum bt_ctf_notit_status status = BT_CTF_NOTIT_STATUS_OK;
	struct bt_ctf_field_type *event_context_type;

	if (status != BT_CTF_NOTIT_STATUS_OK) {
		goto end;
	}

	event_context_type = bt_ctf_event_class_get_context_type(
		notit->meta.event_class);

	if (!event_context_type) {
		status = BT_CTF_NOTIT_STATUS_ERROR;
		goto end;
	}

	status = read_dscope_begin_state(notit, event_context_type,
		STATE_DSCOPE_EVENT_PAYLOAD_BEGIN,
		STATE_DSCOPE_EVENT_CONTEXT_CONTINUE,
		&notit->dscopes.event_context);

end:
	BT_CTF_PUT(event_context_type);

	return status;
}

static
enum bt_ctf_notit_status read_event_context_continue_state(
	struct bt_ctf_notit *notit)
{
	return read_dscope_continue_state(notit,
		STATE_DSCOPE_EVENT_PAYLOAD_BEGIN);
}

static
enum bt_ctf_notit_status read_event_payload_begin_state(
	struct bt_ctf_notit *notit)
{
	enum bt_ctf_notit_status status = BT_CTF_NOTIT_STATUS_OK;
	struct bt_ctf_field_type *event_payload_type;

	if (status != BT_CTF_NOTIT_STATUS_OK) {
		goto end;
	}

	event_payload_type = bt_ctf_event_class_get_payload_type(
		notit->meta.event_class);

	if (!event_payload_type) {
		status = BT_CTF_NOTIT_STATUS_ERROR;
		goto end;
	}

	status = read_dscope_begin_state(notit, event_payload_type,
		STATE_EMIT_NOTIF_EVENT,
		STATE_DSCOPE_EVENT_PAYLOAD_CONTINUE,
		&notit->dscopes.event_payload);

end:
	BT_CTF_PUT(event_payload_type);

	return status;
}

static
enum bt_ctf_notit_status read_event_payload_continue_state(
	struct bt_ctf_notit *notit)
{
	return read_dscope_continue_state(notit, STATE_EMIT_NOTIF_EVENT);
}

static
enum bt_ctf_notit_status skip_packet_padding_state(
	struct bt_ctf_notit *notit)
{
	enum bt_ctf_notit_status status = BT_CTF_NOTIT_STATUS_OK;
	size_t bits_to_skip;

	assert(notit->cur_packet_size > 0);
	bits_to_skip = notit->cur_packet_size - packet_at(notit);

	if (bits_to_skip == 0) {
		notit->state = STATE_DSCOPE_TRACE_PACKET_HEADER_BEGIN;
		goto end;
	} else {
		size_t bits_to_consume;
		status = buf_ensure_available_bits(notit);

		if (status != BT_CTF_NOTIT_STATUS_OK) {
			goto end;
		}

		bits_to_consume = MIN(buf_available_bits(notit), bits_to_skip);
		buf_consume_bits(notit, bits_to_consume);
		bits_to_skip = notit->cur_packet_size - packet_at(notit);

		if (bits_to_skip == 0) {
			notit->state = STATE_DSCOPE_TRACE_PACKET_HEADER_BEGIN;
			goto end;
		}
	}

end:
	return status;
}

static inline
enum bt_ctf_notit_status handle_state(struct bt_ctf_notit *notit)
{
	enum bt_ctf_notit_status status = BT_CTF_NOTIT_STATUS_OK;

	switch (notit->state) {
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

	case STATE_EMIT_NOTIF_NEW_PACKET:
		notit->state = STATE_DSCOPE_STREAM_EVENT_HEADER_BEGIN;
		break;

	case STATE_DSCOPE_STREAM_EVENT_HEADER_BEGIN:
		status = read_event_header_begin_state(notit);
		break;

	case STATE_DSCOPE_STREAM_EVENT_HEADER_CONTINUE:
		status = read_event_header_continue_state(notit);
		break;

	case STATE_AFTER_STREAM_EVENT_HEADER:
		status = after_event_header_state(notit);
		break;

	case STATE_DSCOPE_STREAM_EVENT_CONTEXT_BEGIN:
		status = read_stream_event_context_begin_state(notit);
		break;

	case STATE_DSCOPE_STREAM_EVENT_CONTEXT_CONTINUE:
		status = read_stream_event_context_continue_state(notit);
		break;

	case STATE_DSCOPE_EVENT_CONTEXT_BEGIN:
		status = read_event_context_begin_state(notit);
		break;

	case STATE_DSCOPE_EVENT_CONTEXT_CONTINUE:
		status = read_event_context_continue_state(notit);
		break;

	case STATE_DSCOPE_EVENT_PAYLOAD_BEGIN:
		status = read_event_payload_begin_state(notit);
		break;

	case STATE_DSCOPE_EVENT_PAYLOAD_CONTINUE:
		status = read_event_payload_continue_state(notit);
		break;

	case STATE_EMIT_NOTIF_EVENT:
		notit->state = STATE_DSCOPE_STREAM_EVENT_HEADER_BEGIN;
		break;

	case STATE_EMIT_NOTIF_END_PACKET:
		notit->state = STATE_SKIP_PACKET_PADDING;
		break;

	case STATE_SKIP_PACKET_PADDING:
		status = skip_packet_padding_state(notit);
		break;
	}

	return status;
}

void bt_ctf_notit_reset(struct bt_ctf_notit *notit)
{
	assert(notit);
	stack_clear(notit->stack);
	BT_CTF_PUT(notit->meta.stream_class);
	BT_CTF_PUT(notit->meta.event_class);
	put_all_dscopes(notit);
	notit->buf.addr = NULL;
	notit->buf.sz = 0;
	notit->buf.at = 0;
	notit->buf.packet_offset = 0;
	notit->state = STATE_INIT;
	notit->cur_content_size = -1;
	notit->cur_packet_size = -1;
}

static
struct bt_ctf_field *get_next_field(struct bt_ctf_notit *notit)
{
	struct bt_ctf_field *next_field = NULL;
	struct bt_ctf_field *base_field;
	struct bt_ctf_field_type *base_type;
	size_t index;

	assert(!stack_empty(notit->stack));
	index = stack_top(notit->stack)->index;
	base_field = stack_top(notit->stack)->base;
	base_type = bt_ctf_field_get_type(base_field);

	if (!base_type) {
		goto end;
	}

	switch (bt_ctf_field_type_get_type_id(base_type)) {
	case CTF_TYPE_STRUCT:
		next_field = bt_ctf_field_structure_get_field_by_index(
			base_field, index);
		break;

	case CTF_TYPE_ARRAY:
		next_field = bt_ctf_field_array_get_field(base_field, index);
		break;

	case CTF_TYPE_SEQUENCE:
		next_field = bt_ctf_field_sequence_get_field(base_field, index);
		break;

	case CTF_TYPE_VARIANT:
		next_field = bt_ctf_field_variant_get_current_field(base_field);
		break;

	default:
		assert(false);
		break;
	}

end:
	BT_CTF_PUT(base_type);

	return next_field;
}

static
enum bt_ctf_btr_status btr_signed_int_cb(int64_t value,
	struct bt_ctf_field_type *type, void *data)
{
	enum bt_ctf_btr_status status = BT_CTF_BTR_STATUS_OK;
	struct bt_ctf_field *field = NULL;
	struct bt_ctf_notit *notit = data;
	int ret;

	/* create next field */
	field = get_next_field(notit);

	if (!field) {
		status = BT_CTF_BTR_STATUS_ERROR;
		goto end;
	}

	switch(bt_ctf_field_type_get_type_id(type)) {
	case CTF_TYPE_INTEGER:
		ret = bt_ctf_field_signed_integer_set_value(field, value);
		assert(!ret);
		break;

	case CTF_TYPE_ENUM:
	{
		struct bt_ctf_field *int_field;

		int_field = bt_ctf_field_enumeration_get_container(field);
		assert(int_field);
		ret = bt_ctf_field_signed_integer_set_value(int_field, value);
		assert(!ret);
		BT_CTF_PUT(int_field);
		break;
	}

	default:
		status = BT_CTF_BTR_STATUS_ERROR;
		goto end;
	}

	stack_top(notit->stack)->index++;

end:
	BT_CTF_PUT(field);

	return status;
}

static
enum bt_ctf_btr_status btr_unsigned_int_cb(uint64_t value,
	struct bt_ctf_field_type *type, void *data)
{
	enum bt_ctf_btr_status status = BT_CTF_BTR_STATUS_OK;
	struct bt_ctf_field *field = NULL;
	struct bt_ctf_notit *notit = data;
	int ret;

	/* create next field */
	field = get_next_field(notit);

	if (!field) {
		status = BT_CTF_BTR_STATUS_ERROR;
		goto end;
	}

	switch(bt_ctf_field_type_get_type_id(type)) {
	case CTF_TYPE_INTEGER:
		ret = bt_ctf_field_unsigned_integer_set_value(field, value);
		assert(!ret);
		break;

	case CTF_TYPE_ENUM:
	{
		struct bt_ctf_field *int_field;

		int_field = bt_ctf_field_enumeration_get_container(field);
		assert(int_field);
		ret = bt_ctf_field_unsigned_integer_set_value(int_field, value);
		assert(!ret);
		BT_CTF_PUT(int_field);
		break;
	}

	default:
		status = BT_CTF_BTR_STATUS_ERROR;
		goto end;
	}

	stack_top(notit->stack)->index++;

end:
	BT_CTF_PUT(field);

	return status;
}

static
enum bt_ctf_btr_status btr_floating_point_cb(double value,
	struct bt_ctf_field_type *type, void *data)
{
	enum bt_ctf_btr_status status = BT_CTF_BTR_STATUS_OK;
	struct bt_ctf_field *field = NULL;
	struct bt_ctf_notit *notit = data;
	int ret;

	/* create next field */
	field = get_next_field(notit);

	if (!field) {
		status = BT_CTF_BTR_STATUS_ERROR;
		goto end;
	}

	ret = bt_ctf_field_floating_point_set_value(field, value);
	assert(!ret);
	stack_top(notit->stack)->index++;

end:
	BT_CTF_PUT(field);

	return status;
}

static
enum bt_ctf_btr_status btr_string_begin_cb(
	struct bt_ctf_field_type *type, void *data)
{
	enum bt_ctf_btr_status status = BT_CTF_BTR_STATUS_OK;
	struct bt_ctf_field *field = NULL;
	struct bt_ctf_notit *notit = data;
	int ret;

	/* create next field */
	field = get_next_field(notit);

	/*
	 * Push on stack. Not a compound type per se, but we know that only
	 * btr_string_cb() may be called between this call and a subsequent
	 * call to btr_string_end_cb().
	 */
	ret = stack_push(notit->stack, field);

	if (ret) {
		status = BT_CTF_BTR_STATUS_ERROR;
		goto end;
	}

end:
	BT_CTF_PUT(field);

	return status;
}

static
enum bt_ctf_btr_status btr_string_cb(const char *value,
	size_t len, struct bt_ctf_field_type *type, void *data)
{
	enum bt_ctf_btr_status status = BT_CTF_BTR_STATUS_OK;
	struct bt_ctf_field *field = NULL;
	struct bt_ctf_notit *notit = data;
	int ret;

	/* get string field */
	field = stack_top(notit->stack)->base;
	assert(field);

	/* append current string */
	ret = bt_ctf_field_string_append_len(field, value, len);

	if (ret) {
		status = BT_CTF_BTR_STATUS_ERROR;
		goto end;
	}

end:
	return status;
}

static
enum bt_ctf_btr_status btr_string_end_cb(
	struct bt_ctf_field_type *type, void *data)
{
	struct bt_ctf_notit *notit = data;

	/* pop string field */
	stack_pop(notit->stack);

	/* go to next field */
	stack_top(notit->stack)->index++;

	return BT_CTF_BTR_STATUS_OK;
}

enum bt_ctf_btr_status btr_compound_begin_cb(
	struct bt_ctf_field_type *type, void *data)
{
	enum bt_ctf_btr_status status = BT_CTF_BTR_STATUS_OK;
	struct bt_ctf_notit *notit = data;
	struct bt_ctf_field *field;
	int ret;

	/* create field */
	if (stack_empty(notit->stack)) {
		/* root: create dynamic scope field */
		*notit->cur_dscope_field = bt_ctf_field_create(type);
	} else {
		field = get_next_field(notit);
	}

	if (!field) {
		status = BT_CTF_BTR_STATUS_ERROR;
		goto end;
	}

	/* push field */
	ret = stack_push(notit->stack, field);

	if (ret) {
		status = BT_CTF_BTR_STATUS_ERROR;
		goto end;
	}

end:
	BT_CTF_PUT(field);

	return status;
}

enum bt_ctf_btr_status btr_compound_end_cb(
	struct bt_ctf_field_type *type, void *data)
{
	struct bt_ctf_notit *notit = data;

	assert(!stack_empty(notit->stack));

	/* pop stack now */
	stack_pop(notit->stack);

	return BT_CTF_BTR_STATUS_OK;
}

static
struct bt_ctf_field *resolve_field(struct bt_ctf_notit *notit,
	struct bt_ctf_field_path *path)
{
	struct bt_ctf_field *field = NULL;
	unsigned int i;

	switch (path->root) {
	case CTF_NODE_TRACE_PACKET_HEADER:
		field = notit->dscopes.trace_packet_header;
		break;

	case CTF_NODE_STREAM_PACKET_CONTEXT:
		field = notit->dscopes.stream_packet_context;
		break;

	case CTF_NODE_STREAM_EVENT_HEADER:
		field = notit->dscopes.stream_event_header;
		break;

	case CTF_NODE_STREAM_EVENT_CONTEXT:
		field = notit->dscopes.stream_event_context;
		break;

	case CTF_NODE_EVENT_CONTEXT:
		field = notit->dscopes.event_context;
		break;

	case CTF_NODE_EVENT_FIELDS:
		field = notit->dscopes.event_payload;
		break;

	default:
		break;
	}

	if (!field) {
		goto end;
	}

	bt_ctf_get(field);

	for (i = 0; i < path->path_indexes->len; ++i) {
		struct bt_ctf_field *next_field = NULL;
		struct bt_ctf_field_type *field_type;
		int index = g_array_index(path->path_indexes, int, i);

		field_type = bt_ctf_field_get_type(field);

		if (!field_type) {
			BT_CTF_PUT(field);
			goto end;
		}

		if (is_struct_type(field_type)) {
			next_field = bt_ctf_field_structure_get_field_by_index(
				field, index);
		} else if (is_variant_type(field_type)) {
			next_field =
				bt_ctf_field_variant_get_current_field(field);
		}

		BT_CTF_PUT(field);
		BT_CTF_PUT(field_type);

		if (!next_field) {
			goto end;
		}

		/* move next field -> field */
		field = next_field;
		next_field = NULL;
	}

end:
	return field;
}

static
int64_t btr_get_sequence_length_cb(struct bt_ctf_field_type *type,
	void *data)
{
	int64_t ret = -1;
	int iret;
	struct bt_ctf_field_path *path;
	struct bt_ctf_notit *notit = data;
	struct bt_ctf_field *field = NULL;
	uint64_t length;

	path = bt_ctf_field_type_sequence_get_length_field_path(type);

	if (!path) {
		goto end;
	}

	field = resolve_field(notit, path);

	if (!field) {
		goto end;
	}

	iret = bt_ctf_field_unsigned_integer_get_value(field, &length);

	if (iret) {
		goto end;
	}

	ret = (int64_t) length;

end:
	BT_CTF_PUT(field);

	return ret;
}

static
struct bt_ctf_field_type *btr_get_variant_type_cb(
	struct bt_ctf_field_type *type, void *data)
{
	return NULL;
}

struct bt_ctf_notit *bt_ctf_notit_create(struct bt_ctf_trace *trace,
	size_t max_request_sz, struct bt_ctf_notit_medium_ops medops,
	void *data)
{
	struct bt_ctf_notit *notit = NULL;
	struct bt_ctf_btr_cbs cbs = {
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
			.get_variant_type = btr_get_variant_type_cb,
		},
	};

	assert(trace);
	assert(medops.request_bytes);
	notit = g_new0(struct bt_ctf_notit, 1);

	if (!notit) {
		goto end;
	}

	notit->meta.trace = trace;
	bt_ctf_trace_get(notit->meta.trace);
	notit->medium.medops = medops;

	if (max_request_sz == 0) {
		notit->medium.max_request_sz = 4096;
	} else {
		notit->medium.max_request_sz = max_request_sz;
	}

	notit->medium.data = data;
	notit->stack = stack_new();

	if (!notit->stack) {
		bt_ctf_notit_destroy(notit);
		notit = NULL;
		goto end;
	}

	notit->btr = bt_ctf_btr_create(cbs, notit);

	if (!notit->btr) {
		bt_ctf_notit_destroy(notit);
		notit = NULL;
	}

	bt_ctf_notit_reset(notit);

end:
	return notit;
}

void bt_ctf_notit_destroy(struct bt_ctf_notit *notit)
{
	BT_CTF_PUT(notit->meta.trace);
	BT_CTF_PUT(notit->meta.stream_class);
	BT_CTF_PUT(notit->meta.event_class);
	put_all_dscopes(notit);

	if (notit->stack) {
		stack_destroy(notit->stack);
	}

	if (notit->btr) {
		bt_ctf_btr_destroy(notit->btr);
	}

	g_free(notit);
}

enum bt_ctf_notit_status bt_ctf_notit_get_next_notification(
	struct bt_ctf_notit *notit, struct bt_ctf_notit_notif **notification)
{
	enum bt_ctf_notit_status status = BT_CTF_NOTIT_STATUS_OK;

	assert(notit);
	assert(notification);

	while (true) {
		status = handle_state(notit);

		if (status != BT_CTF_NOTIT_STATUS_OK) {
			goto end;
		}

		switch (notit->state) {
		case STATE_EMIT_NOTIF_NEW_PACKET:
			// TODO: create new packet notification and set
			goto end;

		case STATE_EMIT_NOTIF_EVENT:
			// TODO: create event notification and set
			goto end;

		case STATE_EMIT_NOTIF_END_PACKET:
			// TODO: create end of packet notification and set
			goto end;

		default:
			/* non-emit state: continue */
			break;
		}
	}

end:
	return status;
}
