/*
 * Babeltrace - CTF binary file reader
 *                  ¯¯     ¯¯   ¯
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
#include <assert.h>
#include <string.h>
#include <babeltrace/ctf-ir/ctf-bifir.h>
#include <babeltrace/ctf-ir/ctf-btr.h>
#include <babeltrace/bitfield.h>
#include <babeltrace/ctf-ir/event-types.h>
#include <babeltrace/ctf-ir/event-fields.h>
#include <babeltrace/ctf-ir/stream-class.h>
#include <glib.h>

#define BYTES_TO_BITS(x)		((x) * 8)
#define BITS_TO_BYTES_FLOOR(x)		((x) >> 3)
#define BITS_TO_BYTES_CEIL(x)		(((x) + 7) >> 3)
#define IN_BYTE_OFFSET(at)		((at) & 7)

/* a visit stack entry */
struct stack_entry {
	/*
	 * Current base field, one of:
	 *
	 *   * structure
	 *   * array
	 *   * sequence
	 *   * variant
	 *
	 * Field is owned by this.
	 */
	struct bt_ctf_field *base;

	/* index of next field to read */
	int64_t index;
};

/* visit stack */
struct stack {
	/* entries (struct stack_entry *) (top is last element) */
	GPtrArray *entries;
};

/*
 * Global decoding state, as such:
 *
 *   * GDS_INIT: initializes the context to begin the decoding of an
 *     an entity. The entity to decode is ctx->entity. This state
 *     creates the first field for this entity's field type, and pushes
 *     it to the visit stack as its root entry.
 *   * GDS_DECODE: decode phase. The field decoding state handler is
 *     called here as long as it needs to continue, that is, as long as
 *     there's something on the visit stack.
 */
enum global_decoding_state {
	GDS_INIT,
	GDS_DECODE,
	GDS_DONE,
};

/* decoding entities */
enum decoding_entity {
	ENTITY_TRACE_PACKET_HEADER,
	ENTITY_STREAM_PACKET_CONTEXT,
	ENTITY_STREAM_EVENT_HEADER,
	ENTITY_STREAM_EVENT_CONTEXT,
	ENTITY_EVENT_CONTEXT,
	ENTITY_EVENT_PAYLOAD,
};

/* binary file reader */
struct bt_ctf_bifir {
	/* visit stack */
	struct stack *stack;

	/*
	 * Last decoded entity.
	 *
	 * This variable is only used for communication between the
	 * decoding functions and the state handling function. It must
	 * be NULL whenever a packet reader API function is entered or
	 * exited.
	 */
	struct bt_ctf_field *last_decoded_entity;

	/* trace and classes (owned by this) */
	struct {
		struct bt_ctf_trace *trace;
		struct bt_ctf_stream_class *stream_class;
		struct bt_ctf_event_class *event_class;
	} meta;

	/* current concrete stuff (owned by this) */
	struct {
		struct bt_ctf_field *trace_packet_header;
		struct bt_ctf_field *stream_packet_context;
		struct bt_ctf_field *stream_event_header;
		struct bt_ctf_field *stream_event_context;
		struct bt_ctf_field *event_context;
		struct bt_ctf_field *event_payload;
	} entities;

	/* state variables */
	struct {
		/* current global decoding state */
		enum global_decoding_state global;

		/* current entity being decoded */
		enum decoding_entity entity;
	} state;

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

	/* medium stuff */
	struct {
		struct bt_ctf_bifir_medium_ops medops;
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

	bt_ctf_field_put(entry->base);
	bt_ctf_field_type_put(entry->base_type);
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

static inline
enum bt_ctf_bifir_status bifir_status_from_m_status(
	enum bt_ctf_bifir_medium_status m_status)
{
	return m_status;
}

static inline
size_t available_bits(struct bt_ctf_stream_reader_ctx *ctx)
{
	return ctx->buf.length - ctx->buf.at;
}

static inline
void consume_bits(struct bt_ctf_stream_reader_ctx *ctx, size_t incr)
{
	ctx->buf.at += incr;
}

static inline
bool has_enough_bits(struct bt_ctf_stream_reader_ctx *ctx, size_t len)
{
	return available_bits(ctx) >= len;
}

static
enum bt_ctf_stream_reader_status request_bytes(
	struct bt_ctf_stream_reader_ctx *ctx)
{
	uint8_t *buffer_addr;
	size_t buffer_sz;
	enum bt_ctf_medium_status m_status;

	m_status = ctx->medium.medops.get_next_bytes(
		ctx->medium.max_request_sz, &buffer_addr,
		&buffer_sz, ctx->medium.data);

	if (m_status == BT_CTF_BIFIR_MEDIUM_STATUS_OK) {
		ctx->buf.stream_offset += ctx->buf.length;
		ctx->buf.at = 0;
		ctx->buf.length = BYTES_TO_BITS(buffer_len);
		ctx->buf.addr = buffer_addr;
	}

	return bifir_status_from_m_status(m_status);
}

static inline
enum bt_ctf_stream_reader_status ensure_available_bits(
	struct bt_ctf_stream_reader_ctx *ctx)
{
	enum bt_ctf_stream_reader_status status =
		BT_CTF_STREAM_READER_STATUS_OK;

	if (available_bits(ctx) == 0) {
		/*
		 * This cannot return BT_CTF_STREAM_READER_STATUS_OK
		 * and no bits.
		 */
		status = request_bytes(ctx);
	}

	return status;
}

static inline
size_t stream_at(struct bt_ctf_stream_reader_ctx *ctx)
{
	return ctx->buf.stream_offset + ctx->buf.at;
}

static inline
int64_t get_field_length(struct bt_ctf_stream_reader_ctx *ctx,
	struct bt_ctf_field_type *field_type)
{
	int64_t length;

	switch (bt_ctf_field_type_get_type_id(field_type)) {
	case CTF_TYPE_STRUCT:
		length = (int64_t) bt_ctf_field_type_structure_get_field_count(
			field_type);
		break;

	case CTF_TYPE_VARIANT:
		length = (int64_t) bt_ctf_field_type_variant_get_field_count(
			field_type);
		break;

	case CTF_TYPE_ARRAY:
		length = bt_ctf_field_type_array_get_length(field_type);
		break;

	default:
		length = -1;
	}

	return length;
}

static inline
int get_basic_field_length(struct bt_ctf_field_type *field_type)
{
	int size;

	switch (bt_ctf_field_type_get_type_id(field_type)) {
	case CTF_TYPE_INTEGER:
		size = bt_ctf_field_type_integer_get_size(field_type);
		break;

	case CTF_TYPE_FLOAT:
	{
		int exp_dig, mant_dig;

		exp_dig =
			bt_ctf_field_type_floating_point_get_exponent_digits(
				field_type);
		mant_dig =
			bt_ctf_field_type_floating_point_get_mantissa_digits(
				field_type);

		if (exp_dig < 0 || mant_dig < 0) {
			size = -1;
		}

		size = exp_dig + mant_dig;
		break;
	}

	case CTF_TYPE_ENUM:
	{
		struct bt_ctf_field_type *int_type;

		int_type = bt_ctf_field_type_enumeration_get_container_type(
			field_type);

		if (!int_type) {
			size = -1;
			goto end;
		}

		size = get_basic_field_length(int_type);
		bt_ctf_field_type_put(int_type);
		break;
	}

	case CTF_TYPE_STRING:
		size = 8;
		break;

	default:
		size = -1;
		break;
	}

end:
	return size;
}

static
void stitch_reset(struct bt_ctf_stream_reader_ctx *ctx)
{
	ctx->stitch.offset = 0;
	ctx->stitch.length = 0;
}

static
void stitch_append_from_buf(struct bt_ctf_stream_reader_ctx *ctx, size_t length)
{
	size_t stitch_byte_at =
		BITS_TO_BYTES_FLOOR(ctx->stitch.offset + ctx->stitch.length);
	size_t buf_byte_at = BITS_TO_BYTES_FLOOR(ctx->buf.at);
	size_t nb_bytes = BITS_TO_BYTES_CEIL(length);

	assert(nb_bytes > 0);
	memcpy(&ctx->stitch.buf[stitch_byte_at], &ctx->buf.addr[buf_byte_at],
		nb_bytes);
	ctx->stitch.length += length;
	consume_bits(ctx, length);
}

static
void stitch_append_from_remaining_buf(struct bt_ctf_stream_reader_ctx *ctx)
{
	stitch_append_from_buf(ctx, available_bits(ctx));
}

static
void stitch_set_from_remaining_buf(struct bt_ctf_stream_reader_ctx *ctx)
{
	stitch_reset(ctx);
	ctx->stitch.offset = IN_BYTE_OFFSET(ctx->buf.at);
	stitch_append_from_remaining_buf(ctx);
}

#if 0
static inline
enum bt_ctf_stream_reader_status decode_integer(
	struct bt_ctf_stream_reader_ctx *ctx, struct bt_ctf_field *field,
	struct bt_ctf_field_type *field_type, int read_len)
{
	int ret;
	int signd;
	enum bt_ctf_byte_order bo;
	enum bt_ctf_stream_reader_status status =
		BT_CTF_STREAM_READER_STATUS_OK;

	signd = bt_ctf_field_type_integer_get_signed(field_type);

	if (signd < 0) {
		status = BT_CTF_STREAM_READER_STATUS_ERROR;
		goto end;
	}

	bo = bt_ctf_field_type_get_byte_order(field_type);

	if (bo == BT_CTF_BYTE_ORDER_BIG_ENDIAN ||
			bo == BT_CTF_BYTE_ORDER_NETWORK) {
		if (signd) {
			int64_t v;

			bt_bitfield_read_be(ctx->buf, uint8_t,
				ctx->at, read_len, &v);
			ret = bt_ctf_field_signed_integer_set_value(
				field, v);
		} else {
			uint64_t v;

			bt_bitfield_read_be(ctx->buf, uint8_t,
				ctx->at, read_len, &v);
			ret = bt_ctf_field_unsigned_integer_set_value(
				field, v);
		}
	} else if (bo == BT_CTF_BYTE_ORDER_LITTLE_ENDIAN) {
		if (signd) {
			int64_t v;

			bt_bitfield_read_le(ctx->buf, uint8_t,
				ctx->at, read_len, &v);
			ret = bt_ctf_field_signed_integer_set_value(
				field, v);
		} else {
			uint64_t v;

			bt_bitfield_read_le(ctx->buf, uint8_t,
				ctx->at, read_len, &v);
			ret = bt_ctf_field_unsigned_integer_set_value(
				field, v);
		}
	} else {
		status = BT_CTF_STREAM_READER_STATUS_ERROR;
		goto end;
	}

	if (ret < 0) {
		status = BT_CTF_STREAM_READER_STATUS_ERROR;
		goto end;
	}

end:
	return status;
}

static inline
enum bt_ctf_stream_reader_status decode_float(
	struct bt_ctf_stream_reader_ctx *ctx, struct bt_ctf_field *field,
	struct bt_ctf_field_type *field_type, int read_len)
{
	int ret;
	double dblval;
	enum bt_ctf_byte_order bo;
	enum bt_ctf_stream_reader_status status =
		BT_CTF_STREAM_READER_STATUS_OK;

	union {
		uint32_t u;
		float f;
	} f32;

	union {
		uint64_t u;
		double f;
	} f64;

	bo = bt_ctf_field_type_get_byte_order(field_type);

	switch (read_len) {
	case 32:
	{
		if (bo == BT_CTF_BYTE_ORDER_BIG_ENDIAN ||
				bo == BT_CTF_BYTE_ORDER_NETWORK) {
			bt_bitfield_read_be(ctx->buf, uint8_t,
					ctx->at, read_len, &f32.u);
		} else if (bo == BT_CTF_BYTE_ORDER_LITTLE_ENDIAN) {
			bt_bitfield_read_le(ctx->buf, uint8_t,
					ctx->at, read_len, &f32.u);
		} else {
			status = BT_CTF_STREAM_READER_STATUS_ERROR;
			goto end;
		}

		dblval = (double) f32.f;
		break;
	}

	case 64:
	{
		if (bo == BT_CTF_BYTE_ORDER_BIG_ENDIAN ||
				bo == BT_CTF_BYTE_ORDER_NETWORK) {
			bt_bitfield_read_be(ctx->buf, uint8_t,
					ctx->at, read_len, &f64.u);
		} else if (bo == BT_CTF_BYTE_ORDER_LITTLE_ENDIAN) {
			bt_bitfield_read_le(ctx->buf, uint8_t,
					ctx->at, read_len, &f64.u);
		} else {
			status = BT_CTF_STREAM_READER_STATUS_ERROR;
			goto end;
		}

		dblval = f64.f;
		break;
	}

	default:
		status = BT_CTF_STREAM_READER_STATUS_ERROR;
		goto end;
	}

	ret = bt_ctf_field_floating_point_set_value(field, dblval);

	if (ret < 0) {
		status = BT_CTF_STREAM_READER_STATUS_ERROR;
		goto end;
	}

end:
	return status;
}

static inline
enum bt_ctf_stream_reader_status decode_atomic_field(
	struct bt_ctf_stream_reader_ctx *ctx, struct stack_entry *top,
	struct bt_ctf_field *field, struct bt_ctf_field_type *field_type)
{
	int read_len;
	enum bt_ctf_stream_reader_status status =
		BT_CTF_STREAM_READER_STATUS_OK;

	read_len = get_basic_field_length(field_type);

	if (read_len <= 0) {
		status = BT_CTF_STREAM_READER_STATUS_ERROR;
		goto end;
	}

	/* request bits if needed */
	if (!has_enough_bits(ctx, read_len)) {
		enum bt_ctf_medium_status m_status;
		size_t request_len;

		if (ctx->step_by_step) {
			request_len = read_len;
		} else {
			// TODO: min(ctx->max_request_sz, content_size)
			request_len = ctx->max_request_sz;
		}

		m_status = request_bits(ctx, request_len);
		status = sr_status_from_m_status(m_status);
		goto end;
	}

	/* read atomic field */
	switch (bt_ctf_field_type_get_type_id(field_type)) {
	case CTF_TYPE_INTEGER:
		status = decode_integer(ctx, field, field_type, read_len);

		if (status != BT_CTF_STREAM_READER_STATUS_OK) {
			goto end;
		}
		break;

	case CTF_TYPE_FLOAT:
		status = decode_float(ctx, field, field_type, read_len);

		if (status != BT_CTF_STREAM_READER_STATUS_OK) {
			goto end;
		}
		break;

	default:
		status = BT_CTF_STREAM_READER_STATUS_ERROR;
		goto end;
	}

	/* update current buffer position */
	ctx->at += read_len;

	/* we decoded the field: increment stack top entry's index */
	top->index++;

end:
	return status;
}
#endif

static inline
enum state_machine_action handle_fds_init(struct bt_ctf_stream_reader_ctx *ctx,
	enum bt_ctf_stream_reader_status *status)
{
	struct bt_ctf_field_type *next_field_type = NULL;
	enum state_machine_action action = SMA_CONTINUE;
	struct bt_ctf_field *next_field = NULL;
	struct stack_entry *top;
	int64_t field_length;
	int ret;

	*status = BT_CTF_STREAM_READER_STATUS_OK;
	top = stack_top(ctx->stack);

	/* are we done decoding the fields of the base field? */
	if (top->index == top->base_len) {
		/* decoded the whole root field? */
		if (stack_size(ctx->stack) == 1) {
			/* set last decoded entity */
			ctx->last_decoded_entity = top->base;
			bt_ctf_field_get(ctx->last_decoded_entity);
			action = SMA_DONE;
		}

		stack_pop(ctx->stack);
		goto end;
	}

	/* create next field */
	switch (bt_ctf_field_type_get_type_id(top->base_type)) {
	case CTF_TYPE_STRUCT:
		next_field = bt_ctf_field_structure_get_field_by_index(
			top->base, top->index);
		break;

	case CTF_TYPE_ARRAY:
		next_field = bt_ctf_field_array_get_field(
			top->base, top->index);
		break;

	default:
		break;
	}

	if (!next_field) {
		action = SMA_ERROR;
		goto end;
	}

	/* get next field's type */
	next_field_type = bt_ctf_field_get_type(next_field);

	if (!next_field_type) {
		action = SMA_ERROR;
		goto end;
	}

	switch (bt_ctf_field_type_get_type_id(next_field_type)) {
	case CTF_TYPE_STRUCT:
	case CTF_TYPE_ARRAY:
	case CTF_TYPE_SEQUENCE:
	case CTF_TYPE_VARIANT:
		field_length = get_field_length(ctx, next_field_type);
		ret = stack_push(ctx->stack, next_field, next_field_type,
			field_length);

		if (ret) {
			action = SMA_ERROR;
			goto end;
		}

		top->index++;
		ctx->state.skip_base_padding = true;
		break;

	case CTF_TYPE_INTEGER:
	case CTF_TYPE_FLOAT:
	case CTF_TYPE_ENUM:
	case CTF_TYPE_STRING:
		ctx->state.skip_base_padding = false;
		bt_ctf_field_put(ctx->cur_basic.field);
		ctx->cur_basic.field = next_field;
		next_field = NULL;
		bt_ctf_field_type_put(ctx->cur_basic.field_type);
		ctx->cur_basic.field_type = next_field_type;
		next_field_type = NULL;
		break;

	default:
		assert(false);
		break;
	}

	ctx->state.field = FDS_SKIP_PADDING;

end:
	if (next_field) {
		bt_ctf_field_put(next_field);
	}

	if (next_field_type) {
		bt_ctf_field_type_put(next_field_type);
	}

	return action;
}

static inline
enum state_machine_action handle_fds_skip_padding(
	struct bt_ctf_stream_reader_ctx *ctx,
	enum bt_ctf_stream_reader_status *status)
{
	int field_alignment;
	unsigned int skip_bits;
	size_t aligned_stream_at;
	struct bt_ctf_field_type *field_type;
	enum state_machine_action action = SMA_CONTINUE;

	*status = BT_CTF_STREAM_READER_STATUS_OK;

	if (ctx->state.skip_base_padding) {
		struct stack_entry *top = stack_top(ctx->stack);

		field_type = top->base_type;
	} else {
		field_type = ctx->cur_basic.field_type;
	}

	/* get field's alignment */
	field_alignment = bt_ctf_field_type_get_alignment(field_type);

	if (field_alignment < 0) {
		action = SMA_ERROR;
		goto end;
	}

	/* compute how many bits we need to skip */
	//aligned_stream_at = ALIGN(stream_at(ctx), field_alignment);
	skip_bits = aligned_stream_at - stream_at(ctx);

	/* nothing to skip? done */
	if (skip_bits == 0) {
		if (ctx->state.skip_base_padding) {
			ctx->state.field = FDS_INIT;
		} else {
			ctx->state.field = FDS_DECODE_BASIC_FIELD;
		}

		goto end;
	}

	*status = ensure_available_bits(ctx);

	if (*status != BT_CTF_STREAM_READER_STATUS_OK) {
		if (*status == BT_CTF_STREAM_READER_STATUS_ERROR) {
			action = SMA_ERROR;
		}

		goto end;
	}

	/* consume as many bits as possible in what's left */
	consume_bits(ctx, MIN(available_bits(ctx), skip_bits));

end:
	return action;
}

static inline
int decode_and_set_cur_basic_integer_field(
	struct bt_ctf_stream_reader_ctx *ctx,
	const uint8_t *buf, size_t at)
{
	int ret;
	int signd;
	int64_t field_length;
	enum bt_ctf_byte_order bo;

	signd = bt_ctf_field_type_integer_get_signed(ctx->cur_basic.field_type);
	field_length = get_basic_field_length(ctx->cur_basic.field_type);
	bo = bt_ctf_field_type_get_byte_order(ctx->cur_basic.field_type);

	if (signd) {
		int64_t v;

		if (bo == BT_CTF_BYTE_ORDER_BIG_ENDIAN ||
				bo == BT_CTF_BYTE_ORDER_NETWORK) {
			bt_bitfield_read_be(buf, uint8_t, at, field_length,
				&v);
		} else if (bo == BT_CTF_BYTE_ORDER_LITTLE_ENDIAN) {
			bt_bitfield_read_le(buf, uint8_t, at, field_length,
				&v);
		} else {
			ret = -1;
			goto end;
		}

		ret = bt_ctf_field_signed_integer_set_value(
			ctx->cur_basic.field, v);
	} else {
		uint64_t v;

		if (bo == BT_CTF_BYTE_ORDER_BIG_ENDIAN ||
				bo == BT_CTF_BYTE_ORDER_NETWORK) {
			bt_bitfield_read_be(buf, uint8_t, at, field_length,
				&v);
		} else if (bo == BT_CTF_BYTE_ORDER_LITTLE_ENDIAN) {
			bt_bitfield_read_le(buf, uint8_t, at, field_length,
				&v);
		} else {
			ret = -1;
			goto end;
		}

		ret = bt_ctf_field_unsigned_integer_set_value(
			ctx->cur_basic.field, v);
	}

end:
	return ret;
}

static inline
enum state_machine_action handle_fds_decode_integer_field_continue(
	struct bt_ctf_stream_reader_ctx *ctx,
	enum bt_ctf_stream_reader_status *status)
{
	size_t available;
	int64_t field_length;
	int64_t needed_bits;
	enum state_machine_action action = SMA_CONTINUE;

	field_length = get_basic_field_length(ctx->cur_basic.field_type);
	*status = ensure_available_bits(ctx);

	if (*status != BT_CTF_STREAM_READER_STATUS_OK) {
		if (*status == BT_CTF_STREAM_READER_STATUS_ERROR) {
			action = SMA_ERROR;
		}

		goto end;
	}

	available = available_bits(ctx);
	needed_bits = field_length - ctx->stitch.length;

	if (needed_bits <= available) {
		int ret;

		/* we have all the bits; append to stitch, then decode/set */
		stitch_append_from_buf(ctx, needed_bits);
		ret = decode_and_set_cur_basic_integer_field(ctx,
			ctx->stitch.buf, ctx->stitch.offset);

		if (ret) {
			action = SMA_ERROR;
			goto end;
		}

		stack_top(ctx->stack)->index++;
		ctx->state.field = FDS_INIT;
		goto end;
	}

	/* we are here; it means we don't have enough data to decode this */
	stitch_append_from_remaining_buf(ctx);

end:
	return action;
}

static inline
enum state_machine_action handle_fds_decode_integer_field_begin(
	struct bt_ctf_stream_reader_ctx *ctx,
	enum bt_ctf_stream_reader_status *status)
{
	size_t available;
	int64_t field_length;
	enum state_machine_action action = SMA_CONTINUE;

	field_length = get_basic_field_length(ctx->cur_basic.field_type);
	*status = ensure_available_bits(ctx);

	if (*status != BT_CTF_STREAM_READER_STATUS_OK) {
		if (*status == BT_CTF_STREAM_READER_STATUS_ERROR) {
			action = SMA_ERROR;
		}

		goto end;
	}

	available = available_bits(ctx);

	if (field_length <= available) {
		/* we have all the bits; decode and set now */
		int ret = decode_and_set_cur_basic_integer_field(ctx,
			ctx->buf.addr, ctx->buf.at);

		if (ret) {
			action = SMA_ERROR;
			goto end;
		}

		stack_top(ctx->stack)->index++;
		consume_bits(ctx, field_length);
		ctx->state.field = FDS_INIT;
		goto end;
	}

	/* we are here; it means we don't have enough data to decode this */
	stitch_set_from_remaining_buf(ctx);
	ctx->state.field = FDS_DECODE_INTEGER_FIELD_CONTINUE;

end:
	return action;
}

static inline
enum state_machine_action handle_fds_decode_basic_field(
	struct bt_ctf_stream_reader_ctx *ctx,
	enum bt_ctf_stream_reader_status *status)
{
	switch (bt_ctf_field_type_get_type_id(ctx->cur_basic.field_type)) {
	case CTF_TYPE_INTEGER:
		ctx->state.field = FDS_DECODE_INTEGER_FIELD_BEGIN;
		break;

	case CTF_TYPE_FLOAT:
		ctx->state.field = FDS_DECODE_FLOAT_FIELD_BEGIN;
		break;

	case CTF_TYPE_ENUM:
		ctx->state.field = FDS_DECODE_ENUM_FIELD_BEGIN;
		break;

	case CTF_TYPE_STRING:
		ctx->state.field = FDS_DECODE_STRING_FIELD_BEGIN;
		break;

	default:
		assert(false);
	}

	return SMA_CONTINUE;
}

static inline
enum state_machine_action handle_fd_state(struct bt_ctf_stream_reader_ctx *ctx,
	enum bt_ctf_stream_reader_status *status)
{
	enum state_machine_action action;

	switch (ctx->state.field) {
	case FDS_INIT:
		action = handle_fds_init(ctx, status);
		break;

	case FDS_SKIP_PADDING:
		action = handle_fds_skip_padding(ctx, status);
		break;

	case FDS_DECODE_BASIC_FIELD:
		action = handle_fds_decode_basic_field(ctx, status);
		break;

	case FDS_DECODE_INTEGER_FIELD_BEGIN:
		action = handle_fds_decode_integer_field_begin(ctx, status);
		break;

	case FDS_DECODE_INTEGER_FIELD_CONTINUE:
		action = handle_fds_decode_integer_field_continue(ctx, status);
		break;
	}

	return action;
}

static inline
struct bt_ctf_field_type *get_ctx_entity_field_type(
	struct bt_ctf_stream_reader_ctx *ctx)
{
	struct bt_ctf_field_type *field_type = NULL;

	switch (ctx->state.entity) {
	case ENTITY_TRACE_PACKET_HEADER:
		field_type =
			bt_ctf_trace_get_packet_header_type(ctx->meta.trace);
		break;

	case ENTITY_STREAM_PACKET_CONTEXT:
		field_type =
			bt_ctf_stream_class_get_packet_context_type(
				ctx->meta.stream_class);
		break;

	case ENTITY_STREAM_EVENT_HEADER:
		field_type = bt_ctf_stream_class_get_event_header_type(
			ctx->meta.stream_class);
		break;

	case ENTITY_STREAM_EVENT_CONTEXT:
		field_type = bt_ctf_stream_class_get_event_context_type(
			ctx->meta.stream_class);
		break;

	case ENTITY_EVENT_CONTEXT:
		field_type = bt_ctf_event_class_get_context_type(
			ctx->meta.event_class);
		break;

	case ENTITY_EVENT_PAYLOAD:
		field_type = bt_ctf_event_class_get_payload_type(
			ctx->meta.event_class);
		break;
	}

	return field_type;
}

static inline
void move_last_decoded_entity_to_entity(struct bt_ctf_stream_reader_ctx *ctx)
{
	struct bt_ctf_field **dest_entity;

	assert(ctx->last_decoded_entity);

	switch (ctx->state.entity) {
	case ENTITY_TRACE_PACKET_HEADER:
		dest_entity = &ctx->entities.trace_packet_header;
		ctx->state.entity = ENTITY_STREAM_PACKET_CONTEXT;
		break;

	case ENTITY_STREAM_PACKET_CONTEXT:
		dest_entity = &ctx->entities.stream_packet_context;
		ctx->state.entity = ENTITY_STREAM_EVENT_HEADER;
		break;

	case ENTITY_STREAM_EVENT_HEADER:
		dest_entity = &ctx->entities.stream_event_header;
		ctx->state.entity = ENTITY_STREAM_EVENT_CONTEXT;
		break;

	case ENTITY_STREAM_EVENT_CONTEXT:
		dest_entity = &ctx->entities.stream_event_context;
		ctx->state.entity = ENTITY_EVENT_CONTEXT;
		break;

	case ENTITY_EVENT_CONTEXT:
		dest_entity = &ctx->entities.event_context;
		ctx->state.entity = ENTITY_EVENT_PAYLOAD;
		break;

	case ENTITY_EVENT_PAYLOAD:
		dest_entity = &ctx->entities.event_payload;
		ctx->state.entity = ENTITY_STREAM_EVENT_HEADER;
		break;
	}

	bt_ctf_field_put(*dest_entity);
	*dest_entity = ctx->last_decoded_entity;
	ctx->last_decoded_entity = NULL;
}

static inline
enum bt_ctf_stream_reader_status handle_gd_state(
	struct bt_ctf_stream_reader_ctx *ctx)
{
	int ret;
	int64_t length;
	enum state_machine_action action;
	struct bt_ctf_field *field = NULL;
	enum bt_ctf_stream_reader_status status;
	struct bt_ctf_field_type *field_type = NULL;

	status = BT_CTF_STREAM_READER_STATUS_OK;

	switch (ctx->state.global) {
	case GDS_INIT:
		/* get the appropriate field type for the current entity */
		field_type = get_ctx_entity_field_type(ctx);

		if (!field_type) {
			status = BT_CTF_STREAM_READER_STATUS_ERROR;
			goto end;
		}

		/* create the root field of the current entity */
		field = bt_ctf_field_create(field_type);

		if (!field) {
			status = BT_CTF_STREAM_READER_STATUS_ERROR;
			goto end;
		}

		length = get_field_length(ctx, field_type);

		if (length < 0) {
			status = BT_CTF_STREAM_READER_STATUS_ERROR;
			goto end;
		}

		/* push root field on stack */
		assert(stack_size(ctx->stack) == 0);
		ret = stack_push(ctx->stack, field, field_type, length);
		bt_ctf_field_put(field);
		field = NULL;
		bt_ctf_field_type_put(field_type);
		field_type = NULL;

		if (ret) {
			status = BT_CTF_STREAM_READER_STATUS_ERROR;
			goto end;
		}

		assert(!ctx->last_decoded_entity);
		ctx->cur_packet_size = -1;
		ctx->cur_content_size = -1;
		ctx->state.field = FDS_SKIP_PADDING;
		ctx->state.global = GDS_DECODE;
		ctx->state.skip_base_padding = true;
		break;

	case GDS_DECODE:
		action = handle_fd_state(ctx, &status);

		switch (action) {
		case SMA_ERROR:
			status = BT_CTF_STREAM_READER_STATUS_ERROR;
			goto end;

		case SMA_DONE:
			ctx->state.global = GDS_INIT;

			/* move current field to appropriate member */
			move_last_decoded_entity_to_entity(ctx);
			break;

		case SMA_CONTINUE:
			break;
		}
		break;

	case GDS_DONE:
		assert(false);
		break;
	}

end:
	if (field_type) {
		bt_ctf_field_type_put(field_type);
	}

	if (field) {
		bt_ctf_field_put(field);
	}

	return status;
}

struct bt_ctf_stream_reader_ctx *bt_ctf_stream_reader_create(
	struct bt_ctf_trace *trace, size_t max_request_sz,
	struct bt_ctf_medium_ops ops, void *data)
{
	struct bt_ctf_stream_reader_ctx *ctx = NULL;

	ctx = g_new0(struct bt_ctf_stream_reader_ctx, 1);

	if (!ctx) {
		goto end;
	}

	ctx->meta.trace = trace;
	bt_ctf_trace_get(ctx->meta.trace);
	ctx->state.global = GDS_INIT;
	ctx->state.entity = ENTITY_TRACE_PACKET_HEADER;
	ctx->state.field = FDS_INIT;
	ctx->medium.ops = ops;

	if (max_request_sz == 0) {
		ctx->medium.max_request_sz = 4096;
	} else {
		ctx->medium.max_request_sz = max_request_sz;
	}

	ctx->medium.user_data = data;
	ctx->stack = stack_new();

	if (!ctx->stack) {
		bt_ctf_stream_reader_destroy(ctx);
		ctx = NULL;
		goto end;
	}

end:
	return ctx;
}

void bt_ctf_stream_reader_destroy(struct bt_ctf_stream_reader_ctx *ctx)
{
	bt_ctf_field_put(ctx->cur_basic.field);
	bt_ctf_field_type_put(ctx->cur_basic.field_type);
	bt_ctf_trace_put(ctx->meta.trace);
	bt_ctf_stream_class_put(ctx->meta.stream_class);
	bt_ctf_event_class_put(ctx->meta.event_class);
	bt_ctf_field_put(ctx->entities.trace_packet_header);
	bt_ctf_field_put(ctx->entities.stream_packet_context);
	bt_ctf_field_put(ctx->entities.stream_event_header);
	bt_ctf_field_put(ctx->entities.stream_event_context);
	bt_ctf_field_put(ctx->entities.event_context);
	bt_ctf_field_put(ctx->entities.event_payload);
	assert(!ctx->last_decoded_entity);
	stack_destroy(ctx->stack);
	g_free(ctx);
}

static
enum bt_ctf_stream_reader_status decode_packet_header(
	struct bt_ctf_stream_reader_ctx *ctx)
{
	enum bt_ctf_stream_reader_status status =
		BT_CTF_STREAM_READER_STATUS_OK;

	/* continue decoding packet header if needed */
	while (!ctx->entities.trace_packet_header) {
		status = handle_gd_state(ctx);

		if (status == BT_CTF_STREAM_READER_STATUS_AGAIN ||
				status == BT_CTF_STREAM_READER_STATUS_ERROR ||
				status == BT_CTF_STREAM_READER_STATUS_EOS) {
			goto end;
		}
	}

end:
	return status;
}

enum bt_ctf_stream_reader_status bt_ctf_stream_reader_get_header(
	struct bt_ctf_stream_reader_ctx *ctx,
	struct bt_ctf_field **packet_header)
{
	enum bt_ctf_stream_reader_status status;

	/* continue decoding packet header */
	status = decode_packet_header(ctx);

	if (ctx->entities.trace_packet_header) {
		*packet_header = ctx->entities.trace_packet_header;
		bt_ctf_field_get(*packet_header);
	}

	return status;
}

static
enum bt_ctf_stream_reader_status decode_packet_context(
	struct bt_ctf_stream_reader_ctx *ctx)
{
	enum bt_ctf_stream_reader_status status =
		BT_CTF_STREAM_READER_STATUS_OK;

	/* continue decoding packet context if needed */
	while (!ctx->entities.stream_packet_context) {
		status = handle_gd_state(ctx);

		if (status == BT_CTF_STREAM_READER_STATUS_AGAIN ||
				status == BT_CTF_STREAM_READER_STATUS_ERROR ||
				status == BT_CTF_STREAM_READER_STATUS_EOS) {
			goto end;
		}
	}

end:
	return status;
}

enum bt_ctf_stream_reader_status bt_ctf_stream_reader_get_context(
	struct bt_ctf_stream_reader_ctx *ctx,
	struct bt_ctf_field **packet_context)
{
	enum bt_ctf_stream_reader_status status;

	/* continue decoding packet context */
	status = decode_packet_context(ctx);

	if (ctx->entities.stream_packet_context) {
		*packet_context = ctx->entities.stream_packet_context;
		bt_ctf_field_get(*packet_context);
	}

	return status;
}

enum bt_ctf_stream_reader_status bt_ctf_stream_reader_get_next_event(
	struct bt_ctf_stream_reader_ctx *ctx,
	struct bt_ctf_event **event)
{
	return BT_CTF_STREAM_READER_STATUS_NOENT;
}
