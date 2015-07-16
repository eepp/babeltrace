/*
 * Babeltrace - CTF binary type reader (BTR)
 *
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
#include <babeltrace/bitfield.h>
#include <babeltrace/ctf-ir/ctf-btr.h>
#include <babeltrace/ctf-ir/event-types.h>
#include <babeltrace/align.h>
#include <glib.h>

#define DIV8(_x)			((_x) >> 3)
#define BYTES_TO_BITS(_x)		((_x) * 8)
#define BITS_TO_BYTES_FLOOR(_x)		DIV8(_x)
#define BITS_TO_BYTES_CEIL(_x)		DIV8((_x) + 7)
#define IN_BYTE_OFFSET(_at)		((_at) & 7)

/* a visit stack entry */
struct stack_entry {
	/*
	 * Current type of base field, one of:
	 *
	 *   * structure
	 *   * array
	 *   * sequence
	 *   * variant
	 *
	 * Owned by this.
	 */
	struct bt_ctf_field_type *base_type;

	/* length of base field (always 1 for variant types) */
	int64_t base_len;

	/* index of next field to read */
	int64_t index;
};

/* visit stack */
struct stack {
	/* entries (struct stack_entry *) (top is last element) */
	GPtrArray *entries;
};

enum btr_state {
	BTR_STATE_NEXT_FIELD,
	BTR_STATE_ALIGN_BASIC,
	BTR_STATE_ALIGN_COMPOUND,
	BTR_STATE_READ_BASIC_BEGIN,
	BTR_STATE_READ_BASIC_CONTINUE,
	BTR_STATE_DONE,
};

/* binary type reader, where everything lives and dies */
struct bt_ctf_btr {
	/* visit stack */
	struct stack *stack;

	/* current basic field type */
	struct bt_ctf_field_type *cur_basic_field_type;

	/* current state */
	enum btr_state state;

	/*
	 * Last basic field type's byte order.
	 *
	 * This is used to detect errors since two contiguous basic
	 * types for which the common boundary is not the boundary of
	 * a byte cannot have different byte orders.
	 *
	 * This is set to BT_CTF_BYTE_ORDER_UNKNOWN on reset and when
	 * the last basic field type was a string type.
	 */
	enum bt_ctf_byte_order last_bo;

	/* current byte order (copied to last_bo after a successful read) */
	enum bt_ctf_byte_order cur_bo;

	/* stitch buffer infos */
	struct {
		/* stitch buffer */
		uint8_t buf[16];

		/* offset within stitch buffer of first bit */
		size_t offset;

		/* length (bits) of data in stitch buffer from offset */
		size_t at;
	} stitch;

	/* user buffer infos */
	struct {
		/* address */
		const uint8_t *addr;

		/* offset of data from address (bits) */
		size_t offset;

		/* current position from offset (bits) */
		size_t at;

		/* offset of offset within whole packet (bits) */
		size_t packet_offset;

		/* data size in buffer (bits) */
		size_t sz;

		/* buffer size (bytes) */
		size_t buf_sz;
	} buf;

	/* user stuff */
	struct {
		/* callback functions */
		struct bt_ctf_btr_cbs cbs;

		/* private data */
		void *data;
	} user;
};

static
void stack_entry_free_func(gpointer data)
{
	struct stack_entry *entry = data;

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
	if (!stack) {
		return;
	}

	g_ptr_array_free(stack->entries, TRUE);
	g_free(stack);
}

static inline
int64_t get_compound_field_type_length(struct bt_ctf_btr *btr,
	struct bt_ctf_field_type *field_type)
{
	int64_t length;

	switch (bt_ctf_field_type_get_type_id(field_type)) {
	case CTF_TYPE_STRUCT:
		length = (int64_t) bt_ctf_field_type_structure_get_field_count(
			field_type);
		break;

	case CTF_TYPE_VARIANT:
		/* variant field types always "contain" a single type */
		length = 1;
		break;

	case CTF_TYPE_ARRAY:
		length = bt_ctf_field_type_array_get_length(field_type);
		break;

	case CTF_TYPE_SEQUENCE:
		length = btr->user.cbs.query.get_sequence_length(field_type,
			btr->user.data);
		break;

	default:
		length = BT_CTF_BTR_STATUS_ERROR;
	}

	return length;
}

static
int stack_push(struct stack *stack, struct bt_ctf_field_type *base_type,
	size_t base_len)
{
	int ret = 0;
	struct stack_entry *entry;

	assert(stack);
	assert(base_type);

	entry = g_new0(struct stack_entry, 1);

	if (!entry) {
		ret = BT_CTF_BTR_STATUS_ERROR;
		goto end;
	}

	entry->base_type = base_type;
	bt_ctf_field_type_get(entry->base_type);
	entry->base_len = base_len;
	g_ptr_array_add(stack->entries, entry);

end:
	return ret;
}

static
int stack_push_with_len(struct bt_ctf_btr *btr,
	struct bt_ctf_field_type *base_type)
{
	int ret = 0;
	int64_t base_len = get_compound_field_type_length(btr, base_type);

	if (base_len < 0) {
		ret = BT_CTF_BTR_STATUS_ERROR;
		goto end;
	}

	ret = stack_push(btr->stack, base_type, (size_t) base_len);

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
struct stack_entry *stack_top(struct stack *stack)
{
	assert(stack);
	assert(stack_size(stack));

	return g_ptr_array_index(stack->entries, stack->entries->len - 1);
}

static inline
size_t available_bits(struct bt_ctf_btr *btr)
{
	return btr->buf.sz - btr->buf.at;
}

static inline
void consume_bits(struct bt_ctf_btr *btr, size_t incr)
{
	btr->buf.at += incr;
}

static inline
bool has_enough_bits(struct bt_ctf_btr *btr, size_t len)
{
	return available_bits(btr) >= len;
}

static inline
bool at_least_one_bit_left(struct bt_ctf_btr *btr)
{
	return has_enough_bits(btr, 1);
}

static inline
size_t packet_at(struct bt_ctf_btr *btr)
{
	return btr->buf.packet_offset + btr->buf.at;
}

static inline
size_t buf_at_from_addr(struct bt_ctf_btr *btr)
{
	/*
	 * Considering this:
	 *
	 *     ====== offset ===== (17)
	 *
	 *     xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
	 *     ^
	 *     addr (0)           ==== at ==== (12)
	 *
	 * We want this:
	 *
	 *     =============================== (29)
	 */
	return btr->buf.offset + btr->buf.at;
}

static inline
int get_basic_field_type_size(struct bt_ctf_field_type *field_type)
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
			size = BT_CTF_BTR_STATUS_ERROR;
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
			size = BT_CTF_BTR_STATUS_ERROR;
			goto end;
		}

		size = get_basic_field_type_size(int_type);
		bt_ctf_field_type_put(int_type);
		break;
	}

	default:
		size = BT_CTF_BTR_STATUS_ERROR;
		break;
	}

end:
	return size;
}

static
void stitch_reset(struct bt_ctf_btr *btr)
{
	btr->stitch.offset = 0;
	btr->stitch.at = 0;
}

static inline
size_t stitch_at_from_addr(struct bt_ctf_btr *btr)
{
	return btr->stitch.offset + btr->stitch.at;
}

static
void stitch_append_from_buf(struct bt_ctf_btr *btr, size_t sz)
{
	size_t stitch_byte_at;
	size_t buf_byte_at;
	size_t nb_bytes;;

	if (sz == 0) {
		return;
	}

	stitch_byte_at =
		BITS_TO_BYTES_FLOOR(stitch_at_from_addr(btr));
	buf_byte_at = BITS_TO_BYTES_FLOOR(buf_at_from_addr(btr));
	nb_bytes = BITS_TO_BYTES_CEIL(sz);
	assert(nb_bytes > 0);
	memcpy(&btr->stitch.buf[stitch_byte_at], &btr->buf.addr[buf_byte_at],
		nb_bytes);
	btr->stitch.at += sz;
	consume_bits(btr, sz);
}

static
void stitch_append_from_remaining_buf(struct bt_ctf_btr *btr)
{
	stitch_append_from_buf(btr, available_bits(btr));
}

static
void stitch_set_from_remaining_buf(struct bt_ctf_btr *btr)
{
	stitch_reset(btr);
	btr->stitch.offset = IN_BYTE_OFFSET(buf_at_from_addr(btr));
	stitch_append_from_remaining_buf(btr);
}

static inline
enum bt_ctf_btr_status read_unsigned_bitfield(const uint8_t *buf, size_t at,
	int64_t field_size, enum bt_ctf_byte_order bo, uint64_t *v)
{
	enum bt_ctf_btr_status status = BT_CTF_BTR_STATUS_OK;

	switch (bo) {
	case BT_CTF_BYTE_ORDER_BIG_ENDIAN:
	case BT_CTF_BYTE_ORDER_NETWORK:
		bt_bitfield_read_be(buf, uint8_t, at, field_size, v);
		break;

	case BT_CTF_BYTE_ORDER_LITTLE_ENDIAN:
		bt_bitfield_read_le(buf, uint8_t, at, field_size, v);
		break;

	default:
		status = BT_CTF_BTR_STATUS_ERROR;
	}

	return status;
}

static inline
enum bt_ctf_btr_status read_signed_bitfield(const uint8_t *buf, size_t at,
	int64_t field_size, enum bt_ctf_byte_order bo, int64_t *v)
{
	enum bt_ctf_btr_status status = BT_CTF_BTR_STATUS_OK;

	switch (bo) {
	case BT_CTF_BYTE_ORDER_BIG_ENDIAN:
	case BT_CTF_BYTE_ORDER_NETWORK:
		bt_bitfield_read_be(buf, uint8_t, at, field_size, v);
		break;

	case BT_CTF_BYTE_ORDER_LITTLE_ENDIAN:
		bt_bitfield_read_le(buf, uint8_t, at, field_size, v);
		break;

	default:
		status = BT_CTF_BTR_STATUS_ERROR;
	}

	return status;
}

typedef enum bt_ctf_btr_status (* read_basic_and_call_cb_t)(struct bt_ctf_btr *,
	const uint8_t *, size_t);

static inline
enum bt_ctf_btr_status validate_contiguous_bo(struct bt_ctf_btr *btr,
	enum bt_ctf_byte_order next_bo)
{
	enum bt_ctf_btr_status status = BT_CTF_BTR_STATUS_OK;

	/* always valid when at a byte boundary */
	if (packet_at(btr) % 8 == 0) {
		goto end;
	}

	/* always valid if last byte order is unknown */
	if (btr->last_bo == BT_CTF_BYTE_ORDER_UNKNOWN) {
		goto end;
	}

	/* always valid if next byte order is unknown */
	if (next_bo == BT_CTF_BYTE_ORDER_UNKNOWN) {
		goto end;
	}

	/* make sure last byte order is compatible with the next byte order */
	switch (btr->last_bo) {
	case BT_CTF_BYTE_ORDER_BIG_ENDIAN:
	case BT_CTF_BYTE_ORDER_NETWORK:
		if (next_bo != BT_CTF_BYTE_ORDER_BIG_ENDIAN &&
				next_bo != BT_CTF_BYTE_ORDER_NETWORK) {
			status = BT_CTF_BTR_STATUS_ERROR;
		}
		break;

	case BT_CTF_BYTE_ORDER_LITTLE_ENDIAN:
		if (next_bo != BT_CTF_BYTE_ORDER_LITTLE_ENDIAN) {
			status = BT_CTF_BTR_STATUS_ERROR;
		}
		break;

	default:
		status = BT_CTF_BTR_STATUS_ERROR;
	}

end:
	return status;
}

static
enum bt_ctf_btr_status read_basic_float_and_call_cb(struct bt_ctf_btr *btr,
	const uint8_t *buf, size_t at)
{
	int ret;
	double dblval;
	int64_t field_size;
	enum bt_ctf_byte_order bo;
	enum bt_ctf_btr_status status = BT_CTF_BTR_STATUS_OK;

	field_size = get_basic_field_type_size(btr->cur_basic_field_type);
	bo = bt_ctf_field_type_get_byte_order(btr->cur_basic_field_type);
	btr->cur_bo = bo;

	switch (field_size) {
	case 32:
	{
		uint64_t v;
		union {
			uint32_t u;
			float f;
		} f32;

		ret = bt_ctf_field_type_floating_point_get_mantissa_digits(
			btr->cur_basic_field_type);
		assert(ret == 24);
		ret = bt_ctf_field_type_floating_point_get_exponent_digits(
			btr->cur_basic_field_type);
		assert(ret == 8);
		status = read_unsigned_bitfield(buf, at, field_size, bo, &v);

		if (status != BT_CTF_BTR_STATUS_OK) {
			goto end;
		}

		f32.u = (uint32_t) v;
		dblval = (double) f32.f;
		break;
	}

	case 64:
	{
		union {
			uint64_t u;
			double d;
		} f64;

		ret = bt_ctf_field_type_floating_point_get_mantissa_digits(
			btr->cur_basic_field_type);
		assert(ret == 53);
		ret = bt_ctf_field_type_floating_point_get_exponent_digits(
			btr->cur_basic_field_type);
		assert(ret == 11);
		status = read_unsigned_bitfield(buf, at, field_size, bo,
			&f64.u);

		if (status != BT_CTF_BTR_STATUS_OK) {
			goto end;
		}

		dblval = f64.d;
		break;
	}

	default:
		/* only 32-bit and 64-bit fields are supported currently */
		status = BT_CTF_BTR_STATUS_ERROR;
		goto end;
	}

	if (btr->user.cbs.types.floating_point) {
		status = btr->user.cbs.types.floating_point(dblval,
			btr->cur_basic_field_type, btr->user.data);
	}

end:
	return status;
}

static inline
enum bt_ctf_btr_status read_basic_int_and_call(struct bt_ctf_btr *btr,
	const uint8_t *buf, size_t at, struct bt_ctf_field_type *int_type,
	struct bt_ctf_field_type *orig_type)
{
	int signd;
	int64_t field_size;
	enum bt_ctf_byte_order bo;
	enum bt_ctf_btr_status status = BT_CTF_BTR_STATUS_OK;

	signd = bt_ctf_field_type_integer_get_signed(int_type);
	field_size = get_basic_field_type_size(int_type);

	if (field_size < 1) {
		status = BT_CTF_BTR_STATUS_ERROR;
		goto end;
	}

	bo = bt_ctf_field_type_get_byte_order(int_type);

	/*
	 * Update current byte order now because we could be reading
	 * the integer value of an enumeration type, and thus we know
	 * here the actual supporting integer type's byte order.
	 */
	btr->cur_bo = bo;

	if (signd) {
		int64_t v;

		status = read_signed_bitfield(buf, at, field_size, bo, &v);

		if (status != BT_CTF_BTR_STATUS_OK) {
			goto end;
		}

		if (btr->user.cbs.types.signed_int) {
			status = btr->user.cbs.types.signed_int(v,
				btr->cur_basic_field_type, btr->user.data);
		}
	} else {
		uint64_t v;

		status = read_unsigned_bitfield(buf, at, field_size, bo, &v);

		if (status != BT_CTF_BTR_STATUS_OK) {
			goto end;
		}

		if (btr->user.cbs.types.unsigned_int) {
			status = btr->user.cbs.types.unsigned_int(v,
				btr->cur_basic_field_type, btr->user.data);
		}
	}

end:
	return status;
}

static
enum bt_ctf_btr_status read_basic_int_and_call_cb(struct bt_ctf_btr *btr,
	const uint8_t *buf, size_t at)
{
	return read_basic_int_and_call(btr, buf, at, btr->cur_basic_field_type,
		btr->cur_basic_field_type);
}

static
enum bt_ctf_btr_status read_basic_enum_and_call_cb(struct bt_ctf_btr *btr,
	const uint8_t *buf, size_t at)
{
	struct bt_ctf_field_type *int_field_type;
	enum bt_ctf_btr_status status = BT_CTF_BTR_STATUS_OK;

	int_field_type = bt_ctf_field_type_enumeration_get_container_type(
		btr->cur_basic_field_type);

	if (!int_field_type) {
		status = BT_CTF_BTR_STATUS_ERROR;
		goto end;
	}

	status = read_basic_int_and_call(btr, buf, at,
		int_field_type, btr->cur_basic_field_type);

end:
	bt_ctf_field_type_put(int_field_type);

	return status;
}

static inline
enum bt_ctf_btr_status read_basic_type_and_call_continue(struct bt_ctf_btr *btr,
	read_basic_and_call_cb_t read_basic_and_call_cb)
{
	size_t available;
	int64_t field_size;
	int64_t needed_bits;
	enum bt_ctf_btr_status status = BT_CTF_BTR_STATUS_OK;

	if (!at_least_one_bit_left(btr)) {
		status = BT_CTF_BTR_STATUS_EOF;
		goto end;
	}

	field_size = get_basic_field_type_size(btr->cur_basic_field_type);

	if (field_size < 1) {
		status = BT_CTF_BTR_STATUS_ERROR;
		goto end;
	}

	available = available_bits(btr);
	needed_bits = field_size - btr->stitch.at;

	if (needed_bits <= available) {
		/* we have all the bits; append to stitch, then decode */
		stitch_append_from_buf(btr, needed_bits);
		status = read_basic_and_call_cb(btr, btr->stitch.buf,
			btr->stitch.offset);

		if (status != BT_CTF_BTR_STATUS_OK) {
			goto end;
		}

		if (stack_empty(btr->stack)) {
			/* root is a basic type */
			btr->state = BTR_STATE_DONE;
		} else {
			/* go to next field */
			stack_top(btr->stack)->index++;
			btr->state = BTR_STATE_NEXT_FIELD;

			/*
			 * Update last byte order. This will be set to
			 * BT_CTF_BYTE_ORDER_UNKNOWN when the current
			 * type is a string type, but
			 * validate_contiguous_bo() is always valid
			 * when comparing with BT_CTF_BYTE_ORDER_UNKNOWN.
			 */
			btr->last_bo = btr->cur_bo;
		}
		goto end;
	}

	/* we are here; it means we don't have enough data to decode this */
	stitch_append_from_remaining_buf(btr);
	status = BT_CTF_BTR_STATUS_EOF;

end:
	return status;
}

static inline
enum bt_ctf_btr_status read_basic_type_and_call_begin(struct bt_ctf_btr *btr,
	read_basic_and_call_cb_t read_basic_and_call_cb)
{
	size_t available;
	int64_t field_size;
	enum bt_ctf_byte_order bo;
	enum bt_ctf_btr_status status = BT_CTF_BTR_STATUS_OK;

	if (!at_least_one_bit_left(btr)) {
		status = BT_CTF_BTR_STATUS_EOF;
		goto end;
	}

	field_size = get_basic_field_type_size(btr->cur_basic_field_type);

	if (field_size < 1) {
		status = BT_CTF_BTR_STATUS_ERROR;
		goto end;
	}

	bo = bt_ctf_field_type_get_byte_order(btr->cur_basic_field_type);
	status = validate_contiguous_bo(btr, bo);

	if (status != BT_CTF_BTR_STATUS_OK) {
		goto end;
	}

	available = available_bits(btr);

	if (field_size <= available) {
		/* we have all the bits; decode and set now */
		status = read_basic_and_call_cb(btr, btr->buf.addr,
			buf_at_from_addr(btr));

		if (status != BT_CTF_BTR_STATUS_OK) {
			goto end;
		}

		consume_bits(btr, field_size);

		if (stack_empty(btr->stack)) {
			/* root is a basic type */
			btr->state = BTR_STATE_DONE;
		} else {
			/* go to next field */
			stack_top(btr->stack)->index++;
			btr->state = BTR_STATE_NEXT_FIELD;

			/*
			 * Update last byte order. This will be set to
			 * BT_CTF_BYTE_ORDER_UNKNOWN when the current
			 * type is a string type, but
			 * validate_contiguous_bo() is always valid
			 * when comparing with BT_CTF_BYTE_ORDER_UNKNOWN.
			 */
			btr->last_bo = btr->cur_bo;
		}

		goto end;
	}

	/* we are here; it means we don't have enough data to decode this */
	stitch_set_from_remaining_buf(btr);
	btr->state = BTR_STATE_READ_BASIC_CONTINUE;
	status = BT_CTF_BTR_STATUS_EOF;

end:
	return status;
}

static inline
enum bt_ctf_btr_status read_basic_int_type_and_call_begin(
	struct bt_ctf_btr *btr)
{
	return read_basic_type_and_call_begin(btr, read_basic_int_and_call_cb);
}

static inline
enum bt_ctf_btr_status read_basic_int_type_and_call_continue(
	struct bt_ctf_btr *btr)
{
	return read_basic_type_and_call_continue(btr,
		read_basic_int_and_call_cb);
}

static inline
enum bt_ctf_btr_status read_basic_float_type_and_call_begin(
	struct bt_ctf_btr *btr)
{
	return read_basic_type_and_call_begin(btr,
		read_basic_float_and_call_cb);
}

static inline
enum bt_ctf_btr_status read_basic_float_type_and_call_continue(
	struct bt_ctf_btr *btr)
{
	return read_basic_type_and_call_continue(btr,
		read_basic_float_and_call_cb);
}

static inline
enum bt_ctf_btr_status read_basic_enum_type_and_call_begin(
	struct bt_ctf_btr *btr)
{
	return read_basic_type_and_call_begin(btr,
		read_basic_enum_and_call_cb);
}

static inline
enum bt_ctf_btr_status read_basic_enum_type_and_call_continue(
	struct bt_ctf_btr *btr)
{
	return read_basic_type_and_call_continue(btr,
		read_basic_enum_and_call_cb);
}

static inline
enum bt_ctf_btr_status read_basic_string_type_and_call(
	struct bt_ctf_btr *btr, bool begin)
{
	size_t buf_at_bytes;
	const uint8_t *result;
	size_t available_bytes;
	const uint8_t *first_chr;
	enum bt_ctf_btr_status status = BT_CTF_BTR_STATUS_OK;

	if (!at_least_one_bit_left(btr)) {
		status = BT_CTF_BTR_STATUS_EOF;
		goto end;
	}

	assert(buf_at_from_addr(btr) % 8 == 0);
	available_bytes = BITS_TO_BYTES_FLOOR(available_bits(btr));
	buf_at_bytes = BITS_TO_BYTES_FLOOR(buf_at_from_addr(btr));
	first_chr = &btr->buf.addr[buf_at_bytes];
	result = memchr(first_chr, '\0', available_bytes);

	if (begin && btr->user.cbs.types.string_begin) {
		status = btr->user.cbs.types.string_begin(
			btr->cur_basic_field_type, btr->user.data);

		if (status != BT_CTF_BTR_STATUS_OK) {
			goto end;
		}
	}

	if (!result) {
		/* no null character yet */
		if (btr->user.cbs.types.string) {
			status = btr->user.cbs.types.string(
				(const char *) first_chr,
				available_bytes, btr->cur_basic_field_type,
				btr->user.data);

			if (status != BT_CTF_BTR_STATUS_OK) {
				goto end;
			}
		}

		consume_bits(btr, BYTES_TO_BITS(available_bytes));
		btr->state = BTR_STATE_READ_BASIC_CONTINUE;
		status = BT_CTF_BTR_STATUS_EOF;
	} else {
		/* found the null character */
		size_t result_len = (size_t) (result - first_chr);

		if (btr->user.cbs.types.string && result_len) {
			status = btr->user.cbs.types.string(
				(const char *) first_chr,
				result_len, btr->cur_basic_field_type,
				btr->user.data);

			if (status != BT_CTF_BTR_STATUS_OK) {
				goto end;
			}
		}

		if (btr->user.cbs.types.string_end) {
			status = btr->user.cbs.types.string_end(
				btr->cur_basic_field_type, btr->user.data);

			if (status != BT_CTF_BTR_STATUS_OK) {
				goto end;
			}
		}

		consume_bits(btr, BYTES_TO_BITS(result_len + 1));

		if (stack_empty(btr->stack)) {
			/* root is a basic type */
			btr->state = BTR_STATE_DONE;
		} else {
			/* go to next field */
			stack_top(btr->stack)->index++;
			btr->state = BTR_STATE_NEXT_FIELD;
		}
	}

end:
	return status;
}

static inline
enum bt_ctf_btr_status read_basic_begin_state(struct bt_ctf_btr *btr)
{
	enum bt_ctf_btr_status status;

	assert(btr->cur_basic_field_type);

	switch (bt_ctf_field_type_get_type_id(btr->cur_basic_field_type)) {
	case CTF_TYPE_INTEGER:
		status = read_basic_int_type_and_call_begin(btr);
		break;

	case CTF_TYPE_FLOAT:
		status = read_basic_float_type_and_call_begin(btr);
		break;

	case CTF_TYPE_ENUM:
		status = read_basic_enum_type_and_call_begin(btr);
		break;

	case CTF_TYPE_STRING:
		status = read_basic_string_type_and_call(btr, true);
		break;

	default:
		assert(false);
	}

	return status;
}

static inline
enum bt_ctf_btr_status read_basic_continue_state(struct bt_ctf_btr *btr)
{
	enum bt_ctf_btr_status status;

	assert(btr->cur_basic_field_type);

	switch (bt_ctf_field_type_get_type_id(btr->cur_basic_field_type)) {
	case CTF_TYPE_INTEGER:
		status = read_basic_int_type_and_call_continue(btr);
		break;

	case CTF_TYPE_FLOAT:
		status = read_basic_float_type_and_call_continue(btr);
		break;

	case CTF_TYPE_ENUM:
		status = read_basic_enum_type_and_call_continue(btr);
		break;

	case CTF_TYPE_STRING:
		status = read_basic_string_type_and_call(btr, false);
		break;

	default:
		assert(false);
	}

	return status;
}

static inline
enum bt_ctf_btr_status align_type_state(struct bt_ctf_btr *btr,
	struct bt_ctf_field_type *field_type, enum btr_state next_state)
{
	int field_alignment;
	size_t skip_bits;
	size_t aligned_packet_at;
	enum bt_ctf_btr_status status = BT_CTF_BTR_STATUS_OK;

	/* get field's alignment */
	field_alignment = bt_ctf_field_type_get_alignment(field_type);

	if (field_alignment < 0) {
		status = BT_CTF_BTR_STATUS_ERROR;
		goto end;
	}

	if (field_alignment == 0) {
		field_alignment = 1;
	}

	/* compute how many bits we need to skip */
	aligned_packet_at = ALIGN(packet_at(btr), field_alignment);
	skip_bits = aligned_packet_at - packet_at(btr);

	/* nothing to skip? done */
	if (skip_bits == 0) {
		btr->state = next_state;
		goto end;
	}

	/* make sure there's at least one bit left */
	if (!at_least_one_bit_left(btr)) {
		status = BT_CTF_BTR_STATUS_EOF;
		goto end;
	}

	/* consume as many bits as possible in what's left */
	consume_bits(btr, MIN(available_bits(btr), skip_bits));

	/* are we done now? */
	aligned_packet_at = ALIGN(packet_at(btr), field_alignment);
	skip_bits = aligned_packet_at - packet_at(btr);

	if (skip_bits == 0) {
		btr->state = next_state;
		goto end;
	} else {
		status = BT_CTF_BTR_STATUS_EOF;
	}

end:
	return status;
}

static inline
bool is_compound_type(struct bt_ctf_field_type *field_type)
{
	enum ctf_type_id id = bt_ctf_field_type_get_type_id(field_type);

	return id == CTF_TYPE_STRUCT || id == CTF_TYPE_ARRAY ||
		id == CTF_TYPE_SEQUENCE || id == CTF_TYPE_VARIANT;
}

static inline
enum bt_ctf_btr_status next_field_state(struct bt_ctf_btr *btr)
{
	int ret;
	struct stack_entry *top;
	struct bt_ctf_field_type *next_field_type = NULL;
	enum bt_ctf_btr_status status = BT_CTF_BTR_STATUS_OK;

	if (stack_empty(btr->stack)) {
		goto end;
	}

	top = stack_top(btr->stack);

	/* are we done with this base type? */
	if (top->index == top->base_len) {
		if (btr->user.cbs.types.compound_end) {
			status = btr->user.cbs.types.compound_end(
				top->base_type, btr->user.data);

			if (status != BT_CTF_BTR_STATUS_OK) {
				goto end;
			}
		}

		stack_pop(btr->stack);

		/* are we done with the root type? */
		if (stack_empty(btr->stack)) {
			btr->state = BTR_STATE_DONE;
		}

		goto end;
	}

	/* get next field's type */
	switch (bt_ctf_field_type_get_type_id(top->base_type)) {
	case CTF_TYPE_STRUCT:
		ret = bt_ctf_field_type_structure_get_field(
			top->base_type, NULL, &next_field_type,
			top->index);

		if (ret) {
			status = BT_CTF_BTR_STATUS_ERROR;
			goto end;
		}
		break;

	case CTF_TYPE_ARRAY:
		next_field_type =
			bt_ctf_field_type_array_get_element_type(
				top->base_type);
		break;

	case CTF_TYPE_SEQUENCE:
		next_field_type =
			bt_ctf_field_type_sequence_get_element_type(
				top->base_type);
		break;

	case CTF_TYPE_VARIANT:
		next_field_type =
			btr->user.cbs.query.get_variant_type(
				top->base_type, btr->user.data);
		break;

	default:
		break;
	}

	if (!next_field_type) {
		status = BT_CTF_BTR_STATUS_ERROR;
		goto end;
	}

	if (is_compound_type(next_field_type)) {
		if (btr->user.cbs.types.compound_begin) {
			status = btr->user.cbs.types.compound_begin(
				next_field_type, btr->user.data);

			if (status != BT_CTF_BTR_STATUS_OK) {
				goto end;
			}
		}

		ret = stack_push_with_len(btr, next_field_type);

		if (ret) {
			status = BT_CTF_BTR_STATUS_ERROR;
			goto end;
		}

		/* update previous top's index */
		top->index++;

		/* next state: align a compound type */
		btr->state = BTR_STATE_ALIGN_COMPOUND;
	} else {
		/* replace current basic field type */
		bt_ctf_field_type_put(btr->cur_basic_field_type);
		btr->cur_basic_field_type = next_field_type;
		next_field_type = NULL;

		/* next state: align a basic type */
		btr->state = BTR_STATE_ALIGN_BASIC;
	}

end:
	bt_ctf_field_type_put(next_field_type);

	return status;
}

static inline
enum bt_ctf_btr_status handle_state(struct bt_ctf_btr *btr)
{
	enum bt_ctf_btr_status status = BT_CTF_BTR_STATUS_OK;

	switch (btr->state) {
	case BTR_STATE_NEXT_FIELD:
		status = next_field_state(btr);
		break;

	case BTR_STATE_ALIGN_BASIC:
		status = align_type_state(btr, btr->cur_basic_field_type,
			BTR_STATE_READ_BASIC_BEGIN);
		break;

	case BTR_STATE_ALIGN_COMPOUND:
		status = align_type_state(btr, stack_top(btr->stack)->base_type,
			BTR_STATE_NEXT_FIELD);
		break;

	case BTR_STATE_READ_BASIC_BEGIN:
		status = read_basic_begin_state(btr);
		break;

	case BTR_STATE_READ_BASIC_CONTINUE:
		status = read_basic_continue_state(btr);
		break;

	case BTR_STATE_DONE:
		break;
	}

	return status;
}

struct bt_ctf_btr *bt_ctf_btr_create(struct bt_ctf_btr_cbs cbs, void *data)
{
	struct bt_ctf_btr *btr;

	btr = g_new0(struct bt_ctf_btr, 1);

	if (!btr) {
		goto end;
	}

	btr->stack = stack_new();

	if (!btr->stack) {
		bt_ctf_btr_destroy(btr);
		btr = NULL;
		goto end;
	}

	btr->state = BTR_STATE_NEXT_FIELD;
	btr->user.cbs = cbs;
	btr->user.data = data;

end:
	return btr;
}

void bt_ctf_btr_destroy(struct bt_ctf_btr *btr)
{
	stack_destroy(btr->stack);
	bt_ctf_field_type_put(btr->cur_basic_field_type);
	g_free(btr);
}

static
void reset(struct bt_ctf_btr *btr)
{
	stack_clear(btr->stack);
	bt_ctf_field_type_put(btr->cur_basic_field_type);
	btr->cur_basic_field_type = NULL;
	stitch_reset(btr);
	btr->buf.addr = NULL;
	btr->last_bo = BT_CTF_BYTE_ORDER_UNKNOWN;
}

size_t bt_ctf_btr_start(struct bt_ctf_btr *btr,
	struct bt_ctf_field_type *type, const uint8_t *buf,
	size_t offset, size_t packet_offset, size_t sz,
	enum bt_ctf_btr_status *status)
{
	assert(btr);
	assert(buf);
	assert(sz > 0);
	assert(BYTES_TO_BITS(sz) > offset);
	reset(btr);
	btr->buf.addr = buf;
	btr->buf.offset = offset;
	btr->buf.at = 0;
	btr->buf.packet_offset = packet_offset;
	btr->buf.buf_sz = sz;
	btr->buf.sz = BYTES_TO_BITS(sz) - offset;
	*status = BT_CTF_BTR_STATUS_OK;

	/* set root type */
	if (is_compound_type(type)) {
		/* compound type: push on visit stack */
		int stack_ret;

		if (btr->user.cbs.types.compound_begin) {
			*status = btr->user.cbs.types.compound_begin(
				type, btr->user.data);

			if (*status != BT_CTF_BTR_STATUS_OK) {
				goto end;
			}
		}

		stack_ret = stack_push_with_len(btr, type);

		if (stack_ret) {
			*status = BT_CTF_BTR_STATUS_ERROR;
			goto end;
		}

		btr->state = BTR_STATE_ALIGN_COMPOUND;
	} else {
		/* basic type: set as current basic type */
		btr->cur_basic_field_type = type;
		bt_ctf_field_type_get(btr->cur_basic_field_type);
		btr->state = BTR_STATE_ALIGN_BASIC;
	}

	/* run the machine! */
	while (true) {
		*status = handle_state(btr);

		if (*status != BT_CTF_BTR_STATUS_OK) {
			break;
		} else if (btr->state == BTR_STATE_DONE) {
			break;
		}
	}

	btr->buf.packet_offset += btr->buf.at;

end:
	return btr->buf.at;
}

size_t bt_ctf_btr_continue(struct bt_ctf_btr *btr,
	const uint8_t *buf, size_t sz,
	enum bt_ctf_btr_status *status)
{
	assert(btr);
	assert(buf);
	assert(sz > 0);
	btr->buf.addr = buf;
	btr->buf.offset = 0;
	btr->buf.at = 0;
	btr->buf.buf_sz = sz;
	btr->buf.sz = BYTES_TO_BITS(sz);
	*status = BT_CTF_BTR_STATUS_OK;

	/* continue running the machine */
	while (true) {
		*status = handle_state(btr);

		if (*status != BT_CTF_BTR_STATUS_OK) {
			break;
		} else if (btr->state == BTR_STATE_DONE) {
			break;
		}
	}

	btr->buf.packet_offset += btr->buf.at;

	return btr->buf.at;
}
