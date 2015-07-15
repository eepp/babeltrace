/*
 * test_ctf_btr.c
 *
 * CTF binary type reader tests
 *
 * Copyright (c) 2015 EfficiOS Inc. and Linux Foundation
 * Copyright (c) 2015 Philippe Proulx <pproulx@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; under version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <glib.h>
#include <babeltrace/ctf-ir/ctf-btr.h>
#include "tap/tap.h"

enum expected_event_type {
	EET_UNSIGNED_INT,
	EET_SIGNED_INT,
	EET_FLOAT,
	EET_UNSIGNED_ENUM,
	EET_SIGNED_ENUM,
	EET_STRING,
	EET_ARRAY_BEGIN,
	EET_ARRAY_END,
	EET_SEQUENCE_BEGIN,
	EET_SEQUENCE_END,
	EET_STRUCT_BEGIN,
	EET_STRUCT_END,
	EET_VARIANT_BEGIN,
	EET_VARIANT_END,
};

struct expected_event {
	struct bt_ctf_field_type *field_type;
	enum expected_event_type type;
	union {
		int64_t signed_int;
		uint64_t unsigned_int;
		double dbl;
		const char *string;
	} value;
};

#define EE_INIT()	do {i = 0;} while (0)

#define EE_BASE(_type, _ft)					\
	do {							\
		expected_events[i].type = (_type);		\
		expected_events[i].field_type = (_ft);		\
	} while (0)

#define EE_COMPOUND(_type, _ft)					\
	do {							\
		EE_BASE(_type, _ft);				\
		i++;						\
	} while (0)

#define EE_SIGNED_INT(_type, _ft, _val)				\
	do {							\
		EE_BASE(_type, _ft);				\
		expected_events[i].value.signed_int = (_val);	\
		i++;						\
	} while (0)

#define EE_UNSIGNED_INT(_type, _ft, _val)				\
	do {							\
		EE_BASE(_type, _ft);				\
		expected_events[i].value.unsigned_int = (_val);	\
		i++;						\
	} while (0)

#define EE_FLOAT(_ft, _val)					\
	do {							\
		EE_BASE(EET_FLOAT, _ft);			\
		expected_events[i].value.dbl = (_val);		\
		i++;						\
	} while (0)

#define EE_STRING(_ft, _val)					\
	do {							\
		EE_BASE(EET_STRING, _ft);			\
		expected_events[i].value.string = (_val);	\
		i++;						\
	} while (0)

struct cb_data {
	struct expected_event *expected_events;
	GString *cur_string;
	size_t count;
	size_t index;
};

static
void test_create_destroy(void)
{
	struct bt_ctf_btr *btr;
	struct bt_ctf_btr_cbs cbs;

	btr = bt_ctf_btr_create(cbs, NULL);
	ok(btr, "bt_ctf_btr_create() creates a BTR");
	bt_ctf_btr_destroy(btr);
	ok(btr, "bt_ctf_btr_destroy() does not crash");
}

static
enum bt_ctf_btr_status test_read_complex_type_signed_int_cb(int64_t value,
	struct bt_ctf_field_type *type, void *data)
{
	enum expected_event_type eet;
	enum bt_ctf_btr_status status = BT_CTF_BTR_STATUS_OK;
	struct cb_data *cb_data = data;
	struct expected_event *ee;

	switch (bt_ctf_field_type_get_type_id(type)) {
	case CTF_TYPE_INTEGER:
		eet = EET_SIGNED_INT;
		break;

	case CTF_TYPE_ENUM:
		eet = EET_SIGNED_ENUM;
		break;

	default:
		status = BT_CTF_BTR_STATUS_ERROR;
		goto end;
	}

	assert(cb_data->index < cb_data->count);
	ee = &cb_data->expected_events[cb_data->index];
	ok(ee->type == eet,
		"signed int event type matches expected event type");
	ok(ee->field_type == type,
		"signed int event field type matches expected event field type");
	ok(ee->value.signed_int == value,
		"signed int event value matches expected event value (%ld)",
		value);
	cb_data->index++;

end:
	return status;
}

static
enum bt_ctf_btr_status test_read_complex_type_unsigned_int_cb(uint64_t value,
	struct bt_ctf_field_type *type, void *data)
{
	enum expected_event_type eet;
	enum bt_ctf_btr_status status = BT_CTF_BTR_STATUS_OK;
	struct cb_data *cb_data = data;
	struct expected_event *ee;

	switch (bt_ctf_field_type_get_type_id(type)) {
	case CTF_TYPE_INTEGER:
		eet = EET_UNSIGNED_INT;
		break;

	case CTF_TYPE_ENUM:
		eet = EET_UNSIGNED_ENUM;
		break;

	default:
		status = BT_CTF_BTR_STATUS_ERROR;
		goto end;
	}

	assert(cb_data->index < cb_data->count);
	ee = &cb_data->expected_events[cb_data->index];
	ok(ee->type == eet,
		"unsigned int event type matches expected event type");
	ok(ee->field_type == type,
		"unsigned int event field type matches expected event field type");
	ok(ee->value.unsigned_int == value,
		"unsigned int event value matches expected event value (%lu)",
		value);
	cb_data->index++;

end:
	return status;
}

static inline
double normalize_float(double f)
{
	return round(f * 10000.) / 10000.;
}

static
enum bt_ctf_btr_status test_read_complex_type_float_cb(double value,
	struct bt_ctf_field_type *type, void *data)
{
	struct cb_data *cb_data = data;
	struct expected_event *ee;

	assert(cb_data->index < cb_data->count);
	ee = &cb_data->expected_events[cb_data->index];
	ok(ee->type == EET_FLOAT,
		"float event type matches expected event type");
	ok(ee->field_type == type,
		"float event field type matches expected event field type");
	ok(normalize_float(ee->value.dbl) == normalize_float(value),
		"float event value matches expected event value (%f)",
		value);
	cb_data->index++;

	return BT_CTF_BTR_STATUS_OK;
}

static
enum bt_ctf_btr_status test_read_complex_type_string_begin_cb(
	struct bt_ctf_field_type *type, void *data)
{
	struct cb_data *cb_data = data;
	struct expected_event *ee;

	assert(cb_data->index < cb_data->count);
	ee = &cb_data->expected_events[cb_data->index];
	ok(ee->type == EET_STRING,
		"string begin event type matches expected event type");
	ok(ee->field_type == type,
		"string begin event field type matches expected event field type");
	g_string_truncate(cb_data->cur_string, 0);

	return BT_CTF_BTR_STATUS_OK;
}

static
enum bt_ctf_btr_status test_read_complex_type_string_cb(const char *value,
	size_t len, struct bt_ctf_field_type *type, void *data)
{
	struct cb_data *cb_data = data;
	struct expected_event *ee;

	assert(cb_data->index < cb_data->count);
	ee = &cb_data->expected_events[cb_data->index];
	ok(ee->type == EET_STRING,
		"string event type matches expected event type");
	ok(ee->field_type == type,
		"string event field type matches expected event field type");
	diag("appending string value \"%.*s\"", len, value);
	g_string_append_len(cb_data->cur_string, value, len);

	return BT_CTF_BTR_STATUS_OK;
}

static
enum bt_ctf_btr_status test_read_complex_type_string_end_cb(
	struct bt_ctf_field_type *type, void *data)
{
	struct cb_data *cb_data = data;
	struct expected_event *ee;

	assert(cb_data->index < cb_data->count);
	ee = &cb_data->expected_events[cb_data->index];
	ok(ee->type == EET_STRING,
		"string end event type matches expected event type");
	ok(ee->field_type == type,
		"string end event field type matches expected event field type");
	ok(!strcmp(ee->value.string, cb_data->cur_string->str),
		"current string value matches expected event value (\"%s\")",
		ee->value.string);
	cb_data->index++;

	return BT_CTF_BTR_STATUS_OK;
}

static
enum bt_ctf_btr_status test_read_complex_type_compound_begin_cb(
	struct bt_ctf_field_type *type, void *data)
{
	enum expected_event_type eet;
	enum bt_ctf_btr_status status = BT_CTF_BTR_STATUS_OK;
	struct cb_data *cb_data = data;
	struct expected_event *ee;

	switch (bt_ctf_field_type_get_type_id(type)) {
	case CTF_TYPE_STRUCT:
		eet = EET_STRUCT_BEGIN;
		break;

	case CTF_TYPE_ARRAY:
		eet = EET_ARRAY_BEGIN;
		break;

	case CTF_TYPE_SEQUENCE:
		eet = EET_SEQUENCE_BEGIN;
		break;

	case CTF_TYPE_VARIANT:
		eet = EET_VARIANT_BEGIN;
		break;

	default:
		status = BT_CTF_BTR_STATUS_ERROR;
		goto end;
	}

	assert(cb_data->index < cb_data->count);
	ee = &cb_data->expected_events[cb_data->index];
	ok(ee->type == eet,
		"compound begin event type matches expected event type");
	ok(ee->field_type == type,
		"compound begin event field type matches expected event field type");
	cb_data->index++;

end:
	return status;
}

static
enum bt_ctf_btr_status test_read_complex_type_compound_end_cb(
	struct bt_ctf_field_type *type, void *data)
{
	enum expected_event_type eet;
	enum bt_ctf_btr_status status = BT_CTF_BTR_STATUS_OK;
	struct cb_data *cb_data = data;
	struct expected_event *ee;

	switch (bt_ctf_field_type_get_type_id(type)) {
	case CTF_TYPE_STRUCT:
		eet = EET_STRUCT_END;
		break;

	case CTF_TYPE_ARRAY:
		eet = EET_ARRAY_END;
		break;

	case CTF_TYPE_SEQUENCE:
		eet = EET_SEQUENCE_END;
		break;

	case CTF_TYPE_VARIANT:
		eet = EET_VARIANT_END;
		break;

	default:
		status = BT_CTF_BTR_STATUS_ERROR;
		goto end;
	}

	assert(cb_data->index < cb_data->count);
	ee = &cb_data->expected_events[cb_data->index];
	ok(ee->type == eet,
		"compound end event type matches expected event type");
	ok(ee->field_type == type,
		"compound end event field type matches expected event field type");
	cb_data->index++;

end:
	return status;
}

static
int64_t test_read_complex_type_get_sequence_length(
	struct bt_ctf_field_type *type, void *data)
{
	static size_t at = 0;
	int64_t length = -1;

	switch (at) {
	case 0:
		length = 1;
		at = 1;
		break;

	case 1:
		length = 2;
		at = 0;
		break;

	default:
		break;
	}

	return length;
}

static
struct bt_ctf_field_type *test_read_complex_type_get_variant_type(
	struct bt_ctf_field_type *type, void *data)
{
	struct bt_ctf_field_type *type_type;
	static int index = 0;
	const char *name;

	bt_ctf_field_type_variant_get_field(type, &name, &type_type, index);
	index++;

	if (index == 4) {
		index = 0;
	}

	return type_type;
}

struct bt_ctf_btr_cbs cbs = {
	.types = {
		.signed_int = test_read_complex_type_signed_int_cb,
		.unsigned_int = test_read_complex_type_unsigned_int_cb,
		.floating_point = test_read_complex_type_float_cb,
		.string_begin = test_read_complex_type_string_begin_cb,
		.string = test_read_complex_type_string_cb,
		.string_end = test_read_complex_type_string_end_cb,
		.compound_begin = test_read_complex_type_compound_begin_cb,
		.compound_end = test_read_complex_type_compound_end_cb,
	},
	.query = {
		.get_sequence_length =
			test_read_complex_type_get_sequence_length,
		.get_variant_type = test_read_complex_type_get_variant_type,
	},
};

/*
 * This function tests the binary reading of a very complex IR type
 * from a specific buffer of bytes:
 *
 *   1. The complex type is built.
 *   2. An array of expected events is built.
 *   3. Each time a type callback function is called, it is compared
 *      to the expected event (type, field type, and value).
 */
static
void test_read_complex_type(void)
{
	/*
	 * ctfirtg:
	 *
	 *     class: struct
	 *     fields:
	 *       a:
	 *         class: int
	 *         size: 23
	 *       b:
	 *         class: int
	 *         size: 5
	 *         signed: true
	 *       c:
	 *         class: int
	 *         size: 9
	 *         align: 16
	 *       d:
	 *         class: float
	 *         size:
	 *           exp: 8
	 *           mant: 24
	 *         byte-order: be
	 *         align: 32
	 *       e:
	 *         class: int
	 *         size: 53
	 *         signed: true
	 *       f:
	 *         class: array
	 *         length: 2
	 *         element-type:
	 *           class: struct
	 *           fields:
	 *             a:
	 *               class: int
	 *               size: 1
	 *             b:
	 *               class: enum
	 *               value-type:
	 *                 class: int
	 *                 size: 3
	 *                 signed: true
	 *               members:
	 *                 - label: MINUS ONE
	 *                   value: -1
	 *                 - ZERO
	 *                 - ONE
	 *             c:
	 *               class: string
	 *             d:
	 *               class: array
	 *               length: the.length
	 *               element-type:
	 *                 class: struct
	 *                 fields:
	 *                   a:
	 *                     class: int
	 *                     size: 5
	 *                   b:
	 *                     class: float
	 *                     size:
	 *                       exp: 8
	 *                       mant: 24
	 *                     align: 1
	 *                   c:
	 *                     class: int
	 *                     size: 1
	 *                     align: 32
	 *                   d:
	 *                     class: string
	 *                   e:
	 *                     class: int
	 *                     size: 2
	 *                     signed: true
	 *                     byte-order: be
	 *       g:
	 *         class: array
	 *         length: 4
	 *         element-type:
	 *           class: var
	 *           tag: the.tag
	 *           types:
	 *             a:
	 *               class: int
	 *               size: 5
	 *               signed: true
	 *               byte-order: be
	 *             b:
	 *               class: int
	 *               size: 11
	 *               byte-order: be
	 *             c:
	 *               class: string
	 *             d:
	 *               class: array
	 *               length: 2
	 *               element-type:
	 *                 class: float
	 *                 size:
	 *                   exp: 8
	 *                   mant: 24
	 *       h:
	 *         class: struct
	 *         min-align: 32
	 *         fields:
	 *           a:
	 *             class: int
	 *             size: 64
	 *           b:
	 *             class: int
	 *             size: 64
	 *             signed: true
	 *       i:
	 *         class: int
	 *         size: 4
	 *         signed: true
	 *         byte-order: be
	 *       j:
	 *         class: float
	 *         size:
	 *           exp: 11
	 *           mant: 53
	 *         align: 1
	 *         byte-order: be
	 */

	struct bt_ctf_field_type *root = NULL;
	struct bt_ctf_field_type *root_a = NULL;
	struct bt_ctf_field_type *root_b = NULL;
	struct bt_ctf_field_type *root_c = NULL;
	struct bt_ctf_field_type *root_d = NULL;
	struct bt_ctf_field_type *root_e = NULL;
	struct bt_ctf_field_type *root_f = NULL;
	struct bt_ctf_field_type *root_f_elem = NULL;
	struct bt_ctf_field_type *root_f_elem_a = NULL;
	struct bt_ctf_field_type *root_f_elem_b = NULL;
	struct bt_ctf_field_type *root_f_elem_b_int = NULL;
	struct bt_ctf_field_type *root_f_elem_c = NULL;
	struct bt_ctf_field_type *root_f_elem_d = NULL;
	struct bt_ctf_field_type *root_f_elem_d_elem = NULL;
	struct bt_ctf_field_type *root_f_elem_d_elem_a = NULL;
	struct bt_ctf_field_type *root_f_elem_d_elem_b = NULL;
	struct bt_ctf_field_type *root_f_elem_d_elem_c = NULL;
	struct bt_ctf_field_type *root_f_elem_d_elem_d = NULL;
	struct bt_ctf_field_type *root_f_elem_d_elem_e = NULL;
	struct bt_ctf_field_type *root_g = NULL;
	struct bt_ctf_field_type *root_g_elem = NULL;
	struct bt_ctf_field_type *root_g_elem_a = NULL;
	struct bt_ctf_field_type *root_g_elem_b = NULL;
	struct bt_ctf_field_type *root_g_elem_c = NULL;
	struct bt_ctf_field_type *root_g_elem_d = NULL;
	struct bt_ctf_field_type *root_g_elem_d_elem = NULL;
	struct bt_ctf_field_type *root_h = NULL;
	struct bt_ctf_field_type *root_h_a = NULL;
	struct bt_ctf_field_type *root_h_b = NULL;
	struct bt_ctf_field_type *root_i = NULL;
	struct bt_ctf_field_type *root_j = NULL;
	const size_t init_packet_offset = 4357;
	const size_t init_buf_offset = 5;
	const size_t content_bits = 1247;
	static const uint8_t buf[] = {
		0x55, 0xaa, 0x55, 0xaa,
		0xda, 0xcb, 0x6e, 0xfc,
		0x88, 0xf0, 0xaa, 0xcc,
		0xc0, 0x49, 0x0f, 0xd0,
		0x4a, 0xc5, 0xab, 0xff,
		0x75, 0xd3, 0x95, 0xef,
		0xaf, 0x63, 0x74, 0x66,
		0x34, 0x6c, 0x69, 0x66,
		0x65, 0x00, 0xaa, 0x55,
		0x3a, 0x2f, 0xdd, 0x5e,
		0xe8, 0xaa, 0x55, 0xaa,
		0x80, 0x53, 0x54, 0x52,
		0x69, 0x4e, 0x47, 0x00,
		0x9a, 0x5a, 0x55, 0xaa,
		0xf4, 0x66, 0x6f, 0x72,
		0x20, 0x28, 0x3b, 0x3b,
		0x29, 0x3b, 0x00, 0xf5,
		0xa5, 0x77, 0xe3, 0xf9,
		0xc7, 0xaa, 0x55, 0xf0,
		0xd5, 0x62, 0x65, 0x68,
		0x61, 0x76, 0x69, 0x6f,
		0x75, 0x72, 0x00, 0x75,
		0x3f, 0x01, 0xa1, 0x20,
		0xe8, 0x12, 0x34, 0x56,
		0xf0, 0x42, 0x61, 0x62,
		0x65, 0x6c, 0x74, 0x72,
		0x61, 0x63, 0x65, 0x00,
		0xf6, 0xd2, 0xee, 0x73,
		0x65, 0x67, 0x66, 0x61,
		0x75, 0x6c, 0x74, 0x21,
		0x00, 0x16, 0x6a, 0x95,
		0x40, 0x5d, 0xc4, 0x13,
		0x3f, 0x12, 0x32, 0x00,
		0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x80,
		0xd3, 0xff, 0x6a, 0x09,
		0xe6, 0x67, 0xf3, 0xbc,
		0xd4,
	};

	/*
	 * The following array is a sequence of sequences of byte counts
	 * to read. Each sequence of byte counts starts with the
	 * negative value of the first byte count to read, and ends with
	 * 0. Each sum of sequence, including the absolute value of the
	 * first, must be equal to 157.
	 *
	 * You can use the following Python script to generate such
	 * a sequence:
	 *
	 *     import random
	 *
	 *
	 *     target = 157
	 *     at = 0
	 *     first_done = False
	 *
	 *     while at < target:
	 *         mx = min(target - at, 10)
	 *         count = random.randint(1, mx)
	 *         r_count = count if first_done else -count
	 *         first_done = True
	 *         print('{}, '.format(r_count), end='')
	 *         at += count
	 *
	 *     print('0,')
	 */
	const static int reads[] = {
		-3, 10, 1, 6, 8, 7, 6, 6, 4, 10, 5, 1, 5, 4, 3, 1, 2, 3,
		7, 5, 6, 3, 8, 3, 8, 6, 7, 4, 2, 9, 4, 0,

		-1, 7, 7, 5, 9, 6, 10, 3, 6, 9, 10, 5, 3, 2, 1, 2, 4, 5,
		9, 8, 10, 7, 3, 10, 9, 5, 1, 0,

		-3, 9, 5, 4, 9, 5, 4, 9, 2, 10, 10, 7, 7, 1, 9, 5, 10,
		6, 9, 5, 3, 10, 1, 9, 5, 0,

		-6, 10, 4, 8, 2, 4, 8, 5, 6, 1, 8, 3, 8, 9, 1, 5, 2, 5,
		10, 5, 8, 8, 4, 2, 9, 7, 2, 2, 3, 1, 1, 0,

		-2, 6, 7, 3, 3, 8, 10, 4, 1, 4, 4, 9, 4, 1, 4, 10, 5, 4,
		9, 8, 10, 2, 5, 8, 6, 7, 7, 6, 0,

		-2, 9, 7, 6, 1, 4, 4, 6, 2, 8, 2, 8, 4, 9, 3, 10, 5, 7,
		3, 4, 4, 9, 9, 5, 6, 10, 3, 4, 2, 1, 0,

		-1, 4, 9, 7, 9, 3, 10, 2, 2, 5, 1, 10, 1, 9, 9, 1, 8, 6,
		3, 5, 5, 3, 10, 9, 4, 6, 6, 3, 1, 2, 2, 1, 0,

		-4, 5, 3, 3, 1, 3, 4, 10, 1, 6, 9, 1, 5, 5, 1, 7, 2, 3,
		10, 9, 3, 4, 9, 5, 10, 9, 2, 8, 7, 5, 1, 1, 1, 0,

		-5, 2, 1, 3, 9, 4, 7, 4, 8, 1, 6, 1, 8, 6, 10, 4, 2, 1,
		8, 9, 4, 8, 6, 9, 2, 8, 5, 3, 6, 3, 3, 1, 0,

		-15, 11, 20, 12, 19, 14, 9, 14, 19, 13, 11, 0,

		20, 13, 18, 9, 11, 10, 10, 15, 12, 11, 18, 10, 0,
	};
	size_t read_acc;
	static struct expected_event expected_events[67];
	enum bt_ctf_btr_status status;
	struct bt_ctf_btr *btr;
	struct cb_data cb_data;
	size_t bits;
	size_t i;

	/* create types */
	root = bt_ctf_field_type_structure_create();
	assert(root);
	bt_ctf_field_type_set_alignment(root, 32);
	root_a = bt_ctf_field_type_integer_create(23);
	assert(root_a);
	bt_ctf_field_type_integer_set_signed(root_a, 0);
	bt_ctf_field_type_integer_set_base(root_a, 10);
	bt_ctf_field_type_set_byte_order(root_a, BT_CTF_BYTE_ORDER_LITTLE_ENDIAN);
	bt_ctf_field_type_set_alignment(root_a, 1);
	bt_ctf_field_type_structure_add_field(root, root_a, "a");
	root_b = bt_ctf_field_type_integer_create(5);
	assert(root_b);
	bt_ctf_field_type_integer_set_signed(root_b, 1);
	bt_ctf_field_type_integer_set_base(root_b, 10);
	bt_ctf_field_type_set_byte_order(root_b, BT_CTF_BYTE_ORDER_LITTLE_ENDIAN);
	bt_ctf_field_type_set_alignment(root_b, 1);
	bt_ctf_field_type_structure_add_field(root, root_b, "b");
	root_c = bt_ctf_field_type_integer_create(9);
	assert(root_c);
	bt_ctf_field_type_integer_set_signed(root_c, 0);
	bt_ctf_field_type_integer_set_base(root_c, 10);
	bt_ctf_field_type_set_byte_order(root_c, BT_CTF_BYTE_ORDER_LITTLE_ENDIAN);
	bt_ctf_field_type_set_alignment(root_c, 16);
	bt_ctf_field_type_structure_add_field(root, root_c, "c");
	root_d = bt_ctf_field_type_floating_point_create();
	assert(root_d);
	bt_ctf_field_type_floating_point_set_exponent_digits(root_d, 8);
	bt_ctf_field_type_floating_point_set_mantissa_digits(root_d, 24);
	bt_ctf_field_type_set_byte_order(root_d, BT_CTF_BYTE_ORDER_BIG_ENDIAN);
	bt_ctf_field_type_set_alignment(root_d, 32);
	bt_ctf_field_type_structure_add_field(root, root_d, "d");
	root_e = bt_ctf_field_type_integer_create(53);
	assert(root_e);
	bt_ctf_field_type_integer_set_signed(root_e, 1);
	bt_ctf_field_type_integer_set_base(root_e, 10);
	bt_ctf_field_type_set_byte_order(root_e, BT_CTF_BYTE_ORDER_LITTLE_ENDIAN);
	bt_ctf_field_type_set_alignment(root_e, 1);
	bt_ctf_field_type_structure_add_field(root, root_e, "e");
	root_f_elem = bt_ctf_field_type_structure_create();
	assert(root_f_elem);
	bt_ctf_field_type_set_alignment(root_f_elem, 32);
	root_f_elem_a = bt_ctf_field_type_integer_create(1);
	assert(root_f_elem_a);
	bt_ctf_field_type_integer_set_signed(root_f_elem_a, 0);
	bt_ctf_field_type_integer_set_base(root_f_elem_a, 10);
	bt_ctf_field_type_set_byte_order(root_f_elem_a, BT_CTF_BYTE_ORDER_LITTLE_ENDIAN);
	bt_ctf_field_type_set_alignment(root_f_elem_a, 1);
	bt_ctf_field_type_structure_add_field(root_f_elem, root_f_elem_a, "a");
	root_f_elem_b_int = bt_ctf_field_type_integer_create(3);
	assert(root_f_elem_b_int);
	bt_ctf_field_type_integer_set_signed(root_f_elem_b_int, 1);
	bt_ctf_field_type_integer_set_base(root_f_elem_b_int, 10);
	bt_ctf_field_type_set_byte_order(root_f_elem_b_int, BT_CTF_BYTE_ORDER_LITTLE_ENDIAN);
	bt_ctf_field_type_set_alignment(root_f_elem_b_int, 1);
	root_f_elem_b = bt_ctf_field_type_enumeration_create(root_f_elem_b_int);
	assert(root_f_elem_b);
	bt_ctf_field_type_enumeration_add_mapping(root_f_elem_b, "MINUS ONE", -1, -1);
	bt_ctf_field_type_enumeration_add_mapping(root_f_elem_b, "ZERO", 0, 0);
	bt_ctf_field_type_enumeration_add_mapping(root_f_elem_b, "ONE", 1, 1);
	bt_ctf_field_type_structure_add_field(root_f_elem, root_f_elem_b, "b");
	root_f_elem_c = bt_ctf_field_type_string_create();
	assert(root_f_elem_c);
	bt_ctf_field_type_structure_add_field(root_f_elem, root_f_elem_c, "c");
	root_f_elem_d_elem = bt_ctf_field_type_structure_create();
	assert(root_f_elem_d_elem);
	bt_ctf_field_type_set_alignment(root_f_elem_d_elem, 32);
	root_f_elem_d_elem_a = bt_ctf_field_type_integer_create(5);
	assert(root_f_elem_d_elem_a);
	bt_ctf_field_type_integer_set_signed(root_f_elem_d_elem_a, 0);
	bt_ctf_field_type_integer_set_base(root_f_elem_d_elem_a, 10);
	bt_ctf_field_type_set_byte_order(root_f_elem_d_elem_a, BT_CTF_BYTE_ORDER_LITTLE_ENDIAN);
	bt_ctf_field_type_set_alignment(root_f_elem_d_elem_a, 1);
	bt_ctf_field_type_structure_add_field(root_f_elem_d_elem, root_f_elem_d_elem_a, "a");
	root_f_elem_d_elem_b = bt_ctf_field_type_floating_point_create();
	assert(root_f_elem_d_elem_b);
	bt_ctf_field_type_floating_point_set_exponent_digits(root_f_elem_d_elem_b, 8);
	bt_ctf_field_type_floating_point_set_mantissa_digits(root_f_elem_d_elem_b, 24);
	bt_ctf_field_type_set_byte_order(root_f_elem_d_elem_b, BT_CTF_BYTE_ORDER_LITTLE_ENDIAN);
	bt_ctf_field_type_set_alignment(root_f_elem_d_elem_b, 1);
	bt_ctf_field_type_structure_add_field(root_f_elem_d_elem, root_f_elem_d_elem_b, "b");
	root_f_elem_d_elem_c = bt_ctf_field_type_integer_create(1);
	assert(root_f_elem_d_elem_c);
	bt_ctf_field_type_integer_set_signed(root_f_elem_d_elem_c, 0);
	bt_ctf_field_type_integer_set_base(root_f_elem_d_elem_c, 10);
	bt_ctf_field_type_set_byte_order(root_f_elem_d_elem_c, BT_CTF_BYTE_ORDER_LITTLE_ENDIAN);
	bt_ctf_field_type_set_alignment(root_f_elem_d_elem_c, 32);
	bt_ctf_field_type_structure_add_field(root_f_elem_d_elem, root_f_elem_d_elem_c, "c");
	root_f_elem_d_elem_d = bt_ctf_field_type_string_create();
	assert(root_f_elem_d_elem_d);
	bt_ctf_field_type_structure_add_field(root_f_elem_d_elem, root_f_elem_d_elem_d, "d");
	root_f_elem_d_elem_e = bt_ctf_field_type_integer_create(2);
	assert(root_f_elem_d_elem_e);
	bt_ctf_field_type_integer_set_signed(root_f_elem_d_elem_e, 1);
	bt_ctf_field_type_integer_set_base(root_f_elem_d_elem_e, 10);
	bt_ctf_field_type_set_byte_order(root_f_elem_d_elem_e, BT_CTF_BYTE_ORDER_BIG_ENDIAN);
	bt_ctf_field_type_set_alignment(root_f_elem_d_elem_e, 1);
	bt_ctf_field_type_structure_add_field(root_f_elem_d_elem, root_f_elem_d_elem_e, "e");
	root_f_elem_d = bt_ctf_field_type_sequence_create(root_f_elem_d_elem, "the.length");
	assert(root_f_elem_d);
	bt_ctf_field_type_structure_add_field(root_f_elem, root_f_elem_d, "d");
	root_f = bt_ctf_field_type_array_create(root_f_elem, 2);
	assert(root_f);
	bt_ctf_field_type_structure_add_field(root, root_f, "f");
	root_g_elem = bt_ctf_field_type_variant_create(NULL, "the.tag");
	assert(root_g_elem);
	root_g_elem_a = bt_ctf_field_type_integer_create(5);
	assert(root_g_elem_a);
	bt_ctf_field_type_integer_set_signed(root_g_elem_a, 1);
	bt_ctf_field_type_integer_set_base(root_g_elem_a, 10);
	bt_ctf_field_type_set_byte_order(root_g_elem_a, BT_CTF_BYTE_ORDER_BIG_ENDIAN);
	bt_ctf_field_type_set_alignment(root_g_elem_a, 1);
	bt_ctf_field_type_variant_add_field(root_g_elem, root_g_elem_a, "a");
	root_g_elem_b = bt_ctf_field_type_integer_create(11);
	assert(root_g_elem_b);
	bt_ctf_field_type_integer_set_signed(root_g_elem_b, 0);
	bt_ctf_field_type_integer_set_base(root_g_elem_b, 10);
	bt_ctf_field_type_set_byte_order(root_g_elem_b, BT_CTF_BYTE_ORDER_BIG_ENDIAN);
	bt_ctf_field_type_set_alignment(root_g_elem_b, 1);
	bt_ctf_field_type_variant_add_field(root_g_elem, root_g_elem_b, "b");
	root_g_elem_c = bt_ctf_field_type_string_create();
	assert(root_g_elem_c);
	bt_ctf_field_type_variant_add_field(root_g_elem, root_g_elem_c, "c");
	root_g_elem_d_elem = bt_ctf_field_type_floating_point_create();
	assert(root_g_elem_d_elem);
	bt_ctf_field_type_floating_point_set_exponent_digits(root_g_elem_d_elem, 8);
	bt_ctf_field_type_floating_point_set_mantissa_digits(root_g_elem_d_elem, 24);
	bt_ctf_field_type_set_byte_order(root_g_elem_d_elem, BT_CTF_BYTE_ORDER_LITTLE_ENDIAN);
	bt_ctf_field_type_set_alignment(root_g_elem_d_elem, 8);
	root_g_elem_d = bt_ctf_field_type_array_create(root_g_elem_d_elem, 2);
	assert(root_g_elem_d);
	bt_ctf_field_type_variant_add_field(root_g_elem, root_g_elem_d, "d");
	root_g = bt_ctf_field_type_array_create(root_g_elem, 4);
	assert(root_g);
	bt_ctf_field_type_structure_add_field(root, root_g, "g");
	root_h = bt_ctf_field_type_structure_create();
	assert(root_h);
	bt_ctf_field_type_set_alignment(root_h, 32);
	root_h_a = bt_ctf_field_type_integer_create(64);
	assert(root_h_a);
	bt_ctf_field_type_integer_set_signed(root_h_a, 0);
	bt_ctf_field_type_integer_set_base(root_h_a, 10);
	bt_ctf_field_type_set_byte_order(root_h_a, BT_CTF_BYTE_ORDER_LITTLE_ENDIAN);
	bt_ctf_field_type_set_alignment(root_h_a, 8);
	bt_ctf_field_type_structure_add_field(root_h, root_h_a, "a");
	root_h_b = bt_ctf_field_type_integer_create(64);
	assert(root_h_b);
	bt_ctf_field_type_integer_set_signed(root_h_b, 1);
	bt_ctf_field_type_integer_set_base(root_h_b, 10);
	bt_ctf_field_type_set_byte_order(root_h_b, BT_CTF_BYTE_ORDER_LITTLE_ENDIAN);
	bt_ctf_field_type_set_alignment(root_h_b, 8);
	bt_ctf_field_type_structure_add_field(root_h, root_h_b, "b");
	bt_ctf_field_type_structure_add_field(root, root_h, "h");
	root_i = bt_ctf_field_type_integer_create(4);
	assert(root_i);
	bt_ctf_field_type_integer_set_signed(root_i, 1);
	bt_ctf_field_type_integer_set_base(root_i, 10);
	bt_ctf_field_type_set_byte_order(root_i, BT_CTF_BYTE_ORDER_BIG_ENDIAN);
	bt_ctf_field_type_set_alignment(root_i, 1);
	bt_ctf_field_type_structure_add_field(root, root_i, "i");
	root_j = bt_ctf_field_type_floating_point_create();
	assert(root_j);
	bt_ctf_field_type_floating_point_set_exponent_digits(root_j, 11);
	bt_ctf_field_type_floating_point_set_mantissa_digits(root_j, 53);
	bt_ctf_field_type_set_byte_order(root_j, BT_CTF_BYTE_ORDER_BIG_ENDIAN);
	bt_ctf_field_type_set_alignment(root_j, 1);
	bt_ctf_field_type_structure_add_field(root, root_j, "j");

	/* populate expected events */
	EE_INIT();
	EE_COMPOUND(EET_STRUCT_BEGIN, root);
	EE_UNSIGNED_INT(EET_UNSIGNED_INT, root_a, 7261146);
	EE_SIGNED_INT(EET_SIGNED_INT, root_b, -8);
	EE_UNSIGNED_INT(EET_UNSIGNED_INT, root_c, 136);
	EE_FLOAT(root_d, -3.141590);
	EE_SIGNED_INT(EET_SIGNED_INT, root_e, -2863720989735606LL);
	EE_COMPOUND(EET_ARRAY_BEGIN, root_f);
	EE_COMPOUND(EET_STRUCT_BEGIN, root_f_elem);
	EE_UNSIGNED_INT(EET_UNSIGNED_INT, root_f_elem_a, 1);
	EE_SIGNED_INT(EET_SIGNED_ENUM, root_f_elem_b, -1);
	EE_STRING(root_f_elem_c, "ctf4life");
	EE_COMPOUND(EET_SEQUENCE_BEGIN, root_f_elem_d);
	EE_COMPOUND(EET_STRUCT_BEGIN, root_f_elem_d_elem);
	EE_UNSIGNED_INT(EET_UNSIGNED_INT, root_f_elem_d_elem_a, 26);
	EE_FLOAT(root_f_elem_d_elem_b, 123.456);
	EE_UNSIGNED_INT(EET_UNSIGNED_INT, root_f_elem_d_elem_c, 0);
	EE_STRING(root_f_elem_d_elem_d, "STRiNG");
	EE_SIGNED_INT(EET_SIGNED_INT, root_f_elem_d_elem_e, -2);
	EE_COMPOUND(EET_STRUCT_END, root_f_elem_d_elem);
	EE_COMPOUND(EET_SEQUENCE_END, root_f_elem_d);
	EE_COMPOUND(EET_STRUCT_END, root_f_elem);
	EE_COMPOUND(EET_STRUCT_BEGIN, root_f_elem);
	EE_UNSIGNED_INT(EET_UNSIGNED_INT, root_f_elem_a, 0);
	EE_SIGNED_INT(EET_SIGNED_ENUM, root_f_elem_b, 2);
	EE_STRING(root_f_elem_c, "for (;;);");
	EE_COMPOUND(EET_SEQUENCE_BEGIN, root_f_elem_d);
	EE_COMPOUND(EET_STRUCT_BEGIN, root_f_elem_d_elem);
	EE_UNSIGNED_INT(EET_UNSIGNED_INT, root_f_elem_d_elem_a, 5);
	EE_FLOAT(root_f_elem_d_elem_b, 1.618034);
	EE_UNSIGNED_INT(EET_UNSIGNED_INT, root_f_elem_d_elem_c, 1);
	EE_STRING(root_f_elem_d_elem_d, "behaviour");
	EE_SIGNED_INT(EET_SIGNED_INT, root_f_elem_d_elem_e, 1);
	EE_COMPOUND(EET_STRUCT_END, root_f_elem_d_elem);
	EE_COMPOUND(EET_STRUCT_BEGIN, root_f_elem_d_elem);
	EE_UNSIGNED_INT(EET_UNSIGNED_INT, root_f_elem_d_elem_a, 31);
	EE_FLOAT(root_f_elem_d_elem_b, 8.314462);
	EE_UNSIGNED_INT(EET_UNSIGNED_INT, root_f_elem_d_elem_c, 0);
	EE_STRING(root_f_elem_d_elem_d, "Babeltrace");
	EE_SIGNED_INT(EET_SIGNED_INT, root_f_elem_d_elem_e, -1);
	EE_COMPOUND(EET_STRUCT_END, root_f_elem_d_elem);
	EE_COMPOUND(EET_SEQUENCE_END, root_f_elem_d);
	EE_COMPOUND(EET_STRUCT_END, root_f_elem);
	EE_COMPOUND(EET_ARRAY_END, root_f);
	EE_COMPOUND(EET_ARRAY_BEGIN, root_g);
	EE_COMPOUND(EET_VARIANT_BEGIN, root_g_elem);
	EE_SIGNED_INT(EET_SIGNED_INT, root_g_elem_a, -5);
	EE_COMPOUND(EET_VARIANT_END, root_g_elem);
	EE_COMPOUND(EET_VARIANT_BEGIN, root_g_elem);
	EE_UNSIGNED_INT(EET_UNSIGNED_INT, root_g_elem_b, 843);
	EE_COMPOUND(EET_VARIANT_END, root_g_elem);
	EE_COMPOUND(EET_VARIANT_BEGIN, root_g_elem);
	EE_STRING(root_g_elem_c, "segfault!");
	EE_COMPOUND(EET_VARIANT_END, root_g_elem);
	EE_COMPOUND(EET_VARIANT_BEGIN, root_g_elem);
	EE_COMPOUND(EET_ARRAY_BEGIN, root_g_elem_d);
	EE_FLOAT(root_g_elem_d_elem, 4.6692);
	EE_FLOAT(root_g_elem_d_elem, 0.577215);
	EE_COMPOUND(EET_ARRAY_END, root_g_elem_d);
	EE_COMPOUND(EET_VARIANT_END, root_g_elem);
	EE_COMPOUND(EET_ARRAY_END, root_g);
	EE_COMPOUND(EET_STRUCT_BEGIN, root_h);
	EE_UNSIGNED_INT(EET_UNSIGNED_INT, root_h_a, 18446744073709551615ULL);
	EE_SIGNED_INT(EET_SIGNED_INT, root_h_b, -9223372036854775807LL - 1);
	EE_COMPOUND(EET_STRUCT_END, root_h);
	EE_SIGNED_INT(EET_SIGNED_INT, root_i, -3);
	EE_FLOAT(root_j, 1.414213562373095);
	EE_COMPOUND(EET_STRUCT_END, root);

	/* fill callback data */
	cb_data.expected_events = expected_events;
	cb_data.count = sizeof(expected_events) / sizeof(*expected_events);
	cb_data.index = 0;
	cb_data.cur_string = g_string_new(NULL);

	/* create binary type reader */
	btr = bt_ctf_btr_create(cbs, &cb_data);
	assert(btr);

	/* do a complete read */
	bits = bt_ctf_btr_start(btr, root, buf, init_buf_offset,
		init_packet_offset, sizeof(buf), &status);
	ok(status == BT_CTF_BTR_STATUS_OK, "bt_ctf_btr_start() succeeds");
	ok(bits == content_bits,
		"bt_ctf_btr_start() reads the right amount of bits");

	/* test the continue function */
	for (i = 0; i < sizeof(reads) / sizeof(*reads); ++i) {
		int read = reads[i];

		if (read < 0) {
			read = -read;
			diag("bt_ctf_btr_start() with %d bytes", read);
			read_acc = read;
			cb_data.index = 0;
			bits = bt_ctf_btr_start(btr, root, buf, init_buf_offset,
				init_packet_offset, read, &status);
			ok(status == BT_CTF_BTR_STATUS_EOF,
				"bt_ctf_btr_start() does not have enough bytes");
		} else if (read == 0) {
			ok(bits == content_bits,
				"bt_ctf_btr_start() and bt_ctf_btr_continue() read the right amount of bits");
		} else {
			diag("bt_ctf_btr_continue() with %d bytes", read);
			bits += bt_ctf_btr_continue(btr, &buf[read_acc], read,
				&status);
			ok(status == BT_CTF_BTR_STATUS_OK ||
				status == BT_CTF_BTR_STATUS_EOF,
				"bt_ctf_btr_continue() succeeds");
			read_acc += read;
		}
	}

	/* destroy binary type reader */
	bt_ctf_btr_destroy(btr);

	/* clean callback data */
	g_string_free(cb_data.cur_string, TRUE);

	/* put type references */
	bt_ctf_field_type_put(root);
	bt_ctf_field_type_put(root_a);
	bt_ctf_field_type_put(root_b);
	bt_ctf_field_type_put(root_c);
	bt_ctf_field_type_put(root_d);
	bt_ctf_field_type_put(root_e);
	bt_ctf_field_type_put(root_f);
	bt_ctf_field_type_put(root_f_elem);
	bt_ctf_field_type_put(root_f_elem_a);
	bt_ctf_field_type_put(root_f_elem_b);
	bt_ctf_field_type_put(root_f_elem_b_int);
	bt_ctf_field_type_put(root_f_elem_c);
	bt_ctf_field_type_put(root_f_elem_d);
	bt_ctf_field_type_put(root_f_elem_d_elem);
	bt_ctf_field_type_put(root_f_elem_d_elem_a);
	bt_ctf_field_type_put(root_f_elem_d_elem_b);
	bt_ctf_field_type_put(root_f_elem_d_elem_c);
	bt_ctf_field_type_put(root_f_elem_d_elem_d);
	bt_ctf_field_type_put(root_f_elem_d_elem_e);
	bt_ctf_field_type_put(root_g);
	bt_ctf_field_type_put(root_g_elem);
	bt_ctf_field_type_put(root_g_elem_a);
	bt_ctf_field_type_put(root_g_elem_b);
	bt_ctf_field_type_put(root_g_elem_c);
	bt_ctf_field_type_put(root_g_elem_d);
	bt_ctf_field_type_put(root_g_elem_d_elem);
	bt_ctf_field_type_put(root_h);
	bt_ctf_field_type_put(root_h_a);
	bt_ctf_field_type_put(root_h_b);
	bt_ctf_field_type_put(root_i);
	bt_ctf_field_type_put(root_j);
}

/*
 * This function tests the binary reading of very small IR types, which
 * fit within a single byte.
 */
static
void test_read_tiny_types()
{
	size_t i = 0;
	size_t bits;
	struct bt_ctf_field_type *int3;
	static struct expected_event expected_events[1];
	static const uint8_t buf[] = {
		0x3a,
	};
	struct cb_data cb_data;
	enum bt_ctf_btr_status status;
	struct bt_ctf_btr *btr;

	/* create tiny type */
	int3 = bt_ctf_field_type_integer_create(3);
	bt_ctf_field_type_integer_set_signed(int3, 0);
	bt_ctf_field_type_set_byte_order(int3, BT_CTF_BYTE_ORDER_LITTLE_ENDIAN);
	bt_ctf_field_type_set_alignment(int3, 1);

	/* populate expected events */
	EE_INIT();
	EE_UNSIGNED_INT(EET_UNSIGNED_INT, int3, 5);

	/* fill callback data */
	cb_data.expected_events = expected_events;
	cb_data.count = sizeof(expected_events) / sizeof(*expected_events);
	cb_data.index = 0;
	cb_data.cur_string = NULL;

	/* create binary type reader */
	btr = bt_ctf_btr_create(cbs, &cb_data);
	assert(btr);

	/* read */
	bits = bt_ctf_btr_start(btr, int3, buf, 1, 1, sizeof(buf), &status);
	ok(status == BT_CTF_BTR_STATUS_OK, "bt_ctf_btr_start() succeeds");
	ok(bits == 3,
		"bt_ctf_btr_start() reads the right amount of bits");

	/* read again */
	EE_INIT();
	EE_UNSIGNED_INT(EET_UNSIGNED_INT, int3, 3);
	cb_data.index = 0;
	bits = bt_ctf_btr_start(btr, int3, buf, 4, 4, sizeof(buf), &status);
	ok(status == BT_CTF_BTR_STATUS_OK, "bt_ctf_btr_start() succeeds");
	ok(bits == 3,
		"bt_ctf_btr_start() reads the right amount of bits");

	/* read again */
	EE_INIT();
	EE_UNSIGNED_INT(EET_UNSIGNED_INT, int3, 4);
	cb_data.index = 0;
	bits = bt_ctf_btr_start(btr, int3, buf, 7, 7, sizeof(buf), &status);
	ok(status == BT_CTF_BTR_STATUS_EOF,
		"bt_ctf_btr_start() needs more bytes");
	ok(bits == 1,
		"bt_ctf_btr_start() reads the right amount of bits");
	bits = bt_ctf_btr_continue(btr, buf, sizeof(buf), &status);
	ok(status == BT_CTF_BTR_STATUS_OK, "bt_ctf_btr_continue() succeeds");
	ok(bits == 2,
		"bt_ctf_btr_continue() reads the right amount of bits");

	/* destroy binary type reader */
	bt_ctf_btr_destroy(btr);

	/* put type references */
	bt_ctf_field_type_put(int3);
}

int main(void)
{
	plan_no_plan();
	test_create_destroy();
	test_read_complex_type();
	test_read_tiny_types();

	return 0;
}
