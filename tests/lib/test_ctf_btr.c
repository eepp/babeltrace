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

#define _GNU_SOURCE
#include <babeltrace/ctf-ir/ctf-btr.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "tap/tap.h"

enum expected_event_type {
	EET_UNSIGNED_INT,
	EET_SIGNED_INT,
	EET_FLOAT,
	EET_UNSIGNED_ENUM,
	EET_SIGNED_ENUM,
	EET_STRING_BEGIN,
	EET_STRING,
	EET_STRING_END,
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

struct cb_data {
	struct expected_event *expected_events;
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
	printf("signed int: %ld\n", value);

	return BT_CTF_BTR_STATUS_OK;
}

static
enum bt_ctf_btr_status test_read_complex_type_unsigned_int_cb(uint64_t value,
	struct bt_ctf_field_type *type, void *data)
{
	printf("unsigned int: %lu\n", value);

	return BT_CTF_BTR_STATUS_OK;
}

static
enum bt_ctf_btr_status test_read_complex_type_float_cb(double value,
	struct bt_ctf_field_type *type, void *data)
{
	printf("float: %f\n", value);

	return BT_CTF_BTR_STATUS_OK;
}

static
enum bt_ctf_btr_status test_read_complex_type_string_begin_cb(
	struct bt_ctf_field_type *type, void *data)
{
	puts("string begin");

	return BT_CTF_BTR_STATUS_OK;
}

static
enum bt_ctf_btr_status test_read_complex_type_string_cb(const char *value,
	size_t len, struct bt_ctf_field_type *type, void *data)
{
	printf("string: \"%.*s\"\n", (int) len, value);

	return BT_CTF_BTR_STATUS_OK;
}

static
enum bt_ctf_btr_status test_read_complex_type_string_end_cb(
	struct bt_ctf_field_type *type, void *data)
{
	puts("string end");

	return BT_CTF_BTR_STATUS_OK;
}

static
enum bt_ctf_btr_status test_read_complex_type_compound_begin_cb(
	struct bt_ctf_field_type *type, void *data)
{
	puts("compound begin");

	return BT_CTF_BTR_STATUS_OK;
}

static
enum bt_ctf_btr_status test_read_complex_type_compound_end_cb(
	struct bt_ctf_field_type *type, void *data)
{
	puts("compound end");

	return BT_CTF_BTR_STATUS_OK;
}

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
	 *           byte-order: be
	 *           align: 32
	 *       e:
	 *         class: array
	 *         length: 3
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
	 *               class: struct
	 *               min-align: 16
	 *               fields:
	 *                 a:
	 *                   class: array
	 *                   length: the.length
	 *                   element-type:
	 *                     class: struct
	 *                     fields:
	 *                       a:
	 *                         class: int
	 *                         size: 5
	 *                       b:
	 *                         class: int
	 *                         size: 1
	 *                         align: 32
	 *                       c:
	 *                         class: float
	 *                         size:
	 *                           exp: 8
	 *                           mant: 24
	 *                       d:
	 *                         class: string
	 *       f:
	 *         class: array
	 *         length: 5
	 *         element-type:
	 *           class: var
	 *           tag: the.tag
	 *           types:
	 *             a:
	 *               class: int
	 *               size: 6
	 *               signed: true
	 *             b:
	 *               class: int
	 *               size: 14
	 *               align: 8
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
	 *       g:
	 *         class: int
	 *         size: 32
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
			.get_sequence_length = NULL,
			.get_variant_type = NULL,
		},
	};
	static const uint8_t buf[] = {
		0x55, 0xaa, 0x55, 0xaa,
		0xda, 0xcb, 0x6e, 0xfc,
		0x88, 0xf0, 0xaa, 0xcc,
		0xc0, 0x49, 0x0f, 0xd0,
		0x4a, 0xc5, 0xab, 0xff,
		0x75, 0xd3, 0x95, 0xef,
		0xaf, 0x63, 0x74, 0x66,
		0x34, 0x6c, 0x69, 0x66,
		0x65, 0x00,

	};
	struct bt_ctf_btr *btr;
	enum bt_ctf_btr_status status;
	size_t bits;

	/* create types */
	root = bt_ctf_field_type_structure_create();
	bt_ctf_field_type_set_alignment(root, 32);
	root_a = bt_ctf_field_type_integer_create(23);
	bt_ctf_field_type_integer_set_signed(root_a, 0);
	bt_ctf_field_type_integer_set_base(root_a, 10);
	bt_ctf_field_type_set_byte_order(root_a, BT_CTF_BYTE_ORDER_LITTLE_ENDIAN);
	bt_ctf_field_type_set_alignment(root_a, 1);
	bt_ctf_field_type_structure_add_field(root, root_a, "a");
	root_b = bt_ctf_field_type_integer_create(5);
	bt_ctf_field_type_integer_set_signed(root_b, 1);
	bt_ctf_field_type_integer_set_base(root_b, 10);
	bt_ctf_field_type_set_byte_order(root_b, BT_CTF_BYTE_ORDER_LITTLE_ENDIAN);
	bt_ctf_field_type_set_alignment(root_b, 1);
	bt_ctf_field_type_structure_add_field(root, root_b, "b");
	root_c = bt_ctf_field_type_integer_create(9);
	bt_ctf_field_type_integer_set_signed(root_c, 0);
	bt_ctf_field_type_integer_set_base(root_c, 10);
	bt_ctf_field_type_set_byte_order(root_c, BT_CTF_BYTE_ORDER_LITTLE_ENDIAN);
	bt_ctf_field_type_set_alignment(root_c, 16);
	bt_ctf_field_type_structure_add_field(root, root_c, "c");
	root_d = bt_ctf_field_type_floating_point_create();
	bt_ctf_field_type_floating_point_set_exponent_digits(root_d, 8);
	bt_ctf_field_type_floating_point_set_mantissa_digits(root_d, 24);
	bt_ctf_field_type_set_byte_order(root_d, BT_CTF_BYTE_ORDER_BIG_ENDIAN);
	bt_ctf_field_type_set_alignment(root_d, 32);
	bt_ctf_field_type_structure_add_field(root, root_d, "d");
	root_e = bt_ctf_field_type_integer_create(53);
	bt_ctf_field_type_integer_set_signed(root_e, 1);
	bt_ctf_field_type_integer_set_base(root_e, 10);
	bt_ctf_field_type_set_byte_order(root_e, BT_CTF_BYTE_ORDER_LITTLE_ENDIAN);
	bt_ctf_field_type_set_alignment(root_e, 1);
	bt_ctf_field_type_structure_add_field(root, root_e, "e");
	root_f_elem = bt_ctf_field_type_structure_create();
	bt_ctf_field_type_set_alignment(root_f_elem, 32);
	root_f_elem_a = bt_ctf_field_type_integer_create(1);
	bt_ctf_field_type_integer_set_signed(root_f_elem_a, 0);
	bt_ctf_field_type_integer_set_base(root_f_elem_a, 10);
	bt_ctf_field_type_set_byte_order(root_f_elem_a, BT_CTF_BYTE_ORDER_LITTLE_ENDIAN);
	bt_ctf_field_type_set_alignment(root_f_elem_a, 1);
	bt_ctf_field_type_structure_add_field(root_f_elem, root_f_elem_a, "a");
	root_f_elem_b_int = bt_ctf_field_type_integer_create(3);
	bt_ctf_field_type_integer_set_signed(root_f_elem_b_int, 1);
	bt_ctf_field_type_integer_set_base(root_f_elem_b_int, 10);
	bt_ctf_field_type_set_byte_order(root_f_elem_b_int, BT_CTF_BYTE_ORDER_LITTLE_ENDIAN);
	bt_ctf_field_type_set_alignment(root_f_elem_b_int, 1);
	root_f_elem_b = bt_ctf_field_type_enumeration_create(root_f_elem_b_int);
	bt_ctf_field_type_enumeration_add_mapping(root_f_elem_b, "MINUS ONE", -1, -1);
	bt_ctf_field_type_enumeration_add_mapping(root_f_elem_b, "ZERO", 0, 0);
	bt_ctf_field_type_enumeration_add_mapping(root_f_elem_b, "ONE", 1, 1);
	bt_ctf_field_type_structure_add_field(root_f_elem, root_f_elem_b, "b");
	root_f_elem_c = bt_ctf_field_type_string_create();
	bt_ctf_field_type_structure_add_field(root_f_elem, root_f_elem_c, "c");
	root_f = bt_ctf_field_type_array_create(root_f_elem, 1);
	bt_ctf_field_type_structure_add_field(root, root_f, "f");

	btr = bt_ctf_btr_create(cbs, NULL);
	assert(btr);
	bits = bt_ctf_btr_start(btr, root, buf, 5, 4357, 34, &status);
	printf("=> bits decoded: %u\n", (unsigned int) bits);
	bt_ctf_btr_destroy(btr);

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
}

int main(void)
{
	plan_no_plan();
	test_create_destroy();
	test_read_complex_type();

	return 0;
}
