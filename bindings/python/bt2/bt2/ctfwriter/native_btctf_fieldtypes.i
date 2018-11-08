/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2018 Francis Deslauriers <francis.deslauriers@efficios.com>
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
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

struct bt_ctf_field;
struct bt_ctf_field_type;

enum bt_ctf_field_type_id {
	BT_CTF_FIELD_TYPE_ID_UNKNOWN	= BT_FIELD_TYPE_ID_UNKNOWN,
	BT_CTF_FIELD_TYPE_ID_INTEGER	= BT_FIELD_TYPE_ID_INTEGER,
	BT_CTF_FIELD_TYPE_ID_FLOAT	= BT_FIELD_TYPE_ID_FLOAT,
	BT_CTF_FIELD_TYPE_ID_ENUM	= BT_FIELD_TYPE_ID_ENUM,
	BT_CTF_FIELD_TYPE_ID_STRING	= BT_FIELD_TYPE_ID_STRING,
	BT_CTF_FIELD_TYPE_ID_STRUCT	= BT_FIELD_TYPE_ID_STRUCT,
	BT_CTF_FIELD_TYPE_ID_ARRAY	= BT_FIELD_TYPE_ID_ARRAY,
	BT_CTF_FIELD_TYPE_ID_SEQUENCE	= BT_FIELD_TYPE_ID_SEQUENCE,
	BT_CTF_FIELD_TYPE_ID_VARIANT	= BT_FIELD_TYPE_ID_VARIANT,
	BT_CTF_FIELD_TYPE_ID_NR		= BT_FIELD_TYPE_ID_NR,
};

enum bt_ctf_field_type_id bt_ctf_field_type_get_type_id(
		struct bt_ctf_field_type *field_type);

enum bt_ctf_byte_order {
	BT_CTF_BYTE_ORDER_UNKNOWN		= BT_BYTE_ORDER_UNKNOWN,
	BT_CTF_BYTE_ORDER_NATIVE		= BT_BYTE_ORDER_NATIVE,
	BT_CTF_BYTE_ORDER_UNSPECIFIED		= BT_BYTE_ORDER_UNSPECIFIED,
	BT_CTF_BYTE_ORDER_LITTLE_ENDIAN		= BT_BYTE_ORDER_LITTLE_ENDIAN,
	BT_CTF_BYTE_ORDER_BIG_ENDIAN		= BT_BYTE_ORDER_BIG_ENDIAN,
	BT_CTF_BYTE_ORDER_NETWORK		= BT_BYTE_ORDER_NETWORK,
};

enum bt_ctf_string_encoding {
	BT_CTF_STRING_ENCODING_UNKNOWN	= BT_STRING_ENCODING_UNKNOWN,
	BT_CTF_STRING_ENCODING_NONE	= BT_STRING_ENCODING_NONE,
	BT_CTF_STRING_ENCODING_UTF8	= BT_STRING_ENCODING_UTF8,
	BT_CTF_STRING_ENCODING_ASCII	= BT_STRING_ENCODING_ASCII,
};

int bt_ctf_field_type_get_alignment(
		struct bt_ctf_field_type *field_type);

int bt_ctf_field_type_set_alignment(struct bt_ctf_field_type *field_type,
		unsigned int alignment);

enum bt_ctf_byte_order bt_ctf_field_type_get_byte_order(
		struct bt_ctf_field_type *field_type);

int bt_ctf_field_type_set_byte_order(
		struct bt_ctf_field_type *field_type,
		enum bt_ctf_byte_order byte_order);

enum bt_ctf_integer_base {
	BT_CTF_INTEGER_BASE_UNKNOWN		= -1,
	BT_CTF_INTEGER_BASE_UNSPECIFIED		= 0,
	BT_CTF_INTEGER_BASE_BINARY		= 2,
	BT_CTF_INTEGER_BASE_OCTAL		= 8,
	BT_CTF_INTEGER_BASE_DECIMAL		= 10,
	BT_CTF_INTEGER_BASE_HEXADECIMAL		= 16,
};

struct bt_ctf_field_type *bt_ctf_field_type_integer_create(
		unsigned int size);

int bt_ctf_field_type_integer_get_size(
		struct bt_ctf_field_type *int_field_type);

int bt_ctf_field_type_integer_set_size(
		struct bt_ctf_field_type *int_field_type, unsigned int size);

bt_bool bt_ctf_field_type_integer_is_signed(
		struct bt_ctf_field_type *int_field_type);
int bt_ctf_field_type_integer_set_is_signed(
		struct bt_ctf_field_type *int_field_type, bt_bool is_signed);

enum bt_ctf_integer_base bt_ctf_field_type_integer_get_base(
		struct bt_ctf_field_type *int_field_type);

int bt_ctf_field_type_integer_set_base(
		struct bt_ctf_field_type *int_field_type,
		enum bt_ctf_integer_base base);

enum bt_ctf_string_encoding bt_ctf_field_type_integer_get_encoding(
		struct bt_ctf_field_type *int_field_type);

int bt_ctf_field_type_integer_set_encoding(
		struct bt_ctf_field_type *int_field_type,
		enum bt_ctf_string_encoding encoding);

struct bt_ctf_clock_class *bt_ctf_field_type_integer_get_mapped_clock_class(
		struct bt_ctf_field_type *int_field_type);

int bt_ctf_field_type_integer_set_mapped_clock_class(
		struct bt_ctf_field_type *int_field_type,
		struct bt_ctf_clock_class *clock_class);

struct bt_ctf_field_type *bt_ctf_field_type_floating_point_create(void);

int bt_ctf_field_type_floating_point_get_exponent_digits(
		struct bt_ctf_field_type *float_field_type);

int bt_ctf_field_type_floating_point_set_exponent_digits(
		struct bt_ctf_field_type *float_field_type,
		unsigned int exponent_size);

int bt_ctf_field_type_floating_point_get_mantissa_digits(
		struct bt_ctf_field_type *float_field_type);

int bt_ctf_field_type_floating_point_set_mantissa_digits(
		struct bt_ctf_field_type *float_field_type,
		unsigned int mantissa_sign_size);

struct bt_ctf_field_type *bt_ctf_field_type_enumeration_create(
		struct bt_ctf_field_type *int_field_type);

struct bt_ctf_field_type *bt_ctf_field_type_enumeration_get_container_field_type(
		struct bt_ctf_field_type *enum_field_type);

int64_t bt_ctf_field_type_enumeration_get_mapping_count(
		struct bt_ctf_field_type *enum_field_type);

int bt_ctf_field_type_enumeration_signed_get_mapping_by_index(
		struct bt_ctf_field_type *enum_field_type, uint64_t index,
		const char **BTOUTSTR, int64_t *range_begin, int64_t *range_end);

int bt_ctf_field_type_enumeration_unsigned_get_mapping_by_index(
		struct bt_ctf_field_type *enum_field_type, uint64_t index,
		const char **BTOUTSTR, uint64_t *range_begin,
		uint64_t *range_end);

int bt_ctf_field_type_enumeration_signed_add_mapping(
		struct bt_ctf_field_type *enum_field_type,
		const char *name, int64_t range_begin, int64_t range_end);

int bt_ctf_field_type_enumeration_unsigned_add_mapping(
		struct bt_ctf_field_type *enum_field_type,
		const char *name, uint64_t range_begin, uint64_t range_end);

struct bt_ctf_field_type *bt_ctf_field_type_string_create(void);

enum bt_ctf_string_encoding bt_ctf_field_type_string_get_encoding(
		struct bt_ctf_field_type *string_field_type);

int bt_ctf_field_type_string_set_encoding(
		struct bt_ctf_field_type *string_field_type,
		enum bt_ctf_string_encoding encoding);

struct bt_ctf_field_type *bt_ctf_field_type_structure_create(void);

int64_t bt_ctf_field_type_structure_get_field_count(
		struct bt_ctf_field_type *struct_field_type);

int bt_ctf_field_type_structure_get_field_by_index(
		struct bt_ctf_field_type *struct_field_type,
		const char **BTOUTSTR, struct bt_ctf_field_type **BTCTFOUTFT,
		uint64_t index);

struct bt_ctf_field_type *bt_ctf_field_type_structure_get_field_type_by_name(
		struct bt_ctf_field_type *struct_field_type,
		const char *field_name);

int bt_ctf_field_type_structure_add_field(
		struct bt_ctf_field_type *struct_field_type,
		struct bt_ctf_field_type *field_type,
		const char *field_name);

struct bt_ctf_field_type *bt_ctf_field_type_array_create(
		struct bt_ctf_field_type *element_field_type,
		unsigned int length);

struct bt_ctf_field_type *bt_ctf_field_type_array_get_element_field_type(
		struct bt_ctf_field_type *array_field_type);

int64_t bt_ctf_field_type_array_get_length(
		struct bt_ctf_field_type *array_field_type);

struct bt_ctf_field_type *bt_ctf_field_type_sequence_create(
		struct bt_ctf_field_type *element_field_type,
		const char *length_name);

struct bt_ctf_field_type *bt_ctf_field_type_sequence_get_element_field_type(
		struct bt_ctf_field_type *sequence_field_type);

const char *bt_ctf_field_type_sequence_get_length_field_name(
		struct bt_ctf_field_type *sequence_field_type);

struct bt_ctf_field_type *bt_ctf_field_type_variant_create(
		struct bt_ctf_field_type *tag_field_type,
		const char *tag_name);

struct bt_ctf_field_type *bt_ctf_field_type_variant_get_tag_field_type(
		struct bt_ctf_field_type *variant_field_type);

const char *bt_ctf_field_type_variant_get_tag_name(
		struct bt_ctf_field_type *variant_field_type);

int bt_ctf_field_type_variant_set_tag_name(
		struct bt_ctf_field_type *variant_field_type,
		const char *tag_name);

int64_t bt_ctf_field_type_variant_get_field_count(
		struct bt_ctf_field_type *variant_field_type);

int bt_ctf_field_type_variant_get_field_by_index(
		struct bt_ctf_field_type *variant_field_type,
		const char **BTOUTSTR,
		struct bt_ctf_field_type **BTCTFOUTFT, uint64_t index);

struct bt_ctf_field_type *bt_ctf_field_type_variant_get_field_type_by_name(
		struct bt_ctf_field_type *variant_field_type,
		const char *field_name);

struct bt_ctf_field_type *bt_ctf_field_type_variant_get_field_type_from_tag(
		struct bt_ctf_field_type *variant_field_type,
		struct bt_ctf_field *tag_field);

int bt_ctf_field_type_variant_add_field(
		struct bt_ctf_field_type *variant_field_type,
		struct bt_ctf_field_type *field_type,
		const char *field_name);
