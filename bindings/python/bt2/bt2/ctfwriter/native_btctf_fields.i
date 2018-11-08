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
struct bt_ctf_event_class;
struct bt_ctf_event;
struct bt_ctf_field_type;
struct bt_ctf_field_type_enumeration_mapping_iterator;

struct bt_ctf_field *bt_ctf_field_create(
		struct bt_ctf_field_type *field_type);
struct bt_ctf_field_type *bt_ctf_field_get_type(
		struct bt_ctf_field *field);
enum bt_ctf_field_type_id bt_ctf_field_get_type_id(
		struct bt_ctf_field *field);
struct bt_ctf_field *bt_ctf_field_copy(struct bt_ctf_field *field);
int bt_ctf_field_integer_signed_get_value(
		struct bt_ctf_field *integer_field, int64_t *OUTPUTINIT);
int bt_ctf_field_integer_signed_set_value(
		struct bt_ctf_field *integer_field, int64_t value);
int bt_ctf_field_integer_unsigned_get_value(
		struct bt_ctf_field *integer_field, uint64_t *OUTPUTINIT);
int bt_ctf_field_integer_unsigned_set_value(
		struct bt_ctf_field *integer_field, uint64_t value);
int bt_ctf_field_floating_point_get_value(
		struct bt_ctf_field *float_field, double *OUTPUTINIT);
int bt_ctf_field_floating_point_set_value(
		struct bt_ctf_field *float_field, double value);
struct bt_ctf_field *bt_ctf_field_enumeration_get_container(
		struct bt_ctf_field *enum_field);
const char *bt_ctf_field_string_get_value(
		struct bt_ctf_field *string_field);
int bt_ctf_field_string_set_value(struct bt_ctf_field *string_field,
		const char *value);
int bt_ctf_field_string_append(struct bt_ctf_field *string_field,
		const char *value);
int bt_ctf_field_string_append_len(
		struct bt_ctf_field *string_field, const char *value,
		unsigned int length);
struct bt_ctf_field *bt_ctf_field_structure_get_field_by_name(
		struct bt_ctf_field *struct_field, const char *name);
struct bt_ctf_field *bt_ctf_field_structure_get_field_by_index(
		struct bt_ctf_field *struct_field, uint64_t index);
struct bt_ctf_field *bt_ctf_field_array_get_field(
		struct bt_ctf_field *array_field, uint64_t index);
struct bt_ctf_field *bt_ctf_field_sequence_get_field(
		struct bt_ctf_field *sequence_field, uint64_t index);
int bt_ctf_field_sequence_set_length(struct bt_ctf_field *sequence_field,
		struct bt_ctf_field *length_field);
struct bt_ctf_field *bt_ctf_field_variant_get_field(
		struct bt_ctf_field *variant_field,
		struct bt_ctf_field *tag_field);
struct bt_ctf_field *bt_ctf_field_variant_get_current_field(
		struct bt_ctf_field *variant_field);
