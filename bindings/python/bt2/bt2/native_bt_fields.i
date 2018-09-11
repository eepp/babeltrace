/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Philippe Proulx <pproulx@efficios.com>
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

/* Type */
struct bt_field;
struct bt_field_type;
struct bt_field_type_enumeration_mapping_iterator;


/* Common functions */
struct bt_field_type *bt_field_borrow_type(struct bt_field *field);
enum bt_field_type_id bt_field_get_type_id(struct bt_field *field);

/* Integer field functions */
int64_t bt_field_signed_integer_get_value(struct bt_field *field);
void bt_field_signed_integer_set_value(struct bt_field *field,
		int64_t value);

uint64_t bt_field_unsigned_integer_get_value(struct bt_field *field);
void bt_field_unsigned_integer_set_value(struct bt_field *field,
		uint64_t value);

/* Real number field functions */
double bt_field_real_get_value(struct bt_field *field);
void bt_field_real_set_value(struct bt_field *field, double value);

/* Enumeration field functions */
int bt_field_unsigned_enumeration_get_mapping_labels(
		struct bt_field *field,
		bt_field_type_enumeration_mapping_label_array *label_array,
		uint64_t *count);
int bt_field_signed_enumeration_get_mapping_labels(
		struct bt_field *field,
		bt_field_type_enumeration_mapping_label_array *label_array,
		uint64_t *count);

/* String field functions */
const char *bt_field_string_get_value(struct bt_field *field);
uint64_t bt_field_string_get_length(struct bt_field *field);
int bt_field_string_set_value(struct bt_field *field, const char *value);
int bt_field_string_append(struct bt_field *field, const char *value);
int bt_field_string_append_with_length(
		struct bt_field *field, const char *value,
		uint64_t length);
int bt_field_string_clear(struct bt_field *field);

/* Structure field functions */
struct bt_field *bt_field_structure_borrow_member_field_by_index(
		struct bt_field *field, uint64_t index);
struct bt_field *bt_field_structure_borrow_member_field_by_name(
		struct bt_field *field, const char *name);

/* Array field functions */
uint64_t bt_field_array_get_length(struct bt_field *field);
struct bt_field *bt_field_array_borrow_element_field_by_index(
		struct bt_field *field, uint64_t index);
int bt_field_dynamic_array_set_length(struct bt_field *field,
		uint64_t length);

/* Variant field functions */
int bt_field_variant_select_option_field(struct bt_field *field,
		uint64_t index);
uint64_t bt_field_variant_get_selected_option_field_index(
		struct bt_field *field);
struct bt_field *bt_field_variant_borrow_selected_option_field(
		struct bt_field *field);
