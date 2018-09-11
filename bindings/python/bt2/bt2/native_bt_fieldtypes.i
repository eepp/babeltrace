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
struct bt_field_type;
struct bt_field_path;
struct bt_field_type_signed_enumeration_mapping_ranges;
struct bt_field_type_unsigned_enumeration_mapping_ranges;

/* Common enumerations */
typedef const char * const *bt_field_type_enumeration_mapping_label_array;
enum bt_field_type_id {
	BT_FIELD_TYPE_ID_UNSIGNED_INTEGER,
	BT_FIELD_TYPE_ID_SIGNED_INTEGER,
	BT_FIELD_TYPE_ID_UNSIGNED_ENUMERATION,
	BT_FIELD_TYPE_ID_SIGNED_ENUMERATION,
	BT_FIELD_TYPE_ID_REAL,
	BT_FIELD_TYPE_ID_STRING,
	BT_FIELD_TYPE_ID_STRUCTURE,
	BT_FIELD_TYPE_ID_STATIC_ARRAY,
	BT_FIELD_TYPE_ID_DYNAMIC_ARRAY,
	BT_FIELD_TYPE_ID_VARIANT,
};
enum bt_field_type_integer_preferred_display_base {
	BT_FIELD_TYPE_INTEGER_PREFERRED_DISPLAY_BASE_BINARY,
	BT_FIELD_TYPE_INTEGER_PREFERRED_DISPLAY_BASE_OCTAL,
	BT_FIELD_TYPE_INTEGER_PREFERRED_DISPLAY_BASE_DECIMAL,
	BT_FIELD_TYPE_INTEGER_PREFERRED_DISPLAY_BASE_HEXADECIMAL,
};

/* Common functions */
enum bt_field_type_id bt_field_type_get_type_id(
		struct bt_field_type *field_type);

/* Integer field type base enumeration */
struct bt_field_type *bt_field_type_unsigned_integer_create(void);
struct bt_field_type *bt_field_type_signed_integer_create(void);

/* Integer field type functions */
uint64_t bt_field_type_integer_get_field_value_range(
		struct bt_field_type *field_type);
int bt_field_type_integer_set_field_value_range(
		struct bt_field_type *field_type, uint64_t size);

enum bt_field_type_integer_preferred_display_base
bt_field_type_integer_get_preferred_display_base(
		struct bt_field_type *field_type);
int bt_field_type_integer_set_preferred_display_base(
		struct bt_field_type *field_type,
		enum bt_field_type_integer_preferred_display_base base);

/* Real number field type functions */
struct bt_field_type *bt_field_type_real_create(void);
bt_bool bt_field_type_real_is_single_precision(
		struct bt_field_type *field_type);
int bt_field_type_real_set_is_single_precision(
		struct bt_field_type *field_type,
		bt_bool is_single_precision);

/* Enumeration field type functions */
struct bt_field_type *bt_field_type_unsigned_enumeration_create(void);
struct bt_field_type *bt_field_type_signed_enumeration_create(void);

/* Enumeration field type mapping iterator functions */
uint64_t bt_field_type_enumeration_get_mapping_count(
		struct bt_field_type *field_type);
void bt_field_type_unsigned_enumeration_borrow_mapping_by_index(
		struct bt_field_type *field_type, uint64_t index,
		const char **BTOUTSTR,
		struct bt_field_type_unsigned_enumeration_mapping_ranges
		**BTOUTENUMMAPPINGRANGE);
void bt_field_type_signed_enumeration_borrow_mapping_by_index(
		struct bt_field_type *field_type, uint64_t index,
		const char **BTOUTSTR,
		struct bt_field_type_signed_enumeration_mapping_ranges **BTOUTENUMMAPPINGRANGE);
uint64_t bt_field_type_unsigned_enumeration_mapping_ranges_get_range_count(
		struct bt_field_type_unsigned_enumeration_mapping_ranges *ranges);
uint64_t bt_field_type_signed_enumeration_mapping_ranges_get_range_count(
		struct bt_field_type_signed_enumeration_mapping_ranges *ranges);
void bt_field_type_unsigned_enumeration_mapping_ranges_get_range_by_index(
		struct bt_field_type_unsigned_enumeration_mapping_ranges *ranges,
		uint64_t index, uint64_t *OUTPUTINIT, uint64_t *OUTPUTINIT);
void bt_field_type_signed_enumeration_mapping_ranges_get_range_by_index(
		struct bt_field_type_signed_enumeration_mapping_ranges *ranges,
		uint64_t index, int64_t *OUTPUTINIT, int64_t *OUTPUTINIT);
int bt_field_type_unsigned_enumeration_get_mapping_labels_by_value(
		struct bt_field_type *field_type, uint64_t value,
		bt_field_type_enumeration_mapping_label_array *label_array,
		uint64_t *OUTPUTINIT);
int bt_field_type_signed_enumeration_get_mapping_labels_by_value(
		struct bt_field_type *field_type, int64_t value,
		bt_field_type_enumeration_mapping_label_array *label_array,
		uint64_t *OUTPUTINIT);
int bt_field_type_unsigned_enumeration_map_range(
		struct bt_field_type *field_type, const char *label,
		uint64_t range_lower, uint64_t range_upper);
int bt_field_type_signed_enumeration_map_range(
		struct bt_field_type *field_type, const char *label,
		int64_t range_lower, int64_t range_upper);

/* String field type functions */
struct bt_field_type *bt_field_type_string_create(void);

/* Structure field type functions */
struct bt_field_type *bt_field_type_structure_create(void);
uint64_t bt_field_type_structure_get_member_count(
		struct bt_field_type *field_type);
void bt_field_type_structure_borrow_member_by_index(
		struct bt_field_type *struct_field_type, uint64_t index,
		const char **BTOUTSTR, struct bt_field_type **BTOUTFT);
struct bt_field_type *bt_field_type_structure_borrow_member_field_type_by_name(
		struct bt_field_type *field_type, const char *name);
int bt_field_type_structure_append_member(
		struct bt_field_type *struct_field_type, const char *name,
		struct bt_field_type *field_type);

/* Array field type functions */
struct bt_field_type *bt_field_type_static_array_create(
		struct bt_field_type *elem_field_type,
		uint64_t length);
struct bt_field_type *bt_field_type_dynamic_array_create(
		struct bt_field_type *elem_field_type);
struct bt_field_type *bt_field_type_array_borrow_element_field_type(
		struct bt_field_type *field_type);
uint64_t bt_field_type_static_array_get_length(
		struct bt_field_type *field_type);
struct bt_field_path *
bt_field_type_dynamic_array_borrow_length_field_path(
		struct bt_field_type *field_type);
int bt_field_type_dynamic_array_set_length_field_type(
		struct bt_field_type *field_type,
		struct bt_field_type *length_field_type);

/* Variant field type functions */
struct bt_field_type *bt_field_type_variant_create(void);
struct bt_field_path *
bt_field_type_variant_borrow_selector_field_path(
		struct bt_field_type *field_type);
int bt_field_type_variant_set_selector_field_type(
		struct bt_field_type *field_type,
		struct bt_field_type *selector_field_type);
uint64_t bt_field_type_variant_get_option_count(
		struct bt_field_type *field_type);
void bt_field_type_variant_borrow_option_by_index(
		struct bt_field_type *variant_field_type, uint64_t index,
		const char **BTOUTSTR, struct bt_field_type **BTOUTFT);
struct bt_field_type *bt_field_type_variant_borrow_option_field_type_by_name(
		struct bt_field_type *field_type,
		const char *name);
int bt_field_type_variant_append_option(
		struct bt_field_type *var_field_type,
		const char *name, struct bt_field_type *field_type);
