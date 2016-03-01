/*
 * Values.c: value objects
 *
 * Babeltrace Library
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

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <string.h>
#include <babeltrace/compiler.h>
#include <babeltrace/object-internal.h>
#include <babeltrace/ref.h>
#include <babeltrace/values.h>
#include <babeltrace/compat/glib.h>
#include <babeltrace/logging-internal.h>

#define BT_VALUE_FROM_CONCRETE(_concrete) ((struct bt_value *) (_concrete))
#define BT_VALUE_TO_BOOL(_base) ((struct bt_value_bool *) (_base))
#define BT_VALUE_TO_INTEGER(_base) ((struct bt_value_integer *) (_base))
#define BT_VALUE_TO_FLOAT(_base) ((struct bt_value_float *) (_base))
#define BT_VALUE_TO_STRING(_base) ((struct bt_value_string *) (_base))
#define BT_VALUE_TO_ARRAY(_base) ((struct bt_value_array *) (_base))
#define BT_VALUE_TO_MAP(_base) ((struct bt_value_map *) (_base))

struct bt_value {
	struct bt_object base;
	enum bt_value_type type;
	bool is_frozen;
};

static
struct bt_value bt_value_null_instance = {
	.type = BT_VALUE_TYPE_NULL,
	.is_frozen = true,
};

struct bt_value *bt_value_null = &bt_value_null_instance;

struct bt_value_bool {
	struct bt_value base;
	bool value;
};

struct bt_value_integer {
	struct bt_value base;
	int64_t value;
};

struct bt_value_float {
	struct bt_value base;
	double value;
};

struct bt_value_string {
	struct bt_value base;
	GString *gstr;
};

struct bt_value_array {
	struct bt_value base;
	GPtrArray *garray;
};

struct bt_value_map {
	struct bt_value base;
	GHashTable *ght;
};

static
void bt_value_destroy(struct bt_object *obj);

static
void bt_value_string_destroy(struct bt_value *object)
{
	g_string_free(BT_VALUE_TO_STRING(object)->gstr, TRUE);
}

static
void bt_value_array_destroy(struct bt_value *object)
{
	/*
	 * Pointer array's registered value destructor will take care
	 * of putting each contained object.
	 */
	g_ptr_array_free(BT_VALUE_TO_ARRAY(object)->garray, TRUE);
}

static
void bt_value_map_destroy(struct bt_value *object)
{
	/*
	 * Hash table's registered value destructor will take care of
	 * putting each contained object. Keys are GQuarks and cannot
	 * be destroyed anyway.
	 */
	g_hash_table_destroy(BT_VALUE_TO_MAP(object)->ght);
}

static
void (* const destroy_funcs[])(struct bt_value *) = {
	[BT_VALUE_TYPE_NULL] =		NULL,
	[BT_VALUE_TYPE_BOOL] =		NULL,
	[BT_VALUE_TYPE_INTEGER] =	NULL,
	[BT_VALUE_TYPE_FLOAT] =		NULL,
	[BT_VALUE_TYPE_STRING] =	bt_value_string_destroy,
	[BT_VALUE_TYPE_ARRAY] =		bt_value_array_destroy,
	[BT_VALUE_TYPE_MAP] =		bt_value_map_destroy,
};

static
struct bt_value *bt_value_null_copy(const struct bt_value *null_obj)
{
	return bt_value_null;
}

static
struct bt_value *bt_value_bool_copy(const struct bt_value *bool_obj)
{
	return bt_value_bool_create_init(BT_VALUE_TO_BOOL(bool_obj)->value);
}

static
struct bt_value *bt_value_integer_copy(const struct bt_value *integer_obj)
{
	return bt_value_integer_create_init(
		BT_VALUE_TO_INTEGER(integer_obj)->value);
}

static
struct bt_value *bt_value_float_copy(const struct bt_value *float_obj)
{
	return bt_value_float_create_init(
		BT_VALUE_TO_FLOAT(float_obj)->value);
}

static
struct bt_value *bt_value_string_copy(const struct bt_value *string_obj)
{
	return bt_value_string_create_init(
		BT_VALUE_TO_STRING(string_obj)->gstr->str);
}

static
struct bt_value *bt_value_array_copy(const struct bt_value *array_obj)
{
	int i;
	int err;
	struct bt_value *copy_obj;
	struct bt_value_array *typed_array_obj;

	typed_array_obj = BT_VALUE_TO_ARRAY(array_obj);
	copy_obj = bt_value_array_create();
	if (!copy_obj) {
		BT_ERR("Cannot create array value object\n");
		goto end;
	}

	for (i = 0; i < typed_array_obj->garray->len; ++i) {
		struct bt_value *element_obj_copy;
		struct bt_value *element_obj = bt_value_array_get(array_obj, i);

		if (!element_obj) {
			BT_ERR("Cannot get original array value object's element #%d\n", i);
			BT_PUT(copy_obj);
			goto end;
		}

		element_obj_copy = bt_value_copy(element_obj);
		BT_PUT(element_obj);

		if (!element_obj_copy) {
			BT_ERR("Cannot copy original array value object's element #%d\n", i);
			BT_PUT(copy_obj);
			goto end;
		}

		err = bt_value_array_append(copy_obj, element_obj_copy);
		BT_PUT(element_obj_copy);

		if (err) {
			BT_ERR("Cannot append array value object's element copy #%d to array value object copy\n", i);
			BT_PUT(copy_obj);
			goto end;
		}
	}

end:
	return copy_obj;
}

static
struct bt_value *bt_value_map_copy(const struct bt_value *map_obj)
{
	int err;
	GHashTableIter iter;
	gpointer key, element_obj;
	struct bt_value *copy_obj;
	struct bt_value *element_obj_copy;
	struct bt_value_map *typed_map_obj;

	typed_map_obj = BT_VALUE_TO_MAP(map_obj);
	copy_obj = bt_value_map_create();
	if (!copy_obj) {
		BT_ERR("Cannot create map value object\n");
		goto end;
	}

	g_hash_table_iter_init(&iter, typed_map_obj->ght);

	while (g_hash_table_iter_next(&iter, &key, &element_obj)) {
		const char *key_str = g_quark_to_string((unsigned long) key);

		element_obj_copy = bt_value_copy(element_obj);

		if (!element_obj_copy) {
			BT_ERR("Cannot copy original map value object's element \"%s\"\n", key_str);
			BT_PUT(copy_obj);
			goto end;
		}

		err = bt_value_map_insert(copy_obj, key_str, element_obj_copy);
		BT_PUT(element_obj_copy);

		if (err) {
			BT_ERR("Cannot insert map value object's element copy \"%s\" into map value object copy\n", key_str);
			BT_PUT(copy_obj);
			goto end;
		}
	}

end:
	return copy_obj;
}

static
struct bt_value *(* const copy_funcs[])(const struct bt_value *) = {
	[BT_VALUE_TYPE_NULL] =		bt_value_null_copy,
	[BT_VALUE_TYPE_BOOL] =		bt_value_bool_copy,
	[BT_VALUE_TYPE_INTEGER] =	bt_value_integer_copy,
	[BT_VALUE_TYPE_FLOAT] =		bt_value_float_copy,
	[BT_VALUE_TYPE_STRING] =	bt_value_string_copy,
	[BT_VALUE_TYPE_ARRAY] =		bt_value_array_copy,
	[BT_VALUE_TYPE_MAP] =		bt_value_map_copy,
};

static
int bt_value_null_compare(const struct bt_value *object_a,
		const struct bt_value *object_b)
{
	/*
	 * Always true since bt_value_compare() already checks if both
	 * object_a and object_b have the same type, and in the case of
	 * null value objects, they're always the same if it is so.
	 */
	return 0;
}

static
int bt_value_bool_compare(const struct bt_value *object_a,
		const struct bt_value *object_b)
{
	return BT_VALUE_TO_BOOL(object_a)->value ==
		BT_VALUE_TO_BOOL(object_b)->value ? 0 : 1;
}

static
int bt_value_integer_compare(const struct bt_value *object_a,
		const struct bt_value *object_b)
{
	return BT_VALUE_TO_INTEGER(object_a)->value ==
		BT_VALUE_TO_INTEGER(object_b)->value ? 0 : 1;
}

static
int bt_value_float_compare(const struct bt_value *object_a,
		const struct bt_value *object_b)
{
	return BT_VALUE_TO_FLOAT(object_a)->value ==
		BT_VALUE_TO_FLOAT(object_b)->value ? 0 : 1;
}

static
int bt_value_string_compare(const struct bt_value *object_a,
		const struct bt_value *object_b)
{
	return !strcmp(BT_VALUE_TO_STRING(object_a)->gstr->str,
		BT_VALUE_TO_STRING(object_b)->gstr->str) ? 0 : 1;
}

static
int bt_value_array_compare(const struct bt_value *object_a,
		const struct bt_value *object_b)
{
	int i;
	int ret = 0;
	const struct bt_value_array *array_obj_a =
		BT_VALUE_TO_ARRAY(object_a);

	if (bt_value_array_size(object_a) != bt_value_array_size(object_b)) {
		BT_DBG("Array value objects A and B differ in size\n");
		ret = 1;
		goto end;
	}

	for (i = 0; i < array_obj_a->garray->len; ++i) {
		struct bt_value *element_obj_a;
		struct bt_value *element_obj_b;

		element_obj_a = bt_value_array_get(object_a, i);
		element_obj_b = bt_value_array_get(object_b, i);
		ret = bt_value_compare(element_obj_a, element_obj_b);

		if (ret) {
			if (ret > 0) {
				BT_DBG("Element #%d of array value objects differ\n", i);
			} else {
				BT_ERR("Cannot compare element #%d of array value objects\n", i);
			}

			BT_PUT(element_obj_a);
			BT_PUT(element_obj_b);
			goto end;
		}

		BT_PUT(element_obj_a);
		BT_PUT(element_obj_b);
	}

end:
	return ret;
}

static
int bt_value_map_compare(const struct bt_value *object_a,
		const struct bt_value *object_b)
{
	int ret = 0;
	GHashTableIter iter;
	gpointer key, element_obj_a;
	const struct bt_value_map *map_obj_a = BT_VALUE_TO_MAP(object_a);

	if (bt_value_map_size(object_a) != bt_value_map_size(object_b)) {
		BT_DBG("Map value objects A and B differ in size\n");
		ret = 1;
		goto end;
	}

	g_hash_table_iter_init(&iter, map_obj_a->ght);

	while (g_hash_table_iter_next(&iter, &key, &element_obj_a)) {
		struct bt_value *element_obj_b;
		const char *key_str = g_quark_to_string((unsigned long) key);

		element_obj_b = bt_value_map_get(object_b, key_str);
		ret = bt_value_compare(element_obj_a, element_obj_b);

		if (ret) {
			if (ret > 0) {
				BT_DBG("Element \"%s\" of map value objects differ\n", key_str);
			} else {
				BT_ERR("Cannot compare element \"%s\" of map value objects\n", key_str);
			}

			BT_PUT(element_obj_b);
			goto end;
		}

		BT_PUT(element_obj_b);
	}

end:
	return ret;
}

static
int (* const compare_funcs[])(const struct bt_value *,
		const struct bt_value *) = {
	[BT_VALUE_TYPE_NULL] =		bt_value_null_compare,
	[BT_VALUE_TYPE_BOOL] =		bt_value_bool_compare,
	[BT_VALUE_TYPE_INTEGER] =	bt_value_integer_compare,
	[BT_VALUE_TYPE_FLOAT] =		bt_value_float_compare,
	[BT_VALUE_TYPE_STRING] =	bt_value_string_compare,
	[BT_VALUE_TYPE_ARRAY] =		bt_value_array_compare,
	[BT_VALUE_TYPE_MAP] =		bt_value_map_compare,
};

void bt_value_null_freeze(struct bt_value *object)
{
}

void bt_value_generic_freeze(struct bt_value *object)
{
	object->is_frozen = true;
}

void bt_value_array_freeze(struct bt_value *object)
{
	int i;
	struct bt_value_array *typed_array_obj =
		BT_VALUE_TO_ARRAY(object);

	for (i = 0; i < typed_array_obj->garray->len; ++i) {
		struct bt_value *element_obj =
			g_ptr_array_index(typed_array_obj->garray, i);

		bt_value_freeze(element_obj);
	}

	bt_value_generic_freeze(object);
}

void bt_value_map_freeze(struct bt_value *object)
{
	GHashTableIter iter;
	gpointer key, element_obj;
	const struct bt_value_map *map_obj = BT_VALUE_TO_MAP(object);

	g_hash_table_iter_init(&iter, map_obj->ght);

	while (g_hash_table_iter_next(&iter, &key, &element_obj)) {
		bt_value_freeze(element_obj);
	}

	bt_value_generic_freeze(object);
}

static
void (* const freeze_funcs[])(struct bt_value *) = {
	[BT_VALUE_TYPE_NULL] =		bt_value_null_freeze,
	[BT_VALUE_TYPE_BOOL] =		bt_value_generic_freeze,
	[BT_VALUE_TYPE_INTEGER] =	bt_value_generic_freeze,
	[BT_VALUE_TYPE_FLOAT] =		bt_value_generic_freeze,
	[BT_VALUE_TYPE_STRING] =	bt_value_generic_freeze,
	[BT_VALUE_TYPE_ARRAY] =		bt_value_array_freeze,
	[BT_VALUE_TYPE_MAP] =		bt_value_map_freeze,
};

static
void bt_value_destroy(struct bt_object *obj)
{
	struct bt_value *value;

	value = container_of(obj, struct bt_value, base);
	assert(value->type != BT_VALUE_TYPE_UNKNOWN);

	if (bt_value_is_null(value)) {
		return;
	}

	if (destroy_funcs[value->type]) {
		destroy_funcs[value->type](value);
	}

	g_free(value);
}

enum bt_value_status bt_value_freeze(struct bt_value *object)
{
	enum bt_value_status err = BT_VALUE_STATUS_OK;

	if (!object) {
		BT_ERR_STR("Cannot freeze value object: invalid argument");
		err = BT_VALUE_STATUS_INVAL;
		goto end;
	}

	freeze_funcs[object->type](object);

end:
	return err;
}

bool bt_value_is_frozen(const struct bt_value *object)
{
	return object && object->is_frozen;
}

enum bt_value_type bt_value_get_type(const struct bt_value *object)
{
	if (!object) {
		return BT_VALUE_TYPE_UNKNOWN;
	}

	return object->type;
}

static
struct bt_value bt_value_create_base(enum bt_value_type type)
{
	struct bt_value base;

	base.type = type;
	base.is_frozen = false;
	bt_object_init(&base, bt_value_destroy);

	return base;
}

struct bt_value *bt_value_bool_create_init(bool val)
{
	struct bt_value_bool *bool_obj;

	bool_obj = g_new0(struct bt_value_bool, 1);
	if (!bool_obj) {
		BT_ERR_STR_FUNC(bt_log_str_oom);
		goto end;
	}

	bool_obj->base = bt_value_create_base(BT_VALUE_TYPE_BOOL);
	bool_obj->value = val;

end:
	return BT_VALUE_FROM_CONCRETE(bool_obj);
}

struct bt_value *bt_value_bool_create(void)
{
	struct bt_value *err = bt_value_bool_create_init(false);

	if (err) {
		BT_ERR_FUNC("Cannot create a default boolean value object\n");
	}

	return err;
}

struct bt_value *bt_value_integer_create_init(int64_t val)
{
	struct bt_value_integer *integer_obj;

	integer_obj = g_new0(struct bt_value_integer, 1);
	if (!integer_obj) {
		BT_ERR_STR_FUNC(bt_log_str_oom);
		goto end;
	}

	integer_obj->base = bt_value_create_base(BT_VALUE_TYPE_INTEGER);
	integer_obj->value = val;

end:
	return BT_VALUE_FROM_CONCRETE(integer_obj);
}

struct bt_value *bt_value_integer_create(void)
{
	struct bt_value *err = bt_value_integer_create_init(0);

	if (err) {
		BT_ERR_FUNC("Cannot create a default integer value object\n");
	}

	return err;
}

struct bt_value *bt_value_float_create_init(double val)
{
	struct bt_value_float *float_obj;

	float_obj = g_new0(struct bt_value_float, 1);
	if (!float_obj) {
		BT_ERR_STR_FUNC(bt_log_str_oom);
		goto end;
	}

	float_obj->base = bt_value_create_base(BT_VALUE_TYPE_FLOAT);
	float_obj->value = val;

end:
	return BT_VALUE_FROM_CONCRETE(float_obj);
}

struct bt_value *bt_value_float_create(void)
{
	struct bt_value *err = bt_value_float_create_init(0.);

	if (err) {
		BT_ERR_FUNC("Cannot create a default floating point number value object\n");
	}

	return err;
}

struct bt_value *bt_value_string_create_init(const char *val)
{
	struct bt_value_string *string_obj = NULL;

	if (!val) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		goto end;
	}

	string_obj = g_new0(struct bt_value_string, 1);
	if (!string_obj) {
		BT_ERR_STR_FUNC(bt_log_str_oom);
		goto end;
	}

	string_obj->base = bt_value_create_base(BT_VALUE_TYPE_STRING);
	string_obj->gstr = g_string_new(val);
	if (!string_obj->gstr) {
		BT_ERR_STR_FUNC(bt_log_str_oom);
		g_free(string_obj);
		string_obj = NULL;
		goto end;
	}

end:
	return BT_VALUE_FROM_CONCRETE(string_obj);
}

struct bt_value *bt_value_string_create(void)
{
	struct bt_value *err = bt_value_string_create_init("");

	if (err) {
		BT_ERR_FUNC("Cannot create a default string value object\n");
	}

	return err;
}

struct bt_value *bt_value_array_create(void)
{
	struct bt_value_array *array_obj;

	array_obj = g_new0(struct bt_value_array, 1);
	if (!array_obj) {
		BT_ERR_STR_FUNC(bt_log_str_oom);
		goto end;
	}

	array_obj->base = bt_value_create_base(BT_VALUE_TYPE_ARRAY);
	array_obj->garray = babeltrace_g_ptr_array_new_full(0,
		(GDestroyNotify) bt_put);
	if (!array_obj->garray) {
		BT_ERR_STR_FUNC(bt_log_str_oom);
		g_free(array_obj);
		array_obj = NULL;
		goto end;
	}

end:
	return BT_VALUE_FROM_CONCRETE(array_obj);
}

struct bt_value *bt_value_map_create(void)
{
	struct bt_value_map *map_obj;

	map_obj = g_new0(struct bt_value_map, 1);
	if (!map_obj) {
		BT_ERR_STR_FUNC(bt_log_str_oom);
		goto end;
	}

	map_obj->base = bt_value_create_base(BT_VALUE_TYPE_MAP);
	map_obj->ght = g_hash_table_new_full(g_direct_hash, g_direct_equal,
		NULL, (GDestroyNotify) bt_put);
	if (!map_obj->ght) {
		BT_ERR_STR_FUNC(bt_log_str_oom);
		g_free(map_obj);
		map_obj = NULL;
		goto end;
	}

end:
	return BT_VALUE_FROM_CONCRETE(map_obj);
}

enum bt_value_status bt_value_bool_get(const struct bt_value *bool_obj,
		bool *val)
{
	enum bt_value_status err = BT_VALUE_STATUS_OK;
	struct bt_value_bool *typed_bool_obj = BT_VALUE_TO_BOOL(bool_obj);

	if (!bool_obj || !bt_value_is_bool(bool_obj) || !val) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		err = BT_VALUE_STATUS_INVAL;
		goto end;
	}

	*val = typed_bool_obj->value;

end:
	return err;
}

enum bt_value_status bt_value_bool_set(struct bt_value *bool_obj, bool val)
{
	enum bt_value_status err = BT_VALUE_STATUS_OK;
	struct bt_value_bool *typed_bool_obj = BT_VALUE_TO_BOOL(bool_obj);

	if (!bool_obj || !bt_value_is_bool(bool_obj)) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		err = BT_VALUE_STATUS_INVAL;
		goto end;
	}

	if (bool_obj->is_frozen) {
		BT_ERR_STR_FUNC(bt_log_str_frozen);
		err = BT_VALUE_STATUS_FROZEN;
		goto end;
	}

	typed_bool_obj->value = val;

end:
	return err;
}

enum bt_value_status bt_value_integer_get(const struct bt_value *integer_obj,
		int64_t *val)
{
	enum bt_value_status err = BT_VALUE_STATUS_OK;
	struct bt_value_integer *typed_integer_obj =
		BT_VALUE_TO_INTEGER(integer_obj);

	if (!integer_obj || !bt_value_is_integer(integer_obj) || !val) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		err = BT_VALUE_STATUS_INVAL;
		goto end;
	}

	*val = typed_integer_obj->value;

end:
	return err;
}

enum bt_value_status bt_value_integer_set(struct bt_value *integer_obj,
		int64_t val)
{
	enum bt_value_status err = BT_VALUE_STATUS_OK;
	struct bt_value_integer *typed_integer_obj =
		BT_VALUE_TO_INTEGER(integer_obj);

	if (!integer_obj || !bt_value_is_integer(integer_obj)) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		err = BT_VALUE_STATUS_INVAL;
		goto end;
	}

	if (integer_obj->is_frozen) {
		BT_ERR_STR_FUNC(bt_log_str_frozen);
		err = BT_VALUE_STATUS_FROZEN;
		goto end;
	}

	typed_integer_obj->value = val;

end:
	return err;
}

enum bt_value_status bt_value_float_get(const struct bt_value *float_obj,
		double *val)
{
	enum bt_value_status err = BT_VALUE_STATUS_OK;
	struct bt_value_float *typed_float_obj =
		BT_VALUE_TO_FLOAT(float_obj);

	if (!float_obj || !bt_value_is_float(float_obj) || !val) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		err = BT_VALUE_STATUS_INVAL;
		goto end;
	}

	*val = typed_float_obj->value;

end:
	return err;
}

enum bt_value_status bt_value_float_set(struct bt_value *float_obj,
		double val)
{
	enum bt_value_status err = BT_VALUE_STATUS_OK;
	struct bt_value_float *typed_float_obj =
		BT_VALUE_TO_FLOAT(float_obj);

	if (!float_obj || !bt_value_is_float(float_obj)) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		err = BT_VALUE_STATUS_INVAL;
		goto end;
	}

	if (float_obj->is_frozen) {
		BT_ERR_STR_FUNC(bt_log_str_frozen);
		err = BT_VALUE_STATUS_FROZEN;
		goto end;
	}

	typed_float_obj->value = val;

end:
	return err;
}

enum bt_value_status bt_value_string_get(const struct bt_value *string_obj,
		const char **val)
{
	enum bt_value_status err = BT_VALUE_STATUS_OK;
	struct bt_value_string *typed_string_obj =
		BT_VALUE_TO_STRING(string_obj);

	if (!string_obj || !bt_value_is_string(string_obj) || !val) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		err = BT_VALUE_STATUS_INVAL;
		goto end;
	}

	*val = typed_string_obj->gstr->str;

end:
	return err;
}

enum bt_value_status bt_value_string_set(struct bt_value *string_obj,
		const char *val)
{
	enum bt_value_status err = BT_VALUE_STATUS_OK;
	struct bt_value_string *typed_string_obj =
		BT_VALUE_TO_STRING(string_obj);

	if (!string_obj || !bt_value_is_string(string_obj) || !val) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		err = BT_VALUE_STATUS_INVAL;
		goto end;
	}

	if (string_obj->is_frozen) {
		BT_ERR_STR_FUNC(bt_log_str_frozen);
		err = BT_VALUE_STATUS_FROZEN;
		goto end;
	}

	g_string_assign(typed_string_obj->gstr, val);

end:
	return err;
}

int bt_value_array_size(const struct bt_value *array_obj)
{
	int ret;
	struct bt_value_array *typed_array_obj =
		BT_VALUE_TO_ARRAY(array_obj);

	if (!array_obj || !bt_value_is_array(array_obj)) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		ret = BT_VALUE_STATUS_INVAL;
		goto end;
	}

	ret = (int) typed_array_obj->garray->len;

end:
	return ret;
}

bool bt_value_array_is_empty(const struct bt_value *array_obj)
{
	return bt_value_array_size(array_obj) == 0;
}

struct bt_value *bt_value_array_get(const struct bt_value *array_obj,
		size_t index)
{
	struct bt_value *ret;
	struct bt_value_array *typed_array_obj =
		BT_VALUE_TO_ARRAY(array_obj);

	if (!array_obj || !bt_value_is_array(array_obj) ||
			index >= typed_array_obj->garray->len) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		ret = NULL;
		goto end;
	}

	ret = g_ptr_array_index(typed_array_obj->garray, index);
	bt_get(ret);

end:
	return ret;
}

enum bt_value_status bt_value_array_append(struct bt_value *array_obj,
		struct bt_value *element_obj)
{
	enum bt_value_status err = BT_VALUE_STATUS_OK;
	struct bt_value_array *typed_array_obj =
		BT_VALUE_TO_ARRAY(array_obj);

	if (!array_obj || !bt_value_is_array(array_obj) || !element_obj) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		err = BT_VALUE_STATUS_INVAL;
		goto end;
	}

	if (array_obj->is_frozen) {
		BT_ERR_STR_FUNC(bt_log_str_frozen);
		err = BT_VALUE_STATUS_FROZEN;
		goto end;
	}

	g_ptr_array_add(typed_array_obj->garray, element_obj);
	bt_get(element_obj);

end:
	return err;
}

enum bt_value_status bt_value_array_append_bool(struct bt_value *array_obj,
		bool val)
{
	enum bt_value_status err;
	struct bt_value *bool_obj = NULL;

	bool_obj = bt_value_bool_create_init(val);
	err = bt_value_array_append(array_obj, bool_obj);
	bt_put(bool_obj);

	if (err) {
		BT_ERR_FUNC("Cannot append a boolean value object\n");
	}

	return err;
}

enum bt_value_status bt_value_array_append_integer(
		struct bt_value *array_obj, int64_t val)
{
	enum bt_value_status err;
	struct bt_value *integer_obj = NULL;

	integer_obj = bt_value_integer_create_init(val);
	err = bt_value_array_append(array_obj, integer_obj);
	bt_put(integer_obj);

	if (err) {
		BT_ERR_FUNC("Cannot append an integer value object\n");
	}

	return err;
}

enum bt_value_status bt_value_array_append_float(struct bt_value *array_obj,
		double val)
{
	enum bt_value_status err;
	struct bt_value *float_obj = NULL;

	float_obj = bt_value_float_create_init(val);
	err = bt_value_array_append(array_obj, float_obj);
	bt_put(float_obj);

	if (err) {
		BT_ERR_FUNC("Cannot append a floating point number value object\n");
	}

	return err;
}

enum bt_value_status bt_value_array_append_string(struct bt_value *array_obj,
		const char *val)
{
	enum bt_value_status err;
	struct bt_value *string_obj = NULL;

	string_obj = bt_value_string_create_init(val);
	err = bt_value_array_append(array_obj, string_obj);
	bt_put(string_obj);

	if (err) {
		BT_ERR_FUNC("Cannot append a string value object\n");
	}

	return err;
}

enum bt_value_status bt_value_array_append_empty_array(
		struct bt_value *array_obj)
{
	enum bt_value_status err;
	struct bt_value *empty_array_obj = NULL;

	empty_array_obj = bt_value_array_create();
	err = bt_value_array_append(array_obj, empty_array_obj);
	bt_put(empty_array_obj);

	if (err) {
		BT_ERR_FUNC("Cannot append an empty array value object\n");
	}

	return err;
}

enum bt_value_status bt_value_array_append_empty_map(struct bt_value *array_obj)
{
	enum bt_value_status err;
	struct bt_value *map_obj = NULL;

	map_obj = bt_value_map_create();
	err = bt_value_array_append(array_obj, map_obj);
	bt_put(map_obj);

	if (err) {
		BT_ERR_FUNC("Cannot append an empty map value object\n");
	}

	return err;
}

enum bt_value_status bt_value_array_set(struct bt_value *array_obj,
		size_t index, struct bt_value *element_obj)
{
	enum bt_value_status err = BT_VALUE_STATUS_OK;
	struct bt_value_array *typed_array_obj =
		BT_VALUE_TO_ARRAY(array_obj);

	if (!array_obj || !bt_value_is_array(array_obj) || !element_obj ||
			index >= typed_array_obj->garray->len) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		err = BT_VALUE_STATUS_INVAL;
		goto end;
	}

	if (array_obj->is_frozen) {
		BT_ERR_STR_FUNC(bt_log_str_frozen);
		err = BT_VALUE_STATUS_FROZEN;
		goto end;
	}

	bt_put(g_ptr_array_index(typed_array_obj->garray, index));
	g_ptr_array_index(typed_array_obj->garray, index) = element_obj;
	bt_get(element_obj);

end:
	return err;
}

int bt_value_map_size(const struct bt_value *map_obj)
{
	int ret;
	struct bt_value_map *typed_map_obj = BT_VALUE_TO_MAP(map_obj);

	if (!map_obj || !bt_value_is_map(map_obj)) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		ret = BT_VALUE_STATUS_INVAL;
		goto end;
	}

	ret = (int) g_hash_table_size(typed_map_obj->ght);

end:
	return ret;
}

bool bt_value_map_is_empty(const struct bt_value *map_obj)
{
	return bt_value_map_size(map_obj) == 0;
}

struct bt_value *bt_value_map_get(const struct bt_value *map_obj,
		const char *key)
{
	GQuark quark;
	struct bt_value *ret;
	struct bt_value_map *typed_map_obj = BT_VALUE_TO_MAP(map_obj);

	if (!map_obj || !bt_value_is_map(map_obj) || !key) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		ret = NULL;
		goto end;
	}

	quark = g_quark_from_string(key);
	ret = g_hash_table_lookup(typed_map_obj->ght, GUINT_TO_POINTER(quark));
	if (ret) {
		bt_get(ret);
	} else {
		BT_DBG_FUNC("Cannot get element mapped to key \"%s\"\n", key);
	}

end:
	return ret;
}

bool bt_value_map_has_key(const struct bt_value *map_obj, const char *key)
{
	bool has_key;
	GQuark quark;
	struct bt_value_map *typed_map_obj = BT_VALUE_TO_MAP(map_obj);

	if (!map_obj || !bt_value_is_map(map_obj) || !key) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		has_key = false;
		goto end;
	}

	quark = g_quark_from_string(key);
	has_key = babeltrace_g_hash_table_contains(typed_map_obj->ght,
		GUINT_TO_POINTER(quark));

end:
	return has_key;
}

enum bt_value_status bt_value_map_insert(struct bt_value *map_obj,
		const char *key, struct bt_value *element_obj)
{
	GQuark quark;
	enum bt_value_status err = BT_VALUE_STATUS_OK;
	struct bt_value_map *typed_map_obj = BT_VALUE_TO_MAP(map_obj);

	if (!map_obj || !bt_value_is_map(map_obj) || !key || !element_obj) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		err = BT_VALUE_STATUS_INVAL;
		goto end;
	}

	if (map_obj->is_frozen) {
		BT_ERR_STR_FUNC(bt_log_str_frozen);
		err = BT_VALUE_STATUS_FROZEN;
		goto end;
	}

	quark = g_quark_from_string(key);
	g_hash_table_insert(typed_map_obj->ght,
		GUINT_TO_POINTER(quark), element_obj);
	bt_get(element_obj);

end:
	return err;
}

enum bt_value_status bt_value_map_insert_bool(struct bt_value *map_obj,
		const char *key, bool val)
{
	enum bt_value_status err;
	struct bt_value *bool_obj = NULL;

	bool_obj = bt_value_bool_create_init(val);
	err = bt_value_map_insert(map_obj, key, bool_obj);
	bt_put(bool_obj);

	if (err) {
		BT_ERR_FUNC("Cannot insert a boolean value object mapped to key \"%s\"\n", key);
	}

	return err;
}

enum bt_value_status bt_value_map_insert_integer(struct bt_value *map_obj,
		const char *key, int64_t val)
{
	enum bt_value_status err;
	struct bt_value *integer_obj = NULL;

	integer_obj = bt_value_integer_create_init(val);
	err = bt_value_map_insert(map_obj, key, integer_obj);
	bt_put(integer_obj);

	if (err) {
		BT_ERR_FUNC("Cannot insert an integer value object mapped to key \"%s\"\n", key);
	}

	return err;
}

enum bt_value_status bt_value_map_insert_float(struct bt_value *map_obj,
		const char *key, double val)
{
	enum bt_value_status err;
	struct bt_value *float_obj = NULL;

	float_obj = bt_value_float_create_init(val);
	err = bt_value_map_insert(map_obj, key, float_obj);
	bt_put(float_obj);

	if (err) {
		BT_ERR_FUNC("Cannot insert a floating point number value object mapped to key \"%s\"\n", key);
	}

	return err;
}

enum bt_value_status bt_value_map_insert_string(struct bt_value *map_obj,
		const char *key, const char *val)
{
	enum bt_value_status err;
	struct bt_value *string_obj = NULL;

	string_obj = bt_value_string_create_init(val);
	err = bt_value_map_insert(map_obj, key, string_obj);
	bt_put(string_obj);

	if (err) {
		BT_ERR_FUNC("Cannot insert a string value object mapped to key \"%s\"\n", key);
	}

	return err;
}

enum bt_value_status bt_value_map_insert_empty_array(struct bt_value *map_obj,
		const char *key)
{
	enum bt_value_status err;
	struct bt_value *array_obj = NULL;

	array_obj = bt_value_array_create();
	err = bt_value_map_insert(map_obj, key, array_obj);
	bt_put(array_obj);

	if (err) {
		BT_ERR_FUNC("Cannot insert an empty array value object mapped to key \"%s\"\n", key);
	}

	return err;
}

enum bt_value_status bt_value_map_insert_empty_map(struct bt_value *map_obj,
		const char *key)
{
	enum bt_value_status err;
	struct bt_value *empty_map_obj = NULL;

	empty_map_obj = bt_value_map_create();
	err = bt_value_map_insert(map_obj, key, empty_map_obj);
	bt_put(empty_map_obj);

	if (err) {
		BT_ERR_FUNC("Cannot insert an empty map value object mapped to key \"%s\"\n", key);
	}

	return err;
}

enum bt_value_status bt_value_map_foreach(const struct bt_value *map_obj,
		bt_value_map_foreach_cb cb, void *data)
{
	enum bt_value_status err = BT_VALUE_STATUS_OK;
	gpointer key, element_obj;
	GHashTableIter iter;
	struct bt_value_map *typed_map_obj = BT_VALUE_TO_MAP(map_obj);

	if (!map_obj || !bt_value_is_map(map_obj) || !cb) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		err = BT_VALUE_STATUS_INVAL;
		goto end;
	}

	g_hash_table_iter_init(&iter, typed_map_obj->ght);

	while (g_hash_table_iter_next(&iter, &key, &element_obj)) {
		const char *key_str = g_quark_to_string((unsigned long) key);

		if (!cb(key_str, element_obj, data)) {
			BT_DBG_FUNC("Loop cancelled by user at key \"%s\"\n", key_str);
			err = BT_VALUE_STATUS_CANCELLED;
			break;
		}
	}

end:
	return err;
}

struct bt_value *bt_value_copy(const struct bt_value *object)
{
	struct bt_value *copy_obj = NULL;

	if (!object) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		goto end;
	}

	copy_obj = copy_funcs[object->type](object);
	if (!copy_obj) {
		BT_ERR_FUNC("Cannot copy value object\n");
	}

end:
	return copy_obj;
}

int bt_value_compare(const struct bt_value *object_a,
	const struct bt_value *object_b)
{
	int ret;

	if (!object_a || !object_b) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		ret = -1;
		goto end;
	}

	if (object_a->type != object_b->type) {
		BT_DBG_FUNC("Value objects A and B differ by type\n");
		ret = 1;
		goto end;
	}

	ret = compare_funcs[object_a->type](object_a, object_b);
	if (ret > 0) {
		BT_DBG_FUNC("Value objects differ\n");
	} else if (ret < 0) {
		BT_ERR_FUNC("Cannot compare value objects\n");
	}

end:
	return ret;
}
