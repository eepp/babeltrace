#ifndef _BABELTRACE_VALUES_H
#define _BABELTRACE_VALUES_H

/*
 * Babeltrace - Value objects
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

/*!
@defgroup values Value objects
@ingroup api-ref
@brief Value objects.

This is a set of <strong><em>value objects</em></strong>. The
following functions allow to create, modify, and destroy:

  - \link bt_value_bool_create() Boolean value objects\endlink
  - \link bt_value_integer_create() Integer value objects\endlink
  - \link bt_value_float_create() Floating point number
    value objects\endlink
  - \link bt_value_string_create() String value objects\endlink
  - \link bt_value_array_create() Array value objects\endlink,
    containing zero or more value objects
  - \link bt_value_map_create() Map value objects\endlink, mapping
    string keys to value objects

As with any Babeltrace object, value objects have reference counts.
When \link bt_value_array_append() appending a value object to an
array value object\endlink, or \link bt_value_map_insert() inserting
a value object into a map value object\endlink, its reference count
is incremented, as well as when getting a value object back from
those structures. See \ref refs to learn more about reference counting
management of Babeltrace objects.

Most functions of this API return a <em>status code</em>, one of the
values of #bt_value_status.

A deep copy of any value object can be created using the
bt_value_copy() function. Two value objects can be compared
using bt_value_compare().

The internal code of Babeltrace is able to \em freeze value objects.
It is possible to get the raw value of a frozen value object, but
not to modify it. Reference counting still works on frozen value
objects. A frozen value object may be copied; the returned copy is
not frozen. A frozen value object may also be compared to another
value object.

The following matrix shows some categorized value object functions
to use for each value object type:

<table>
  <tr>
    <th>Function role &rarr;<br>
        Value object type &darr;
    <th>Create
    <th>Check type
    <th>Get value
    <th>Set value
  </tr>
  <tr>
    <th>Null
    <td>Use \ref bt_value_null variable
    <td>bt_value_is_null()
    <td>N/A
    <td>N/A
  </tr>
  <tr>
    <th>Boolean
    <td>bt_value_bool_create()<br>
        bt_value_bool_create_init()
    <td>bt_value_is_bool()
    <td>bt_value_bool_get()
    <td>bt_value_bool_set()
  </tr>
  <tr>
    <th>Integer
    <td>bt_value_integer_create()<br>
        bt_value_integer_create_init()
    <td>bt_value_is_integer()
    <td>bt_value_integer_get()
    <td>bt_value_integer_set()
  </tr>
  <tr>
    <th>Floating point number
    <td>bt_value_float_create()<br>
        bt_value_float_create_init()
    <td>bt_value_is_float()
    <td>bt_value_float_get()
    <td>bt_value_float_set()
  </tr>
  <tr>
    <th>String
    <td>bt_value_string_create()<br>
        bt_value_string_create_init()
    <td>bt_value_is_string()
    <td>bt_value_string_get()
    <td>bt_value_string_set()
  </tr>
  <tr>
    <th>Array
    <td>bt_value_array_create()
    <td>bt_value_is_array()
    <td>bt_value_array_get()
    <td>bt_value_array_append()<br>
        bt_value_array_append_bool()<br>
        bt_value_array_append_integer()<br>
        bt_value_array_append_float()<br>
        bt_value_array_append_string()<br>
        bt_value_array_append_empty_array()<br>
        bt_value_array_append_empty_map()<br>
        bt_value_array_set()
  </tr>
  <tr>
    <th>Map
    <td>bt_value_map_create()
    <td>bt_value_is_map()
    <td>bt_value_map_get()<br>
        bt_value_map_foreach()
    <td>bt_value_map_insert()<br>
        bt_value_map_insert_bool()<br>
        bt_value_map_insert_integer()<br>
        bt_value_map_insert_float()<br>
        bt_value_map_insert_string()<br>
        bt_value_map_insert_empty_array()<br>
        bt_value_map_insert_empty_map()
  </tr>
</table>

@sa values.h

@author	Philippe Proulx <pproulx@efficios.com>
*/

/*!
@file
@brief Value object types and functions.
@sa values
*/

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <babeltrace/ref.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup values
@{
*/

/*!
@brief Status codes.
*/
enum bt_value_status {
	/*! Value object cannot be altered because it's frozen. */
	BT_VALUE_STATUS_FROZEN =	-4,

	/*! Operation cancelled. */
	BT_VALUE_STATUS_CANCELLED =	-3,

	/*! Invalid arguments. */
	/* -22 for compatibility with -EINVAL */
	BT_VALUE_STATUS_INVAL =		-22,

	/*! General error. */
	BT_VALUE_STATUS_ERROR =		-1,

	/*! Okay, no error. */
	BT_VALUE_STATUS_OK =		0,
};

/*!
@struct bt_value
@brief A value object.
@sa values
*/
struct bt_value;

/**
@brief The null value object singleton.

This value object must be used anytime the null value object is needed.

The null value object singleton has no reference count; there's only
one. It is possible to compare any value object to the null value object
singleton to find out if it's the null value object, or otherwise by
using bt_value_is_null().

The null value object singleton is <em>always frozen</em> (see
bt_value_is_frozen()).

Functions of this API return this when the value object is actually
the null value object (of type #BT_VALUE_TYPE_NULL), whereas \c NULL
means an error of some sort.
*/
extern struct bt_value *bt_value_null;

/*!
@name Type information
@{
*/

/*!
@brief Value object type.
*/
enum bt_value_type {
	/*! Unknown value object, used as an error code. */
	BT_VALUE_TYPE_UNKNOWN =		-1,

	/*! Null value object. */
	BT_VALUE_TYPE_NULL =		0,

	/*! Boolean value object (holds \c true or \c false). */
	BT_VALUE_TYPE_BOOL =		1,

	/*! Integer value object (holds a signed 64-bit integer raw value). */
	BT_VALUE_TYPE_INTEGER =		2,

	/*! Floating point number value object (holds a \c double raw value). */
	BT_VALUE_TYPE_FLOAT =		3,

	/*! String value object. */
	BT_VALUE_TYPE_STRING =		4,

	/*! Array value object. */
	BT_VALUE_TYPE_ARRAY =		5,

	/*! Map value object. */
	BT_VALUE_TYPE_MAP =		6,
};

/*!
@brief Returns the type of the value object \p object.

@param[in] object	Value object of which to get the type
@returns		Type of value object \p object,
			or #BT_VALUE_TYPE_UNKNOWN on error

@sa #bt_value_type: Value object types
@sa bt_value_is_null(): Returns whether or not a given value object
	is the null value object
@sa bt_value_is_bool(): Returns whether or not a given value object
	is a boolean value object
@sa bt_value_is_integer(): Returns whether or not a given value
	object is an integer value object
@sa bt_value_is_float(): Returns whether or not a given value object
	is a floating point number value object
@sa bt_value_is_string(): Returns whether or not a given value object
	is a string value object
@sa bt_value_is_array(): Returns whether or not a given value object
	is an array value object
@sa bt_value_is_map(): Returns whether or not a given value object
	is a map value object
*/
extern enum bt_value_type bt_value_get_type(const struct bt_value *object);

/*!
@brief Returns whether or not the value object \p object is the null
	value object.

The only valid null value object is \ref bt_value_null.

An alternative to calling this function is directly comparing the value
object pointer to the \ref bt_value_null variable.

@param[in] object	Value object to check
@returns		\c true if \p object is the null value object

@sa bt_value_get_type(): Returns the type of a given value object
*/
static inline
bool bt_value_is_null(const struct bt_value *object)
{
	return bt_value_get_type(object) == BT_VALUE_TYPE_NULL;
}

/*!
@brief Returns whether or not the value object \p object is a boolean
	value object.

@param[in] object	Value object to check
@returns		\c true if \p object is a boolean value object

@sa bt_value_get_type(): Returns the type of a given value object
*/
static inline
bool bt_value_is_bool(const struct bt_value *object)
{
	return bt_value_get_type(object) == BT_VALUE_TYPE_BOOL;
}

/*!
@brief Returns whether or not the value object \p object is an integer
	value object.

@param[in] object	Value object to check
@returns		\c true if \p object is an integer value object

@sa bt_value_get_type(): Returns the type of a given value object
*/
static inline
bool bt_value_is_integer(const struct bt_value *object)
{
	return bt_value_get_type(object) == BT_VALUE_TYPE_INTEGER;
}

/*!
@brief Returns whether or not the value object \p object is a floating
	point number value object.

@param[in] object	Value object to check
@returns		\c true if \p object is a floating point
			number value object

@sa bt_value_get_type(): Returns the type of a given value object
*/
static inline
bool bt_value_is_float(const struct bt_value *object)
{
	return bt_value_get_type(object) == BT_VALUE_TYPE_FLOAT;
}

/*!
@brief Returns whether or not the value object \p object is a string
	value object.

@param[in] object	Value object to check
@returns		\c true if \p object is a string value object

@sa bt_value_get_type(): Returns the type of a given value object
*/
static inline
bool bt_value_is_string(const struct bt_value *object)
{
	return bt_value_get_type(object) == BT_VALUE_TYPE_STRING;
}

/*!
@brief Returns whether or not the value object \p object is an array
	value object.

@param[in] object	Value object to check
@returns		\c true if \p object is an array value object

@sa bt_value_get_type(): Returns the type of a given value object
*/
static inline
bool bt_value_is_array(const struct bt_value *object)
{
	return bt_value_get_type(object) == BT_VALUE_TYPE_ARRAY;
}

/*!
@brief Returns whether or not the value object \p object is a map value
	object.

@param[in] object	Value object to check
@returns		\c true if \p object is a map value object

@sa bt_value_get_type(): Returns the type of a given value object
*/
static inline
bool bt_value_is_map(const struct bt_value *object)
{
	return bt_value_get_type(object) == BT_VALUE_TYPE_MAP;
}

/*! @} */

/*!
@name Common value object functions
@{
*/

/*!
@brief Returns whether or not the value object \p object is frozen.

@param[in] object	Value object to check
@returns		\c true if \p object is frozen
*/
extern bool bt_value_is_frozen(const struct bt_value *object);

/*!
@brief Creates a deep copy of the value object \p object.

On success, the reference count of the returned value object is set
to 1, unless \p object is \ref bt_value_null.

Copying a frozen value object is allowed: the resulting copy is
<em>not frozen</em>.

@param[in] object	Value object to copy
@returns		Deep copy of \p object on success, or \c NULL
			on error
*/
extern struct bt_value *bt_value_copy(const struct bt_value *object);

/*!
@brief Recursively compares the value objects \p object_a and
	\p object_b and returns \c true if they have the same \em
	content (raw values).

@param[in] object_a	Value object A to compare to \p object_b
@param[in] object_b	Value object B to compare to \p object_a
@returns		\c true if \p object_a and \p object_b have the
			same content, or \c false if they differ or on
			error
*/
extern bool bt_value_compare(const struct bt_value *object_a,
		const struct bt_value *object_b);

/*! @} */

/*!
@name Boolean value object functions
@{
*/

/*!
@brief Creates a default boolean value object.

The created boolean value object's initial raw value is \c false.

On success, the reference count of the returned value object is
set to 1.

@returns	Created boolean value object on success, or \c NULL
		on error

@sa bt_value_bool_create_init(): Creates an initialized boolean
	value object
*/
extern struct bt_value *bt_value_bool_create(void);

/*!
@brief Creates a boolean value object with its initial raw value set to
	\p val.

On success, the reference count of the returned value object is
set to 1.

@param[in] val	Initial raw value
@returns	Created boolean value object on success, or
		\c NULL on error

@sa bt_value_bool_create(): Creates a default boolean value object
*/
extern struct bt_value *bt_value_bool_create_init(bool val);

/*!
@brief Returns the boolean raw value of the boolean value object
	\p bool_obj.

@param[in] bool_obj	Boolean value object of which to get the
			raw value
@param[out] val		Returned boolean raw value
@returns		One of #bt_value_status values

@sa bt_value_bool_set(): Sets the raw value of a boolean value object
*/
extern enum bt_value_status bt_value_bool_get(
		const struct bt_value *bool_obj, bool *val);

/*!
@brief Sets the boolean raw value of the boolean value object
	\p bool_obj to \p val.

@param[in] bool_obj	Boolean value object of which to set
			the raw value
@param[in] val		New boolean raw value
@returns		One of #bt_value_status values

@sa bt_value_bool_get(): Returns the raw value of a given boolean
	value object
*/
extern enum bt_value_status bt_value_bool_set(struct bt_value *bool_obj,
		bool val);

/*! @} */

/*!
@name Integer value object functions
@{
*/

/*!
@brief Creates a default integer value object.

The created integer value object's initial raw value is 0.

On success, the reference count of the returned value object is
set to 1.

@returns	Created integer value object on success, or \c NULL
		on error

@sa bt_value_integer_create_init(): Creates an initialized integer
	value object
*/
extern struct bt_value *bt_value_integer_create(void);

/*!
@brief Creates an integer value object with its initial raw value set to
	\p val.

On success, the reference count of the returned value object is
set to 1.

@param[in] val	Initial raw value
@returns	Created integer value object on success, or
		\c NULL on error

@sa bt_value_integer_create(): Creates a default integer
	value object
*/
extern struct bt_value *bt_value_integer_create_init(int64_t val);

/*!
@brief Returns the integer raw value of the integer value object
	\p integer_obj.

@param[in] integer_obj	Integer value object of which to get the
			raw value
@param[out] val		Returned integer raw value
@returns		One of #bt_value_status values

@sa bt_value_integer_set(): Sets the raw value of an integer value
	object
*/
extern enum bt_value_status bt_value_integer_get(
		const struct bt_value *integer_obj, int64_t *val);

/*!
@brief Sets the integer raw value of the integer value object
	\p integer_obj to \p val.

@param[in] integer_obj	Integer value object of which to set
			the raw value
@param[in] val		New integer raw value
@returns		One of #bt_value_status values

@sa bt_value_integer_get(): Returns the raw value of a given integer
	value object
*/
extern enum bt_value_status bt_value_integer_set(
		struct bt_value *integer_obj, int64_t val);

/*! @} */

/*!
@name Floating point number value object functions
@{
*/

/*!
@brief Creates a default floating point number value object.

The created floating point number value object's initial raw value is 0.

On success, the reference count of the returned value object is
set to 1.

@returns	Created floating point number value object on success,
		or \c NULL on error

@sa bt_value_float_create_init(): Creates an initialized floating
	point number value object
*/
extern struct bt_value *bt_value_float_create(void);

/*!
@brief Creates a floating point number value object with its initial raw
	value set to \p val.

On success, the reference count of the returned value object is
set to 1.

@param[in] val	Initial raw value
@returns	Created floating point number value object on
		success, or \c NULL on error

@sa bt_value_float_create(): Creates a default floating point number
	value object
*/
extern struct bt_value *bt_value_float_create_init(double val);

/*!
@brief Returns the floating point number raw value of the floating point
	number value object \p float_obj.

@param[in] float_obj	Floating point number value object of which to
			get the raw value
@param[out] val		Returned floating point number raw value
@returns		One of #bt_value_status values

@sa bt_value_float_set(): Sets the raw value of a given floating
	point number value object
*/
extern enum bt_value_status bt_value_float_get(
		const struct bt_value *float_obj, double *val);

/*!
@brief Sets the floating point number raw value of the floating point
	number value object \p float_obj to \p val.

@param[in] float_obj	Floating point number value object of which to set
			the raw value
@param[in] val		New floating point number raw value
@returns		One of #bt_value_status values

@sa bt_value_float_get(): Returns the raw value of a floating point
	number value object
*/
extern enum bt_value_status bt_value_float_set(
		struct bt_value *float_obj, double val);

/*! @} */

/*!
@name String value object functions
@{
*/

/*!
@brief Creates a default string value object.

The string value object is initially empty.

On success, the reference count of the returned value object is
set to 1.

@returns	Created string value object on success, or \c NULL
		on error

@sa bt_value_string_create_init(): Creates an initialized string
	value object
*/
extern struct bt_value *bt_value_string_create(void);

/*!
@brief Creates a string value object with its initial raw value set to
	\p val.

On success, \p val is copied and the reference count of the returned
value object is set to 1.

@param[in] val		Initial raw value (copied on success)
@returns		Created string value object on success, or
			\c NULL on error

@sa bt_value_float_create(): Creates a default string value object
*/
extern struct bt_value *bt_value_string_create_init(const char *val);

/*!
@brief Returns the string raw value of the string value object
	\p string_obj.

The returned string is placed in \p *val. It is valid as long as this
value object exists and is \em not modified. The ownership of the
returned string is \em not transferred to the caller.

@param[in] string_obj	String value object of which to get the
			raw value
@param[out] val		Returned string raw value
@returns		One of #bt_value_status values

@sa bt_value_string_set(): Sets the raw value of a string
	value object
*/
extern enum bt_value_status bt_value_string_get(
		const struct bt_value *string_obj, const char **val);

/*!
@brief Sets the string raw value of the string value object
	\p string_obj to \p val.

On success, \p val is copied.

@param[in] string_obj	String value object of which to set
			the raw value
@param[in] val		New string raw value (copied on success)
@returns		One of #bt_value_status values

@sa bt_value_string_get(): Returns the raw value of a given string
	value object
*/
extern enum bt_value_status bt_value_string_set(struct bt_value *string_obj,
		const char *val);

/**
 * @}
 */

/**
 * @name Array value object functions
 * @{
 */

/*!
@brief Creates an empty array value object.

On success, the reference count of the returned value object is
set to 1.

@returns	Created array value object on success, or \c NULL
		on error
*/
extern struct bt_value *bt_value_array_create(void);

/*!
@brief Returns the size of the array value object \p array_obj, that is,
	the number of value objects contained in \p array_obj.

@param[in] array_obj	Array value object of which to get the size
@returns		Array size if the return value is 0 (empty) or a
			positive value, or one of
			#bt_value_status negative values otherwise

@sa bt_value_array_is_empty(): Checks whether or not a given array
	value object is empty
*/
extern int bt_value_array_size(const struct bt_value *array_obj);

/*!
@brief Checks whether or not the array value object \p array_obj
	is empty.

@param[in] array_obj	Array value object to check
@returns		\c true if \p array_obj is empty

@sa bt_value_array_size(): Returns the size of a given array value
	object
*/
extern bool bt_value_array_is_empty(const struct bt_value *array_obj);

/*!
@brief Returns the value object contained in the array value object
	\p array_obj at the index \p index.

On success, the reference count of the returned value object is
incremented, unless it's \ref bt_value_null.

@param[in] array_obj	Array value object of which to get an element
@param[in] index	Index of value object to get
@returns		Value object at index \p index on
			success, or \c NULL on error
*/
extern struct bt_value *bt_value_array_get(const struct bt_value *array_obj,
		size_t index);

/*!
@brief Appends the value object \p element_obj to the array value
	object \p array_obj.

On success, the reference count of \p element_obj is incremented,
unless it's \ref bt_value_null.

@param[in] array_obj	Array value object in which to append
			\p element_obj
@param[in] element_obj	Value object to append
@returns		One of #bt_value_status values

@sa bt_value_array_append_bool(): Appends a boolean raw value to a
	given array value object
@sa bt_value_array_append_integer(): Appends an integer raw value
	to a given array value object
@sa bt_value_array_append_float(): Appends a floating point number
	raw value to a given array value object
@sa bt_value_array_append_string(): Appends a string raw value to a
	given array value object
@sa bt_value_array_append_empty_array(): Appends an empty array value
	object to a given array value object
@sa bt_value_array_append_empty_map(): Appends an empty map value
	object to a given array value object
*/
extern enum bt_value_status bt_value_array_append(struct bt_value *array_obj,
		struct bt_value *element_obj);

/*!
@brief Appends the boolean raw value \p val to the array value object
	\p array_obj.

This is a convenience function which creates the underlying boolean
value object before appending it.

@param[in] array_obj	Array value object in which to append \p val
@param[in] val		Boolean raw value to append to \p array_obj
@returns		One of #bt_value_status values

@sa bt_value_array_append(): Appends a value object to a given
	array value object
*/
extern enum bt_value_status bt_value_array_append_bool(
		struct bt_value *array_obj, bool val);

/*!
@brief Appends the integer raw value \p val to the array value object
	\p array_obj.

This is a convenience function which creates the underlying integer
value object before appending it.

@param[in] array_obj	Array value object in which to append \p val
@param[in] val		Integer raw value to append to \p array_obj
@returns		One of #bt_value_status values

@sa bt_value_array_append(): Appends a value object to a given
	array value object
*/
extern enum bt_value_status bt_value_array_append_integer(
		struct bt_value *array_obj, int64_t val);

/*!
@brief Appends the floating point number raw value \p val to the array
value object \p array_obj.

This is a convenience function which creates the underlying floating
point number value object before appending it.

@param[in] array_obj	Array value object in which to append \p val
@param[in] val		Floating point number raw value to append
			to \p array_obj
@returns		One of #bt_value_status values

@sa bt_value_array_append(): Appends a value object to a given
	array value object
*/
extern enum bt_value_status bt_value_array_append_float(
		struct bt_value *array_obj, double val);

/*!
@brief Appends the string raw value \p val to the array value object
	\p array_obj.

This is a convenience function which creates the underlying string value
object before appending it.

On success, \p val is copied.

@param[in] array_obj	Array value object in which to append \p val
@param[in] val		String raw value to append to \p array_obj
			(copied on success)
@returns		One of #bt_value_status values

@sa bt_value_array_append(): Appends a value object to a given
	array value object
*/
extern enum bt_value_status bt_value_array_append_string(
		struct bt_value *array_obj, const char *val);

/*!
@brief Appends an empty array value object to the array value object
	\p array_obj.

This is a convenience function which creates the underlying array value
object before appending it.

@param[in] array_obj	Array value object in which to append an
			empty array value object
@returns		One of #bt_value_status values

@sa bt_value_array_append(): Appends a value object to a given
	array value object
*/
extern enum bt_value_status bt_value_array_append_empty_array(
		struct bt_value *array_obj);

/*!
@brief Appends an empty map value object to the array value object
	\p array_obj.

This is a convenience function which creates the underlying map value
object before appending it.

@param[in] array_obj	Array value object in which to append an empty
			map value object
@returns		One of #bt_value_status values

@sa bt_value_array_append(): Appends a value object to a given
	array value object
*/
extern enum bt_value_status bt_value_array_append_empty_map(
		struct bt_value *array_obj);

/*!
@brief Replaces the value object contained in the array value object
	\p array_obj at the index \p index by \p element_obj.

On success, the replaced value object's reference count is
decremented, unless it's \ref bt_value_null, and the reference count
of \p element_obj is incremented, unless it's \ref bt_value_null.

@param[in] array_obj		Array value object in which to replace
				an element
@param[in] index		Index of value object to replace in
				\p array_obj
@param[in] element_obj		New value object at position \p index of
				\p array_obj
@returns			One of #bt_value_status values
*/
extern enum bt_value_status bt_value_array_set(struct bt_value *array_obj,
		size_t index, struct bt_value *element_obj);

/*! @} */

/*!
@name Map value object functions
@{
*/

/*!
@brief Creates an empty map value object.

On success, the reference count of the returned value object is
set to 1.

@returns	Created map value object on success, or \c NULL on error
*/
extern struct bt_value *bt_value_map_create(void);

/*!
@brief Returns the size of the map value object \p map_obj, that is, the
	number of entries contained in \p map_obj.

@param[in] map_obj	Map value object of which to get the size
@returns		Map size if the return value is 0 (empty) or a
			positive value, or one of
			#bt_value_status negative values otherwise

@sa bt_value_map_is_empty(): Checks whether or not a given map value
	object is empty
*/
extern int bt_value_map_size(const struct bt_value *map_obj);

/*!
@brief Checks whether or not the map value object \p map_obj is empty.

@param[in] map_obj	Map value object to check
@returns		\c true if \p map_obj is empty

@sa bt_value_map_size(): Returns the size of a given map value object
*/
extern bool bt_value_map_is_empty(const struct bt_value *map_obj);

/*!
@brief Returns the value object associated with the key \p key within
	the map value object \p map_obj.

On success, the reference count of the returned value object is
incremented, unless it's \ref bt_value_null.

@param[in] map_obj	Map value object of which to get an entry
@param[in] key		Key of the value object to get
@returns		Value object associated with the key \p key
			on success, or \c NULL on error
*/
extern struct bt_value *bt_value_map_get(const struct bt_value *map_obj,
		const char *key);

/*!
@brief User function type for bt_value_map_foreach().

\p object is a <em>weak reference</em>; it must be passed to bt_get()
in order to get a new reference.

This function must return \c true to continue the loop, or \c false
to break it.

@param[in] key		Key of map entry
@param[in] object	Value object of map entry (weak reference)
@param[in] data		User data
@returns		\c true to continue the loop, \c false to break
			it
*/
typedef bool (* bt_value_map_foreach_cb)(const char *key,
	struct bt_value *object, void *data);

/*!
@brief Calls a provided user function \p cb for each value object of the
	map value object \p map_obj.

The value object passed to the user function is a <b>weak reference</b>:
bt_get() must be called on it to obtain a new reference.

The key passed to the user function is only valid in the scope of
this user function call.

The user function must return \c true to continue the loop, or
\c false to break it.

@param[in] map_obj	Map value object on which to iterate
@param[in] cb		User function to call back
@param[in] data		User data passed to the user function
@returns		One of #bt_value_status values; more
			specifically, #BT_VALUE_STATUS_CANCELLED is
			returned if the loop was cancelled by the user
			function
*/
extern enum bt_value_status bt_value_map_foreach(
		const struct bt_value *map_obj, bt_value_map_foreach_cb cb,
		void *data);

/*!
@brief Returns whether or not the map value object \p map_obj contains
	an entry mapped to the key \p key.

@param[in] map_obj	Map value object to check
@param[in] key		Key to check
@returns		\c true if \p map_obj has an entry mapped to the
			key \p key, or \c false if it does not or
			on error
*/
extern bool bt_value_map_has_key(const struct bt_value *map_obj,
		const char *key);

/*!
@brief Inserts the value object \p element_obj mapped to the key
	\p key into the map value object \p map_obj.

If a value object is already mapped to \p key in \p map_obj, the
associated value object is first put, and then replaced by
\p element_obj.

On success, \p key is copied, and the reference count of
\p element_obj is incremented, unless it's \ref bt_value_null.

@param[in] map_obj	Map value object in which to insert
			\p element_obj
@param[in] key		Key (copied on success) to which the
			value object to insert is mapped
@param[in] element_obj	Value object to insert, mapped to the
			key \p key
@returns		One of #bt_value_status values

@sa bt_value_map_insert_bool(): Inserts a boolean raw value into a
	given map value object
@sa bt_value_map_insert_integer(): Inserts an integer raw value into
	a given map value object
@sa bt_value_map_insert_float(): Inserts a floating point number raw
	value into a given map value object
@sa bt_value_map_insert_string(): Inserts a string raw value into a
	given map value object
@sa bt_value_map_insert_empty_array(): Inserts an empty array value
	object into a given map value object
@sa bt_value_map_insert_empty_map(): Inserts an empty map value
	object into a given map value object
*/
extern enum bt_value_status bt_value_map_insert(
		struct bt_value *map_obj, const char *key,
		struct bt_value *element_obj);

/*!
@brief Inserts the boolean raw value \p val mapped to the key \p key
	into the map value object \p map_obj.

This is a convenience function which creates the underlying boolean
value object before inserting it.

On success, \p key is copied.

@param[in] map_obj	Map value object in which to insert \p val
@param[in] key		Key (copied on success) to which the boolean
			value object to insert is mapped
@param[in] val		Boolean raw value to insert, mapped to
			the key \p key
@returns		One of #bt_value_status values

@sa bt_value_map_insert(): Inserts a value object into a given map
	value object
*/
extern enum bt_value_status bt_value_map_insert_bool(
		struct bt_value *map_obj, const char *key, bool val);

/*!
@brief Inserts the integer raw value \p val mapped to the key \p key
	into the map value object \p map_obj.

This is a convenience function which creates the underlying integer
value object before inserting it.

On success, \p key is copied.

@param[in] map_obj	Map value object in which to insert \p val
@param[in] key		Key (copied on success) to which the integer
			value object to insert is mapped
@param[in] val		Integer raw value to insert, mapped to
			the key \p key
@returns		One of #bt_value_status values

@sa bt_value_map_insert(): Inserts a value object into a given map
	value object
*/
extern enum bt_value_status bt_value_map_insert_integer(
		struct bt_value *map_obj, const char *key, int64_t val);

/*!
@brief Inserts the floating point number raw value \p val mapped to
	the key \p key into the map value object \p map_obj.

This is a convenience function which creates the underlying floating
point number value object before inserting it.

On success, \p key is copied.

@param[in] map_obj	Map value object in which to insert \p val
@param[in] key		Key (copied on success) to which the floating
			point number value object to insert is mapped
@param[in] val		Floating point number raw value to insert,
			mapped to the key \p key
@returns		One of #bt_value_status values

@sa bt_value_map_insert(): Inserts a value object into a given map
	value object
*/
extern enum bt_value_status bt_value_map_insert_float(
		struct bt_value *map_obj, const char *key, double val);

/*!
@brief Inserts the string raw value \p val mapped to the key \p key
	into the map value object \p map_obj.

This is a convenience function which creates the underlying string value
object before inserting it.

On success, \p val and \p key are copied.

@param[in] map_obj	Map value object in which to insert \p val
@param[in] key		Key (copied on success) to which the string
			value object to insert is mapped
@param[in] val		String raw value to insert (copied on success),
			mapped to the key \p key
@returns		One of #bt_value_status values

@sa bt_value_map_insert(): Inserts a value object into a given map
	value object
*/
extern enum bt_value_status bt_value_map_insert_string(
		struct bt_value *map_obj, const char *key, const char *val);

/*!
@brief Inserts an empty array value object mapped to the key \p key
	into the map value object \p map_obj.

This is a convenience function which creates the underlying array value
object before inserting it.

On success, \p key is copied.

@param[in] map_obj	Map value object in which to insert an empty
			array value object
@param[in] key		Key (copied on success) to which the empty array
			value object to insert is mapped
@returns		One of #bt_value_status values

@sa bt_value_map_insert(): Inserts a value object into a given map
	value object
*/
extern enum bt_value_status bt_value_map_insert_empty_array(
		struct bt_value *map_obj, const char *key);

/*!
@brief Inserts an empty map value object mapped to the key \p key into
	the map value object \p map_obj.

This is a convenience function which creates the underlying map value
object before inserting it.

On success, \p key is copied.

@param[in] map_obj	Map value object in which to insert an empty
			map object
@param[in] key		Key (copied on success) to which the empty map
			value object to insert is mapped
@returns		One of #bt_value_status values

@sa bt_value_map_insert(): Inserts a value object into a given map
	value object
*/
extern enum bt_value_status bt_value_map_insert_empty_map(
		struct bt_value *map_obj, const char *key);

/*! @} */

/*! @} */

#ifdef __cplusplus
}
#endif

#endif /* _BABELTRACE_VALUES_H */
