#ifndef BABELTRACE_CTF_IR_EVENT_CLASS_H
#define BABELTRACE_CTF_IR_EVENT_CLASS_H

/*
 * BabelTrace - CTF IR: Event class
 *
 * Copyright 2013, 2014 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * Author: Jérémie Galarneau <jeremie.galarneau@efficios.com>
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
 *
 * The Common Trace Format (CTF) Specification is available at
 * http://www.efficios.com/ctf
*/

/*!
@defgroup event-class CTF IR event class
@ingroup ctf-ir
@brief CTF IR event class.

A CTF IR <strong><em>event class</em></strong> is a template for
creating concrete \link event.h CTF IR events\endlink.

An event class has the following properties:

  - A \b name, which must be unique amongst all the names of the
    event classes contained in the same
    \link stream-class.h CTF IR stream class\endlink.
  - A numeric \b ID, which also must be unique amongst all the IDs
    of the event classes contained in the same stream class.

A CTF IR event class owns two
\link field-types.h field types\endlink:

  - An optional <strong>event context</strong> field type, which
    represents the \c event.context CTF scope.
  - A mandatory <strong>event payload</strong> field type, which
    represents the \c event.fields CTF scope.

Both field types must be structure field types. The event payload
field type must not be empty.

In the Babeltrace CTF IR system, a \link trace.h trace\endlink
contains one or more \link stream-class.h stream classes\endlink,
and a stream class contains one or more event classes.

Before being able to create an event from an event class using
bt_ctf_event_create(), the prepared event class must be added to
a stream class by calling bt_ctf_stream_class_add_event_class().
This function, when successful, \em freezes the event class,
disallowing future changes of its properties and field types by
the user.

@sa event-class.h
@sa event
@sa streamclass

@author	Jérémie Galarneau <jeremie.galarneau@efficios.com>
@author	Philippe Proulx <pproulx@efficios.com>
*/

/*!
@file
@brief CTF IR event class type and functions.
@sa event-class
*/

#include <stdint.h>
#include <stddef.h>
#include <babeltrace/values.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup event-class
@{
*/

/*!
@struct bt_ctf_event_class
@brief A CTF IR event class.
@sa event-class
*/
struct bt_ctf_event_class;

struct bt_ctf_field;
struct bt_ctf_field_type;
struct bt_ctf_stream_class;

/*!
@brief Creates a default CTF IR event class named \p name­.

The event class is created \em without an event context
\link field-types.h field type\endlink and with an empty event
payload field type.

Upon creation, a unique event ID is assigned to the event class.
It is possible to change this ID afterwards using
bt_ctf_event_class_set_id().

On success, the event class's reference count is initialized to 1.
The user is responsible for calling bt_put() on it once done with
the event class.

@param[in] name	Name of the event class (copied on success)
@returns	Created event class, or \c NULL on error
*/
extern struct bt_ctf_event_class *bt_ctf_event_class_create(const char *name);

/*!
@brief Returns the CTF IR stream class containing the CTF IR event
	class \p event_class.

It is possible that the event class was not added to a stream class
yet, in which case \c NULL is returned. An event class can be added
to a stream class using bt_ctf_stream_class_add_event_class().

On success, the reference count of the returned stream class is
incremented.

@param[in] event_class	Event class of which to get the parent
			stream class
@returns		Stream class containing \p event_class,
			or \c NULL if \p event_class was not
			added to a stream class yet or on error

@sa bt_ctf_stream_class_add_event_class(): Add an event class to
	a stream class
*/
extern struct bt_ctf_stream_class *bt_ctf_event_class_get_stream_class(
		struct bt_ctf_event_class *event_class);

/*!
@name Properties functions
@{
*/

/*!
@brief Returns the name of the CTF IR event class \p event_class.

\p event_class remains the sole owner of the returned string.

@param[in] event_class	Event class of which to get the name
@returns		Name of event class \p event_class, or
			\c NULL on error
*/
extern const char *bt_ctf_event_class_get_name(
		struct bt_ctf_event_class *event_class);

/*!
@brief Returns the numeric ID of the CTF IR event class \p event_class.

@param[in] event_class	Event class of which to get the ID
@returns		ID of event class \p event_class, or a
			negative value on error

@sa bt_ctf_event_class_set_id(): Sets the numeric ID of a given
	event class
*/
extern int64_t bt_ctf_event_class_get_id(
		struct bt_ctf_event_class *event_class);

/*!
@brief Sets the numeric ID of the CTF IR event class
	\p event_class to \p id.

\p id must be unique amongst the IDs of all the event classes
of the stream class containing \p event_class.

@param[in] event_class	Event class of which to set the ID
@param[in] id		ID of the event class
@returns		0 on success, or a negative value on error

@sa bt_ctf_event_class_get_id(): Returns the numeric ID of a given
	event class
*/
extern int bt_ctf_event_class_set_id(
		struct bt_ctf_event_class *event_class, uint32_t id);

/*! @} */

/*!
@name Attribute functions
@{
*/

/*!
@brief Sets the attribute named \p name of the CTF IR event class
	\p event_class to the value \p value.

Valid attributes are:

  - <code>id</code>: must be an integer value object with a raw value
    &ge; 0. This represents the event class's ID and it can also be
    set using bt_ctf_event_class_set_id().
  - <code>name</code>: must be a string value object. This represents
    the name of the event class.
  - <code>loglevel</code>: must be an integer value object with a raw
    value &ge; 0. This represents the numeric log level associated
    with this event class. Log level values are application-specific.
  - <code>model.emf.uri</code>: must be a string value object. This
    represents the Eclipse Modeling Framework URI of the event class.

On success, the reference count of \p value is incremented.

@param[in] event_class	Event class of which to set an
			attribute
@param[in] name		Attribute name (copied on success)
@param[in] value	Attribute value
@returns		0 on success, or a negative value on error

@sa bt_ctf_event_class_get_attribute_value_by_name(): Returns the
	attribute of a given event class having a given name
*/
extern int bt_ctf_event_class_set_attribute(
		struct bt_ctf_event_class *event_class, const char *name,
		struct bt_value *value);

/*!
@brief Returns the number of attributes contained in the CTF IR event
	class \p event_class.

@param[in] event_class	Event class of which to get the number
			of contained attributes
@returns		Number of contained attributes in
			\p event_class, or a negative value on error

@sa bt_ctf_event_class_get_attribute_name(): Returns the name of
	the attribute of a given event class at a given index
@sa bt_ctf_event_class_get_attribute_value(): Returns the value of
	the attribute of a given event class at a given index
*/
extern int bt_ctf_event_class_get_attribute_count(
		struct bt_ctf_event_class *event_class);

/*!
@brief Returns the name of the attribute at the index \p index of the
	CTF IR event class \p event_class.

\p event_class remains the sole owner of the returned string.

@param[in] event_class	Event class of which to get the name
			of an attribute
@param[in] index	Attribute index
@returns		Attribute name, or \c NULL on error

@sa bt_ctf_event_class_get_attribute_value(): Returns the value of
	the attribute of a given event class at a given index
*/
extern const char *
bt_ctf_event_class_get_attribute_name(
		struct bt_ctf_event_class *event_class, int index);

/*!
@brief Returns the value of the attribute at the index \p index of the
	CTF IR event class \p event_class.

On success, the reference count of the returned value object is
incremented.

@param[in] event_class	Event class of which to get the value
			of an attribute
@param[in] index	Attribute index
@returns		Attribute value, or \c NULL on error

@sa bt_ctf_event_class_get_attribute_name(): Returns the name of
	the attribute of a given event class at a given index
*/
extern struct bt_value *
bt_ctf_event_class_get_attribute_value(struct bt_ctf_event_class *event_class,
		int index);

/*!
@brief Returns the value of the attribute named \p name of the CTF IR
	event class \p event_class.

On success, the reference count of the returned value object is
incremented.

@param[in] event_class	Event class of which to get the value
			of an attribute
@param[in] name		Attribute name
@returns		Attribute value, or \c NULL on error
*/
extern struct bt_value *
bt_ctf_event_class_get_attribute_value_by_name(
		struct bt_ctf_event_class *event_class, const char *name);

/*! @} */

/*!
@name Contained field types functions
@{
*/

/*!
@brief Returns the payload field type of the CTF IR event class
\p event_class.

On success, the reference count of the returned field type is
incremented.

@param[in] event_class	Event class of which to get the
			payload field type
@returns		Payload field type of \p event_class,
			or \c NULL on error

@sa bt_ctf_event_class_set_payload_type(): Sets the payload field
	type of a given event class
*/
extern struct bt_ctf_field_type *bt_ctf_event_class_get_payload_type(
		struct bt_ctf_event_class *event_class);

/*!
@brief Sets the payload field type of the CTF IR event class \p event_class
to \p payload_type.

\p payload_type must be a structure field type.

On success, the reference count of \p payload_type is incremented.

@param[in] event_class	Event class of which to set the
			payload field type
@param[in] payload_type	Payload field type
@returns		0 on success, or a negative value on error

@sa bt_ctf_event_class_get_payload_type(): Returns the payload field
	type of a given event class
*/
extern int bt_ctf_event_class_set_payload_type(
		struct bt_ctf_event_class *event_class,
		struct bt_ctf_field_type *payload_type);

/*!
@brief Adds a field type \p field_type named \p name to the payload
	field type of the CTF IR event class \p event_class.

This function is equivalent to getting the payload field type of
\p event_class using bt_ctf_event_class_get_payload_type() and adding
a field type to it using bt_ctf_field_type_structure_add_field().

On success, the reference count of \p field_type is incremented.

@param[in] event_class	Event class containing the payload field
			type in which to add \p field_type
@param[in] field_type	Field type to add to the payload field
			type of \p event_class
@param[in] name		Name of field type to add (copied on
			success)
@returns		0 on success, or a negative value on error
*/
extern int bt_ctf_event_class_add_field(struct bt_ctf_event_class *event_class,
		struct bt_ctf_field_type *field_type,
		const char *name);

/*!
@brief Returns the number of field types contained in the payload field
	type of the CTF IR event class \p event_class.

@param[in] event_class	Event class of which to get the number
			of field types in its payload field
			type
@returns		Number of field types in the payload
			field type of \p event_class, or a
			negative value on error
*/
extern int bt_ctf_event_class_get_field_count(
		struct bt_ctf_event_class *event_class);

/*!
@brief Returns the field type and its name of the payload field type
	of the CTF IR event class \p event_class at the index \p index.

On success, the field type is placed in \p *field_type and its
reference count is incremented. The field type's name is placed in
\p *name. \p event_class remains the sole owner of \p *name.

Both \p name and \p field_type can be \c NULL if the caller is not
interested in one of them.

@param[in] event_class	Event class of which to get a field
			type of its payload field type
@param[out] name	Name of the field type at the index
			\p index in the payload field type of
			\p event_class (can be \c NULL)
@param[out] field_type	Field type at the index \p index in the
			payload field type of \p event_class
			(can be \c NULL)
@param[in] index	Index of the payload field type's field
			type to get
@returns		0 on success, or a negative value on error
*/
extern int bt_ctf_event_class_get_field(struct bt_ctf_event_class *event_class,
		const char **name, struct bt_ctf_field_type **field_type,
		int index);

/*!
@brief Returns the field type named \p name in the payload field type
	of the CTF IR event class \p event_class.

On success, the reference count of the returned field type is
incremented.

@param[in] event_class	Event class of which to get a
			payload field type's field type
@param[in] name		Name of the payload field type's
			field type to get
@returns		Field type named \p name in the payload
			field type of \p event_class
*/
extern struct bt_ctf_field_type *bt_ctf_event_class_get_field_by_name(
		struct bt_ctf_event_class *event_class, const char *name);

/*!
@brief Returns the context field type of the CTF IR event class
	\p event_class.

This function returns \c NULL if \p event_class has no set
context field type.

On success, the reference count of the returned field type is
incremented.

@param[in] event_class	Event class of which to get the
			context field type
@returns		Context field type of \p event_class,
			or \c NULL if no context field type
			is set or on error

@sa bt_ctf_event_class_set_context_type(): Sets the context field
	type of a given event class
*/
extern struct bt_ctf_field_type *bt_ctf_event_class_get_context_type(
		struct bt_ctf_event_class *event_class);

/*!
@brief Sets the context field type of the CTF IR event class
	\p event_class to \p context_type.

\p context_type must be a structure field type.

On success, the reference count of \p context_type is incremented.

@param[in] event_class	Event class of which to set the
			context field type
@param[in] context_type	Context field type
@returns		0 on success, or a negative value
			on error

@sa bt_ctf_event_class_get_context_type(): Returns the context field
	type of a given event class
*/
extern int bt_ctf_event_class_set_context_type(
		struct bt_ctf_event_class *event_class,
		struct bt_ctf_field_type *context_type);

/*! @} */

/*! @} */

/*
 * Deprecated aliases of bt_get() and bt_put().
 *
 * See refs.h
*/
extern void bt_ctf_event_class_get(struct bt_ctf_event_class *event_class);
extern void bt_ctf_event_class_put(struct bt_ctf_event_class *event_class);

#ifdef __cplusplus
}
#endif

#endif /* BABELTRACE_CTF_IR_EVENT_CLASS_H*/
