/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2017-2018 Philippe Proulx <pproulx@efficios.com>
 * Copyright 2015 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 */

#ifndef BABELTRACE_LIB_OBJECT_STRUCT_H
#define BABELTRACE_LIB_OBJECT_STRUCT_H

#include <stdbool.h>

struct bt_object;

typedef void (*bt_object_release_func)(struct bt_object *);
typedef void (*bt_object_parent_is_owner_listener_func)(
		struct bt_object *);

/*
 * Babeltrace object base.
 *
 * All objects publicly exposed by Babeltrace APIs must contain this
 * object as their first member.
 */
struct bt_object {
	/*
	 * True if this object is shared, that is, it has a reference
	 * count.
	 */
	bool is_shared;

	/*
	 * Current reference count.
	 */
	unsigned long long ref_count;

	/*
	 * Release function called when the object's reference count
	 * falls to zero. For an object with a parent, this function is
	 * bt_object_with_parent_release_func(), which calls
	 * `spec_release_func` below if there's no current parent.
	 */
	bt_object_release_func release_func;

	/*
	 * Specific release function called by
	 * bt_object_with_parent_release_func() or directly by a
	 * parent object.
	 */
	bt_object_release_func spec_release_func;

	/*
	 * Optional callback for an object with a parent, called by
	 * bt_object_with_parent_release_func() to indicate to the
	 * object that its parent is its owner.
	 */
	bt_object_parent_is_owner_listener_func
		parent_is_owner_listener_func;

	/*
	 * Optional parent object.
	 */
	struct bt_object *parent;
};

#endif /* BABELTRACE_LIB_OBJECT_STRUCT_H */
