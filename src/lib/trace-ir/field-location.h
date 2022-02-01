/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2022 EfficiOS, Inc.
 *
 * The Common Trace Format (CTF) Specification is available at
 * http://www.efficios.com/ctf
 */

#ifndef BABELTRACE_TRACE_IR_FIELD_LOCATION_INTERNAL
#define BABELTRACE_TRACE_IR_FIELD_LOCATION_INTERNAL

#include "lib/object.h"
#include <babeltrace2/trace-ir/field-location.h>
#include <glib.h>

struct bt_field_location
{
	struct bt_object base;
	enum bt_field_location_scope scope;

	/* Array of `char *`, owned by this. */
	GPtrArray *items;
};

#endif /* BABELTRACE_TRACE_IR_FIELD_LOCATION_INTERNAL */
