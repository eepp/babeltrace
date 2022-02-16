/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2016-2018 Philippe Proulx <pproulx@efficios.com>
 *
 * The Common Trace Format (CTF) Specification is available at
 * http://www.efficios.com/ctf
 */

#ifndef BABELTRACE_TRACE_IR_RESOLVE_FIELD_PATH_INTERNAL
#define BABELTRACE_TRACE_IR_RESOLVE_FIELD_PATH_INTERNAL

#include "common/macros.h"
#include "resolve-field-xref.h"

BT_HIDDEN
enum bt_resolve_field_xref_status bt_resolve_field_paths(
		struct bt_field_class *field_class,
		struct bt_resolve_field_xref_context *ctx,
		const char *api_func);

#endif /* BABELTRACE_TRACE_IR_RESOLVE_FIELD_PATH_INTERNAL */
