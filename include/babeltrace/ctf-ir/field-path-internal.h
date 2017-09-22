#ifndef BABELTRACE_CTF_IR_FIELD_PATH_INTERNAL
#define BABELTRACE_CTF_IR_FIELD_PATH_INTERNAL

/*
 * BabelTrace - CTF IR: Field path
 *
 * Copyright 2016 Philippe Proulx <pproulx@efficios.com>
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

#include <babeltrace/object-internal.h>
#include <assert.h>
#include <glib.h>

struct bt_field_path {
	struct bt_object base;
	enum bt_scope root;

	/*
	 * Array of integers (int) indicating the index in either
	 * structures, variants, arrays, or sequences that make up
	 * the path to a field type. -1 means the "current element
	 * of an array or sequence type".
	 */
	GArray *indexes;
};

BT_HIDDEN
struct bt_field_path *bt_field_path_create(void);

BT_HIDDEN
void bt_field_path_clear(struct bt_field_path *field_path);

BT_HIDDEN
struct bt_field_path *bt_field_path_copy(
		struct bt_field_path *path);

static inline
GString *bt_field_path_string(struct bt_field_path *path)
{
	GString *str = g_string_new(NULL);
	size_t i;

	assert(path);

	if (!str) {
		goto end;
	}

	g_string_append_printf(str, "[%s", bt_scope_string(path->root));

	for (i = 0; i < path->indexes->len; i++) {
		int index = g_array_index(path->indexes, int, i);

		g_string_append_printf(str, ", %d", index);
	}

	g_string_append(str, "]");

end:
	return str;
}

#endif /* BABELTRACE_CTF_IR_FIELD_PATH_INTERNAL */
