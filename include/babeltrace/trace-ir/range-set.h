#ifndef BABELTRACE_TRACE_IR_RANGE_SET_H
#define BABELTRACE_TRACE_IR_RANGE_SET_H

/*
 * Copyright 2017-2019 Philippe Proulx <pproulx@efficios.com>
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

/* For bt_range_set_signed, bt_range_set_unsigned, bt_field_class */
#include <babeltrace/types.h>

/* For bt_range_set_status */
#include <babeltrace/trace-ir/range-set-const.h>

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

extern bt_range_set_unsigned *bt_range_set_unsigned_create(
		bt_field_class *field_class);

extern bt_range_set_status bt_range_set_unsigned_add_range(
		bt_range_set_unsigned *range_set,
		uint64_t lower, uint64_t upper);

extern bt_range_set_signed *bt_range_set_signed_create(
		bt_field_class *field_class);

extern bt_range_set_status bt_range_set_signed_add_range(
		bt_range_set_signed *range_set,
		int64_t lower, int64_t upper);

#ifdef __cplusplus
}
#endif

#endif /* BABELTRACE_TRACE_IR_RANGE_SET_H */
