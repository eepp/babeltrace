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

/*
 * For bt_range_signed, bt_range_unsigned, bt_range_set_signed,
 * bt_range_set_unsigned
 */
#include <babeltrace/types.h>

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum bt_range_set_status {
	BT_RANGE_SET_STATUS_OK = 0,
	BT_RANGE_SET_STATUS_NOMEM = -12,
} bt_range_set_status;

extern uint64_t bt_range_unsigned_get_lower(const bt_range_unsigned *range);

extern uint64_t bt_range_unsigned_get_upper(const bt_range_unsigned *range);

extern int64_t bt_range_signed_get_lower(const bt_range_signed *range);

extern int64_t bt_range_signed_get_upper(const bt_range_signed *range);

extern uint64_t bt_range_set_unsigned_get_range_count(
		const bt_range_set_unsigned *range_set);

extern const bt_range_unsigned *
bt_range_set_unsigned_borrow_range_by_index_const(
		const bt_range_set_unsigned *range_set, uint64_t index);

extern uint64_t bt_range_set_signed_get_range_count(
		const bt_range_set_signed *range_set);

extern const bt_range_signed *bt_range_set_signed_borrow_range_by_index_const(
		const bt_range_set_signed *range_set, uint64_t index);

extern void bt_range_set_unsigned_get_ref(
		const bt_range_set_unsigned *range_set);

extern void bt_range_set_unsigned_put_ref(
		const bt_range_set_unsigned *range_set);

#define BT_RANGE_SET_UNSIGNED_PUT_REF_AND_RESET(_var)	\
	do {						\
		bt_range_set_unsigned_put_ref(_var);	\
		(_var) = NULL;				\
	} while (0)

#define BT_RANGE_SET_UNSIGNED_MOVE_REF(_var_dst, _var_src)	\
	do {							\
		bt_range_set_unsigned_put_ref(_var_dst);	\
		(_var_dst) = (_var_src);			\
		(_var_src) = NULL;				\
	} while (0)

#ifdef __cplusplus
}
#endif

#endif /* BABELTRACE_TRACE_IR_RANGE_SET_H */
