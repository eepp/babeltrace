/*
 * Copyright 2019 Philippe Proulx <pproulx@efficios.com>
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

#define BT_LOG_TAG "RANGE-SET"
#include <babeltrace/lib-logging-internal.h>

#include <babeltrace/assert-pre-internal.h>
#include <babeltrace/trace-ir/range-set-const.h>
#include <babeltrace/trace-ir/range-set-internal.h>
#include <babeltrace/assert-internal.h>

struct bt_range_unsigned;
struct bt_range_signed;
struct bt_range_set_unsigned;
struct bt_range_set_signed;

uint64_t bt_range_unsigned_get_lower(const struct bt_range_unsigned *u_range)
{
	const struct bt_range *range = (const void *) u_range;

	BT_ASSERT_PRE_NON_NULL(range, "Range");
	return range->lower.u;
}

uint64_t bt_range_unsigned_get_upper(const struct bt_range_unsigned *u_range)
{
	const struct bt_range *range = (const void *) u_range;

	BT_ASSERT_PRE_NON_NULL(range, "Range");
	return range->upper.u;
}

int64_t bt_range_signed_get_lower(const struct bt_range_signed *i_range)
{
	const struct bt_range *range = (const void *) i_range;

	BT_ASSERT_PRE_NON_NULL(range, "Range");
	return range->lower.i;
}

int64_t bt_range_signed_get_upper(const struct bt_range_signed *range)
{
	const struct bt_range *range = (const void *) i_range;

	BT_ASSERT_PRE_NON_NULL(range, "Range");
	return range->lower.i;
}

uint64_t bt_range_set_unsigned_get_range_count(
		const bt_range_set_unsigned *u_range_set)
{
	const struct bt_range_set *range_set = (const void *) u_range_set;

	BT_ASSERT_PRE_NON_NULL(range_set, "Range set");
	return (uint64_t) range_set->ranges->len;
}

const struct bt_range_unsigned *bt_range_set_unsigned_borrow_range_by_index_const(
		const bt_range_set_unsigned *u_range_set, uint64_t index)
{
	const struct bt_range_set *range_set = (const void *) u_range_set;

	BT_ASSERT_PRE_NON_NULL(range_set, "Range set");
	BT_ASSERT_PRE_VALID_INDEX(index, range_set->ranges->len);
	return (const void *) BT_RANGE_SET_RANGE_AT_INDEX(range_set, index);
}

uint64_t bt_range_set_signed_get_range_count(
		const bt_range_set_signed *i_range_set)
{
	const struct bt_range_set *range_set = (const void *) i_range_set;

	BT_ASSERT_PRE_NON_NULL(range_set, "Range set");
	return (uint64_t) range_set->ranges->len;
}

const struct bt_range_signed *bt_range_set_signed_borrow_range_by_index_const(
		const bt_range_set_signed *i_range_set, uint64_t index)
{
	const struct bt_range_set *range_set = (const void *) i_range_set;

	BT_ASSERT_PRE_NON_NULL(range_set, "Range set");
	BT_ASSERT_PRE_VALID_INDEX(index, range_set->ranges->len);
	return (const void *) BT_RANGE_SET_RANGE_AT_INDEX(range_set, index);
}
