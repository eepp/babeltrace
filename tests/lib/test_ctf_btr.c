/*
 * test_ctf_btr.c
 *
 * CTF binary type reader tests
 *
 * Copyright (c) 2015 EfficiOS Inc. and Linux Foundation
 * Copyright (c) 2015 Philippe Proulx <pproulx@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; under version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#include <babeltrace/ctf-ir/ctf-btr.h>
#include <assert.h>
#include <string.h>
#include "tap/tap.h"

static
void test_create_destroy(void)
{
	struct bt_ctf_btr *btr;
	struct bt_ctf_btr_cbs cbs;

	btr = bt_ctf_btr_create(cbs, NULL);
	ok(btr, "bt_ctf_btr_create() creates a BTR");
	bt_ctf_btr_destroy(btr);
	ok(btr, "bt_ctf_btr_destroy() does not crash");
}

int main(void)
{
	plan_no_plan();
	test_create_destroy();

	return 0;
}
