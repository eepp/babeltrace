/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2020 Philippe Proulx <pproulx@efficios.com>
 */

#include <babeltrace2/babeltrace.h>

#include "common/assert.h"
#include "utils.h"

static
bt_field_class *get_uint_fc(bt_self_component *self_comp)
{
	bt_trace_class *tc = bt_trace_class_create(self_comp);
	bt_field_class *fc;

	BT_ASSERT(tc);
	fc = bt_field_class_integer_unsigned_create(tc);
	BT_ASSERT(fc);
	return fc;
}

static
void trigger_fc_int_set_field_value_range_size_gt_64(bt_self_component *self_comp)
{
	bt_field_class_integer_set_field_value_range(get_uint_fc(self_comp),
		65);
}

static
void trigger_fc_int_set_field_value_range_null(bt_self_component *self_comp)
{
	bt_field_class_integer_set_field_value_range(NULL, 23);
}

static
const struct ppc_trigger triggers[] = {
	PPC_TRIGGER_PRE_RUN_IN_COMP_CLS_INIT(
		"fc_int_set_field_value_range_size_gt_64",
		"Unsupported size for integer field class's field value range \\(minimum is 1, maximum is 64\\):.*size=65",
		trigger_fc_int_set_field_value_range_size_gt_64
	),
	PPC_TRIGGER_PRE_RUN_IN_COMP_CLS_INIT(
		"fc_int_set_field_value_range_null",
		"Field class is NULL",
		trigger_fc_int_set_field_value_range_null
	),
};

int main(int argc, const char *argv[])
{
	ppc_main(argc, argv, triggers, sizeof(triggers) / sizeof(*triggers));
	return 0;
}
