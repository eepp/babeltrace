/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Philippe Proulx <pproulx@efficios.com>
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
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/* Types */
struct bt_clock_class;
struct bt_clock_value;

/* Clock class functions */
struct bt_clock_class *bt_clock_class_create(void);

const char *bt_clock_class_get_name(struct bt_clock_class *clock_class);

int bt_clock_class_set_name(struct bt_clock_class *clock_class,
	const char *name);

const char *bt_clock_class_get_description(
	struct bt_clock_class *clock_class);

int bt_clock_class_set_description(struct bt_clock_class *clock_class,
	const char *description);

uint64_t bt_clock_class_get_frequency(
	struct bt_clock_class *clock_class);

int bt_clock_class_set_frequency(struct bt_clock_class *clock_class,
	uint64_t freq);

uint64_t bt_clock_class_get_precision(
	struct bt_clock_class *clock_class);

int bt_clock_class_set_precision(struct bt_clock_class *clock_class,
	uint64_t precision);

void bt_clock_class_get_offset(struct bt_clock_class *clock_class,
	int64_t *OUTPUTINIT, uint64_t *OUTPUTINIT);

int bt_clock_class_set_offset(struct bt_clock_class *clock_class,
	int64_t seconds, uint64_t cycles);

bt_bool bt_clock_class_is_absolute(struct bt_clock_class *clock_class);

int bt_clock_class_set_is_absolute(struct bt_clock_class *clock_class,
	bt_bool is_absolute);

bt_uuid bt_clock_class_get_uuid(struct bt_clock_class *clock_class);

int bt_clock_class_set_uuid(struct bt_clock_class *clock_class,
	bt_uuid uuid);

int bt_clock_class_cycles_to_ns_from_origin(
	struct bt_clock_class *clock_class,
	uint64_t cycles, int64_t *OUTPUTINIT);
