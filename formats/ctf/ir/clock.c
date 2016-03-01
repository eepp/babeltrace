/*
 * clock.c
 *
 * Babeltrace CTF IR - Clock
 *
 * Copyright 2013, 2014 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * Author: Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#include <babeltrace/ctf-ir/clock-internal.h>
#include <babeltrace/ctf-ir/utils.h>
#include <babeltrace/ref.h>
#include <babeltrace/ctf-writer/writer-internal.h>
#include <babeltrace/object-internal.h>
#include <babeltrace/compiler.h>
#include <babeltrace/logging-internal.h>
#include <inttypes.h>

static
void bt_ctf_clock_destroy(struct bt_object *obj);

BT_HIDDEN
struct bt_ctf_clock *_bt_ctf_clock_create(void)
{
	struct bt_ctf_clock *clock = g_new0(
		struct bt_ctf_clock, 1);

	if (!clock) {
		BT_ERR_STR(bt_log_str_oom);
		goto end;
	}

	clock->precision = 1;
	clock->frequency = 1000000000;
	bt_object_init(clock, bt_ctf_clock_destroy);
end:
	return clock;
}

BT_HIDDEN
int bt_ctf_clock_set_name(struct bt_ctf_clock *clock,
		const char *name)
{
	int ret = 0;

	if (bt_ctf_validate_identifier(name)) {
		BT_ERR_FUNC("Wrong clock object name (not a valid TSDL identifier): \"%s\"\n",
			name);
		ret = -1;
		goto end;
	}

	if (clock->name) {
		g_string_assign(clock->name, name);
	} else {
		clock->name = g_string_new(name);
		if (!clock->name) {
			BT_ERR_STR_FUNC(bt_log_str_oom);
			ret = -1;
			goto end;
		}
	}

end:
	return ret;
}

struct bt_ctf_clock *bt_ctf_clock_create(const char *name)
{
	int ret;
	struct bt_ctf_clock *clock = NULL;

	clock = _bt_ctf_clock_create();
	if (!clock) {
		BT_ERR_STR_FUNC("Cannot create clock object");
		goto error;
	}

	ret = bt_ctf_clock_set_name(clock, name);
	if (ret) {
		BT_ERR_FUNC("Cannot set clock object's initial name to \"%s\"\n",
			name);
		goto error;
	}

	ret = bt_uuid_generate(clock->uuid);
	if (ret) {
		BT_ERR_FUNC("Cannot generate UUID\n");
		goto error;
	}

	/*
	 * For backward compatibility reasons, a fresh clock can have
	 * a value because it could be added to a trace created by a
	 * CTF writer. As soon as this clock is added to a non-writer
	 * trace, then its value/time functions will be disabled.
	 */
	clock->has_value = 1;
	clock->uuid_set = 1;
	return clock;
error:
	BT_PUT(clock);
	return clock;
}

const char *bt_ctf_clock_get_name(struct bt_ctf_clock *clock)
{
	const char *ret = NULL;

	if (!clock) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		goto end;
	}

	if (clock->name) {
		ret = clock->name->str;
	}

end:
	return ret;
}

const char *bt_ctf_clock_get_description(struct bt_ctf_clock *clock)
{
	const char *ret = NULL;

	if (!clock) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		goto end;
	}

	if (clock->description) {
		ret = clock->description->str;
	}
end:
	return ret;
}

int bt_ctf_clock_set_description(struct bt_ctf_clock *clock, const char *desc)
{
	int ret = 0;

	if (!clock || !desc) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		ret = -1;
		goto end;
	}

	if (clock->frozen) {
		BT_ERR_STR_FUNC(bt_log_str_frozen);
		ret = -1;
		goto end;
	}

	clock->description = g_string_new(desc);
	ret = clock->description ? 0 : -1;
end:
	return ret;
}

uint64_t bt_ctf_clock_get_frequency(struct bt_ctf_clock *clock)
{
	uint64_t ret = -1ULL;

	if (!clock) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		goto end;
	}

	ret = clock->frequency;
end:
	return ret;
}

int bt_ctf_clock_set_frequency(struct bt_ctf_clock *clock, uint64_t freq)
{
	int ret = 0;

	if (!clock) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		ret = -1;
		goto end;
	}

	if (clock->frozen) {
		BT_ERR_STR_FUNC(bt_log_str_frozen);
		ret = -1;
		goto end;
	}

	clock->frequency = freq;
end:
	return ret;
}

uint64_t bt_ctf_clock_get_precision(struct bt_ctf_clock *clock)
{
	uint64_t ret = -1ULL;

	if (!clock) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		goto end;
	}

	ret = clock->precision;
end:
	return ret;
}

int bt_ctf_clock_set_precision(struct bt_ctf_clock *clock, uint64_t precision)
{
	int ret = 0;

	if (!clock) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		ret = -1;
		goto end;
	}

	if (clock->frozen) {
		BT_ERR_STR_FUNC(bt_log_str_frozen);
		ret = -1;
		goto end;
	}

	clock->precision = precision;
end:
	return ret;
}

int bt_ctf_clock_get_offset_s(struct bt_ctf_clock *clock, int64_t *offset_s)
{
	int ret = 0;

	if (!clock || !offset_s) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		ret = -1;
		goto end;
	}

	*offset_s = clock->offset_s;
end:
	return ret;
}

int bt_ctf_clock_set_offset_s(struct bt_ctf_clock *clock, int64_t offset_s)
{
	int ret = 0;

	if (!clock) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		ret = -1;
		goto end;
	}

	if (clock->frozen) {
		BT_ERR_STR_FUNC(bt_log_str_frozen);
		ret = -1;
		goto end;
	}

	clock->offset_s = offset_s;
end:
	return ret;
}

int bt_ctf_clock_get_offset(struct bt_ctf_clock *clock, int64_t *offset)
{
	int ret = 0;

	if (!clock || !offset) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		ret = -1;
		goto end;
	}

	*offset = clock->offset;
end:
	return ret;
}

int bt_ctf_clock_set_offset(struct bt_ctf_clock *clock, int64_t offset)
{
	int ret = 0;

	if (!clock) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		ret = -1;
		goto end;
	}

	if (clock->frozen) {
		BT_ERR_STR_FUNC(bt_log_str_frozen);
		ret = -1;
		goto end;
	}

	clock->offset = offset;
end:
	return ret;
}

int bt_ctf_clock_get_is_absolute(struct bt_ctf_clock *clock)
{
	int ret = -1;

	if (!clock) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		goto end;
	}

	ret = clock->absolute;
end:
	return ret;
}

int bt_ctf_clock_set_is_absolute(struct bt_ctf_clock *clock, int is_absolute)
{
	int ret = 0;

	if (!clock) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		ret = -1;
		goto end;
	}

	if (clock->frozen) {
		BT_ERR_STR_FUNC(bt_log_str_frozen);
		ret = -1;
		goto end;
	}

	clock->absolute = !!is_absolute;
end:
	return ret;
}

const unsigned char *bt_ctf_clock_get_uuid(struct bt_ctf_clock *clock)
{
	const unsigned char *ret;

	if (!clock || !clock->uuid_set) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		ret = NULL;
		goto end;
	}

	ret = clock->uuid;
end:
	return ret;
}

int bt_ctf_clock_set_uuid(struct bt_ctf_clock *clock, const unsigned char *uuid)
{
	int ret = 0;

	if (!clock || !uuid) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		ret = -1;
		goto end;
	}

	if (clock->frozen) {
		BT_ERR_STR_FUNC(bt_log_str_frozen);
		ret = -1;
		goto end;
	}

	memcpy(clock->uuid, uuid, sizeof(uuid_t));
	clock->uuid_set = 1;
end:
	return ret;
}

uint64_t ns_from_value(uint64_t frequency, uint64_t value)
{
	uint64_t ns;

	if (frequency == 1000000000) {
		ns = value;
	} else {
		ns = (uint64_t) ((1e9 * (double) value) / (double) frequency);
	}

	return ns;
}

int bt_ctf_clock_get_time(struct bt_ctf_clock *clock, int64_t *time)
{
	int ret = 0;

	if (!clock || !time) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		ret = -1;
		goto end;
	}


	if (!clock->has_value) {
		/*
		 * Clock belongs to a non-writer mode trace and thus
		 * this function is disabled.
		 */
		BT_ERR_STR_FUNC("Cannot get the time of a clock object which was added to a trace object not created by a writer object");
		goto end;
	}

	*time = (int64_t) ns_from_value(clock->frequency, clock->value);

end:
	return ret;
}

int bt_ctf_clock_set_time(struct bt_ctf_clock *clock, int64_t time)
{
	int ret = 0;
	int64_t value;

	/* Timestamps are strictly monotonic */
	if (!clock) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		ret = -1;
		goto end;
	}


	if (!clock->has_value) {
		/*
		 * Clock belongs to a non-writer mode trace and thus
		 * this function is disabled.
		 */
		BT_ERR_STR_FUNC("Cannot set the time of a clock object which was added to a trace object not created by a writer object");
		ret = -1;
		goto end;
	}

	/* Common case where cycles are actually nanoseconds */
	if (clock->frequency == 1000000000) {
		value = time;
	} else {
		value = (uint64_t) (((double) time *
		        (double) clock->frequency) / 1e9);
	}

	ret = bt_ctf_clock_set_value(clock, value);
	if (ret) {
		BT_ERR_FUNC("Cannot set clock object's value to %" PRId64 "\n",
			value);
	}
end:
	return ret;
}

uint64_t bt_ctf_clock_get_value(struct bt_ctf_clock *clock)
{
	uint64_t ret = -1ULL;

	if (!clock) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		goto end;
	}

	if (!clock->has_value) {
		/*
		 * Clock belongs to a non-writer mode trace and thus
		 * this function is disabled.
		 */
		BT_ERR_STR_FUNC("Cannot get the value of a clock object which was added to a trace object not created by a writer object");
		goto end;
	}

	ret = clock->value;
end:
	return ret;
}

int bt_ctf_clock_set_value(struct bt_ctf_clock *clock, uint64_t value)
{
	int ret = 0;

	if (!clock) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		ret = -1;
		goto end;
	}

	if (!clock->has_value) {
		/*
		 * Clock belongs to a non-writer mode trace and thus
		 * this function is disabled.
		 */
		BT_ERR_STR_FUNC("Cannot set the value of a clock object which was added to a trace object not created by a writer object");
		ret = -1;
		goto end;
	}

	/* Timestamps are strictly monotonic */
	if (value < clock->value) {
		BT_ERR_FUNC("New value (%" PRId64 ") is lesser than clock object's current value (%" PRId64 ")\n",
			value, clock->value);
		ret = -1;
		goto end;
	}

	clock->value = value;
end:
	return ret;
}

void bt_ctf_clock_get(struct bt_ctf_clock *clock)
{
	bt_get(clock);
}

void bt_ctf_clock_put(struct bt_ctf_clock *clock)
{
	bt_put(clock);
}

BT_HIDDEN
void bt_ctf_clock_freeze(struct bt_ctf_clock *clock)
{
	if (!clock) {
		return;
	}

	clock->frozen = 1;
}

BT_HIDDEN
void bt_ctf_clock_serialize(struct bt_ctf_clock *clock,
		struct metadata_context *context)
{
	unsigned char *uuid;

	if (!clock || !context) {
		return;
	}

	uuid = clock->uuid;
	g_string_append(context->string, "clock {\n");
	g_string_append_printf(context->string, "\tname = %s;\n",
		clock->name->str);
	g_string_append_printf(context->string,
		"\tuuid = \"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\";\n",
		uuid[0], uuid[1], uuid[2], uuid[3],
		uuid[4], uuid[5], uuid[6], uuid[7],
		uuid[8], uuid[9], uuid[10], uuid[11],
		uuid[12], uuid[13], uuid[14], uuid[15]);
	if (clock->description) {
		g_string_append_printf(context->string, "\tdescription = \"%s\";\n",
			clock->description->str);
	}

	g_string_append_printf(context->string, "\tfreq = %" PRIu64 ";\n",
		clock->frequency);
	g_string_append_printf(context->string, "\tprecision = %" PRIu64 ";\n",
		clock->precision);
	g_string_append_printf(context->string, "\toffset_s = %" PRIu64 ";\n",
		clock->offset_s);
	g_string_append_printf(context->string, "\toffset = %" PRIu64 ";\n",
		clock->offset);
	g_string_append_printf(context->string, "\tabsolute = %s;\n",
		clock->absolute ? "TRUE" : "FALSE");
	g_string_append(context->string, "};\n\n");
}

static
void bt_ctf_clock_destroy(struct bt_object *obj)
{
	struct bt_ctf_clock *clock;

	clock = container_of(obj, struct bt_ctf_clock, base);
	if (clock->name) {
		g_string_free(clock->name, TRUE);
	}

	if (clock->description) {
		g_string_free(clock->description, TRUE);
	}

	g_free(clock);
}

int64_t bt_ctf_clock_ns_from_value(struct bt_ctf_clock *clock, uint64_t value)
{
	int64_t ns = -1ULL;

	if (!clock) {
		BT_ERR_STR_FUNC(bt_log_str_inval);
		goto end;
	}

	/* Initialize nanosecond timestamp to clock's offset in seconds */
	ns = clock->offset_s * 1000000000;

	/* Add offset in cycles, converted to nanoseconds */
	ns += ns_from_value(clock->frequency, clock->offset);

	/* Add given value, converter to nanoseconds */
	ns += ns_from_value(clock->frequency, value);

end:
	return ns;
}
