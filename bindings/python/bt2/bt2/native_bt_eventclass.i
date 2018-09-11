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

/* Type */
struct bt_event_class;
struct bt_field_type;
struct bt_stream_class;

/* Log levels */
enum bt_event_class_log_level {
	BT_EVENT_CLASS_LOG_LEVEL_EMERGENCY,
	BT_EVENT_CLASS_LOG_LEVEL_ALERT,
	BT_EVENT_CLASS_LOG_LEVEL_CRITICAL,
	BT_EVENT_CLASS_LOG_LEVEL_ERROR,
	BT_EVENT_CLASS_LOG_LEVEL_WARNING,
	BT_EVENT_CLASS_LOG_LEVEL_NOTICE,
	BT_EVENT_CLASS_LOG_LEVEL_INFO,
	BT_EVENT_CLASS_LOG_LEVEL_DEBUG_SYSTEM,
	BT_EVENT_CLASS_LOG_LEVEL_DEBUG_PROGRAM,
	BT_EVENT_CLASS_LOG_LEVEL_DEBUG_PROCESS,
	BT_EVENT_CLASS_LOG_LEVEL_DEBUG_MODULE,
	BT_EVENT_CLASS_LOG_LEVEL_DEBUG_UNIT,
	BT_EVENT_CLASS_LOG_LEVEL_DEBUG_FUNCTION,
	BT_EVENT_CLASS_LOG_LEVEL_DEBUG_LINE,
	BT_EVENT_CLASS_LOG_LEVEL_DEBUG,
};

/* Functions */
struct bt_event_class *bt_event_class_create(
		struct bt_stream_class *stream_class);

struct bt_event_class *bt_event_class_create_with_id(
		struct bt_stream_class *stream_class, uint64_t id);

struct bt_stream_class *bt_event_class_borrow_stream_class(
		struct bt_event_class *event_class);

const char *bt_event_class_get_name(struct bt_event_class *event_class);

int bt_event_class_set_name(struct bt_event_class *event_class,
		const char *name);

uint64_t bt_event_class_get_id(struct bt_event_class *event_class);

enum bt_property_availability bt_event_class_get_log_level(
		struct bt_event_class *event_class,
		enum bt_event_class_log_level *OUTPUTINIT);

int bt_event_class_set_log_level(struct bt_event_class *event_class,
		enum bt_event_class_log_level log_level);

const char *bt_event_class_get_emf_uri(
		struct bt_event_class *event_class);

int bt_event_class_set_emf_uri(struct bt_event_class *event_class,
		const char *emf_uri);

struct bt_field_type *bt_event_class_borrow_specific_context_field_type(
		struct bt_event_class *event_class);

int bt_event_class_set_specific_context_field_type(
		struct bt_event_class *event_class,
		struct bt_field_type *field_type);

struct bt_field_type *bt_event_class_borrow_payload_field_type(
		struct bt_event_class *event_class);

int bt_event_class_set_payload_field_type(
		struct bt_event_class *event_class,
		struct bt_field_type *field_type);
