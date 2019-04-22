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

/* From trace-const.h */

typedef enum bt_trace_status {
	BT_TRACE_STATUS_OK = 0,
	BT_TRACE_STATUS_NOMEM = -12,
} bt_trace_status;

typedef void (* bt_trace_destruction_listener_func)(
		const bt_trace *trace, void *data);

extern const bt_trace_class *bt_trace_borrow_class_const(
		const bt_trace *trace);

extern const char *bt_trace_get_name(const bt_trace *trace);

extern uint64_t bt_trace_get_stream_count(const bt_trace *trace);

extern const bt_stream *bt_trace_borrow_stream_by_index_const(
		const bt_trace *trace, uint64_t index);

extern const bt_stream *bt_trace_borrow_stream_by_id_const(
		const bt_trace *trace, uint64_t id);

extern bt_trace_status bt_trace_add_destruction_listener(
		const bt_trace *trace,
		bt_trace_destruction_listener_func listener,
		void *data, uint64_t *listener_id);

extern bt_trace_status bt_trace_remove_destruction_listener(
		const bt_trace *trace, uint64_t listener_id);

extern void bt_trace_get_ref(const bt_trace *trace);

extern void bt_trace_put_ref(const bt_trace *trace);

/* From trace.h */

extern bt_trace_class *bt_trace_borrow_class(bt_trace *trace);

extern bt_trace *bt_trace_create(bt_trace_class *trace_class);

extern bt_trace_status bt_trace_set_name(bt_trace *trace,
		const char *name);

extern bt_stream *bt_trace_borrow_stream_by_index(bt_trace *trace,
		uint64_t index);

extern bt_stream *bt_trace_borrow_stream_by_id(bt_trace *trace,
		uint64_t id);
