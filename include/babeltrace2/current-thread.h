#ifndef BABELTRACE_CURRENT_THREAD_H
#define BABELTRACE_CURRENT_THREAD_H

/*
 * Copyright (c) 2019 Philippe Proulx <pproulx@efficios.com>
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

#include <stdarg.h>

/*
 * For bt_error, bt_self_component, bt_self_component_class, and
 * bt_self_message_iterator
 */
#include <babeltrace2/types.h>

/* For bt_current_thread_status */
#include <babeltrace2/current-thread-const.h>

#ifdef __cplusplus
extern "C" {
#endif

extern
const bt_error *bt_current_thread_take_error(void);

extern
void bt_current_thread_clear_error(void);

extern
void bt_current_thread_move_error(const bt_error *error);

extern
bt_current_thread_status bt_current_thread_error_append_cause_from_unknown(
		const char *module_name, const char *func_name,
		uint64_t line_no, const char *msg_fmt, ...);

extern
bt_current_thread_status bt_current_thread_error_append_cause_from_component(
		bt_self_component *self_comp, const char *func_name,
		uint64_t line_no, const char *msg_fmt, ...);

extern
bt_current_thread_status
bt_current_thread_error_append_cause_from_component_class(
		bt_self_component_class *self_comp_class, const char *func_name,
		uint64_t line_no, const char *msg_fmt, ...);

extern
bt_current_thread_status
bt_current_thread_error_append_cause_from_message_iterator(
		bt_self_message_iterator *self_iter, const char *func_name,
		uint64_t line_no, const char *msg_fmt, ...);

#define BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_UNKNOWN(_module_name, _msg_fmt, ...) \
	bt_current_thread_error_append_cause_from_unknown( \
		(_module_name), __func__, __LINE__, (_msg_fmt), ##__VA_ARGS__)

#define BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(_self_comp, _msg_fmt, ...) \
	bt_current_thread_error_append_cause_from_component( \
		(_self_comp), __func__, __LINE__, (_msg_fmt), ##__VA_ARGS__)

#define BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT_CLASS(_self_cc, _msg_fmt, ...) \
	bt_current_thread_error_append_cause_from_component_class( \
		(_self_cc), __func__, __LINE__, (_msg_fmt), ##__VA_ARGS__)

#define BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_MESSAGE_ITERATOR(_self_iter, _msg_fmt, ...) \
	bt_current_thread_error_append_cause_from_component( \
		(_self_iter), __func__, __LINE__, (_msg_fmt), ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* BABELTRACE_CURRENT_THREAD_H */
