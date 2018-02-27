#ifndef BABELTRACE_LIB_LOGGING_INTERNAL_H
#define BABELTRACE_LIB_LOGGING_INTERNAL_H

/*
 * Copyright 2017 Philippe Proulx <pproulx@efficios.com>
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

#include <babeltrace/babeltrace-internal.h>
#include <stdarg.h>

#define BT_LOG_OUTPUT_LEVEL bt_lib_log_level

#include <babeltrace/logging-internal.h>

extern
int bt_lib_log_level;

/*
 * The six macros below are logging statements which are specialized
 * for the Babeltrace library.
 *
 * `_fmt` is a typical printf()-style format string, with the following
 * limitations:
 *
 * * The `*` width specifier is not accepted.
 * * The `*` precision specifier is not accepted.
 * * The `j` and `t` length modifiers are not accepted.
 * * The `n` format specifier is not accepted.
 * * The format specifiers defined in <inttypes.h> are not accepted
 *   except for `PRId64`, `PRIu64`, `PRIx64`, `PRIX64`, `PRIo64`, and
 *   `PRIi64`.
 *
 * The Babeltrace extension conversion specifier is accepted. Its syntax
 * is:
 *
 * 1. Introductory `%!` sequence.
 *
 * 2. Optional: `:` to use a custom prefix for the printed fields. The
 *    prefix is specified as a `const char *` parameter before the main
 *    parameter.
 *
 * 3. Optional: `+` to print extended fields. This depends on the
 *    provided format specifier.
 *
 * 4. Format specifier.
 *
 * The available format specifiers are:
 *
 * `r`:
 *     Reference count information. The parameter is any Babeltrace
 *     object.
 *
 * `F`:
 *     Field type. The parameter type is `struct bt_field_type *`.
 *
 * `f`:
 *     Field. The parameter type is `struct bt_field *`.
 *
 * `P`:
 *     Field path. The parameter type is `struct bt_field_path *`.
 *
 * `E`:
 *     Event class. The parameter type is `struct bt_event_class *`.
 *
 * `e`:
 *     Event. The parameter type is `struct bt_event *`.
 *
 * `S`:
 *     Stream class. The parameter type is `struct bt_stream_class *`.
 *
 * `s`:
 *     Stream. The parameter type is `struct bt_stream *`.
 *
 * `a`:
 *     Packet. The parameter type is `struct bt_packet *`.
 *
 * `t`:
 *     Trace. The parameter type is `struct bt_trace *`.
 *
 * `K`:
 *     Clock class. The parameter type is `struct bt_clock_class *`.
 *
 * `k`:
 *     Clock value. The parameter type is `struct bt_clock_value *`.
 *
 * `v`:
 *     Value. The parameter type is `struct bt_value *`.
 *
 * `n`:
 *     Notification. The parameter type is `struct bt_notification *`.
 *
 * `i`:
 *     Notification iterator. The parameter type is
 *     `struct bt_notification_iterator *`.
 *
 * `C`:
 *     Component class. The parameter type is `struct bt_component_class *`.
 *
 * `c`:
 *     Component. The parameter type is `struct bt_component *`.
 *
 * `p`:
 *     Port. The parameter type is `struct bt_port *`.
 *
 * `x`:
 *     Connection. The parameter type is `struct bt_connection *`.
 *
 * `g`:
 *     Graph. The parameter type is `struct bt_graph *`.
 *
 * `u`:
 *     Plugin. The parameter type is `struct bt_plugin *`.
 *
 * `w`:
 *     CTF writer. The parameter type is `struct bt_ctf_writer *`.
 *
 * The string `, ` is printed between individual fields, but not after
 * the last one. Therefore you must put this separator in the format
 * string between two Babeltrace objects, e.g.:
 *
 *     BT_LIB_LOGW("Message: count=%u, %!E, %!+C", count, event_class,
 *                 clock_class);
 *
 * Example with a custom prefix:
 *
 *     BT_LIB_LOGI("Some message: %!:e, %!:+e", "ec-a-", event_class_a,
 *                 "ec-b-", event_class_b);
 *
 * It is safe to pass NULL as any Babeltrace object parameter.
 */
#define BT_LIB_LOGF(_fmt, ...) bt_lib_log(BT_LOG_FATAL, _BT_LOG_TAG, (_fmt), ##__VA_ARGS__)
#define BT_LIB_LOGE(_fmt, ...) bt_lib_log(BT_LOG_ERROR, _BT_LOG_TAG, (_fmt), ##__VA_ARGS__)
#define BT_LIB_LOGW(_fmt, ...) bt_lib_log(BT_LOG_WARN, _BT_LOG_TAG, (_fmt), ##__VA_ARGS__)
#define BT_LIB_LOGI(_fmt, ...) bt_lib_log(BT_LOG_INFO, _BT_LOG_TAG, (_fmt), ##__VA_ARGS__)
#define BT_LIB_LOGD(_fmt, ...) bt_lib_log(BT_LOG_DEBUG, _BT_LOG_TAG, (_fmt), ##__VA_ARGS__)
#define BT_LIB_LOGV(_fmt, ...) bt_lib_log(BT_LOG_VERBOSE, _BT_LOG_TAG, (_fmt), ##__VA_ARGS__)

/*
 * Log statement, specialized for the Babeltrace library.
 *
 * Use one of the BT_LIB_LOGF*() macros above instead of calling this
 * function directly.
 */
BT_HIDDEN
void bt_lib_log(int log_level, const char *tag, const char *fmt, ...);

#endif /* BABELTRACE_LIB_LOGGING_INTERNAL_H */
