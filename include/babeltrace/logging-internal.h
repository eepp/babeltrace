#ifndef BABELTRACE_LOGGING_INTERNAL_H
#define BABELTRACE_LOGGING_INTERNAL_H

/*
 * Babeltrace - Internal logging API
 *
 * Copyright 2016 Philippe Proulx <pproulx@efficios.com>
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

#include <stdio.h>
#include <babeltrace/logging.h>
#include <babeltrace/babeltrace-internal.h>

/* Current log level */
extern enum bt_log_level __bt_log_level;

/* Prefixes */
#define __ERROR_PREFIX		"*** BT Error"
#define __WARNING_PREFIX	"!!! BT Warning"
#define __DEBUG_PREFIX		"::: BT Debug"

/* Common logging fprintf() */
#define BT_LOG_FPRINTF(_fh, _prefix, _fmt, _args...)		\
	do {							\
		fprintf(_fh, _prefix ": " _fmt, ## _args);	\
	} while (0)

/* BT_LOG_FPRINTF() with function name */
#define BT_LOG_FPRINTF_FUNC(_fh, _prefix, _fmt, _args...)		\
	do {								\
		fprintf(_fh, _prefix ": In %s(): " _fmt, __func__, ## _args); \
	} while (0)

/* Error/warning/debug logging enabled */
#define BT_ERR_ENABLED		(__bt_log_level <= BT_LOG_LEVEL_ERROR)
#define BT_WARN_ENABLED		(__bt_log_level <= BT_LOG_LEVEL_WARNING)
#define BT_DBG_ENABLED		(__bt_log_level <= BT_LOG_LEVEL_DEBUG)

/* Error logging */
#define BT_ERR(_fmt, _args...)						\
	do {								\
		if (BT_ERR_ENABLED) {					\
			BT_LOG_FPRINTF(stderr, __ERROR_PREFIX, _fmt, ## _args); \
		}							\
	} while (0)

/* Error logging with function name */
#define BT_ERR_FUNC(_fmt, _args...)					\
	do {								\
		if (BT_ERR_ENABLED) {					\
			BT_LOG_FPRINTF_FUNC(stderr, __ERROR_PREFIX, _fmt, ## _args); \
		}							\
	} while (0)

/* Warning logging */
#define BT_WARN(_fmt, _args...)						\
	do {								\
		if (BT_WARN_ENABLED) {					\
			BT_LOG_FPRINTF(stderr, __WARNING_PREFIX, _fmt, ## _args); \
		}							\
	} while (0)

/* Warning logging with function name */
#define BT_WARN_FUNC(_fmt, _args...)					\
	do {								\
		if (BT_WARN_ENABLED) {					\
			BT_LOG_FPRINTF_FUNC(stderr, __WARNING_PREFIX, _fmt, ## _args); \
		}							\
	} while (0)

/* Debugging logging */
#define BT_DBG(_fmt, _args...)						\
	do {								\
		if (BT_DBG_ENABLED) {					\
			BT_LOG_FPRINTF(stderr, __DEBUG_PREFIX, _fmt, ## _args); \
		}							\
	} while (0)

/* Debugging logging, with function name */
#define BT_DBG_FUNC(_fmt, _args...)					\
	do {								\
		if (BT_DBG_ENABLED) {					\
			BT_LOG_FPRINTF_FUNC(stderr, __DEBUG_PREFIX, _fmt, ## _args); \
		}							\
	} while (0)

#define BT_ERR_STR(_str)		\
	do {				\
		BT_ERR("%s\n", _str);	\
	} while (0)

#define BT_ERR_STR_FUNC(_str)			\
	do {					\
		BT_ERR_FUNC("%s\n", _str);	\
	} while (0)

const char * const bt_log_str_oom;
const char * const bt_log_str_inval;
const char * const bt_log_str_frozen;

#endif /* BABELTRACE_LOGGING_INTERNAL_H */
