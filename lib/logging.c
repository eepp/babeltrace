/*
 * Logging
 *
 * Babeltrace Library
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
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdlib.h>
#include <errno.h>
#include <babeltrace/logging-internal.h>

enum bt_log_level __bt_log_level = BT_LOG_LEVEL_ERROR;
const char * const bt_log_str_oom = "Out of memory";
const char * const bt_log_str_inval = "Invalid argument(s)";
const char * const bt_log_str_frozen = "Argument is frozen";

void bt_logging_set_level(enum bt_log_level log_level)
{
	__bt_log_level = log_level;
}

static
void __attribute__((constructor)) bt_logging_init(void)
{
	const char *log_level_env = getenv("BABELTRACE_LOG_LEVEL");
	unsigned long int log_level;
	char *endptr;

	/* Default log level to error */
	__bt_log_level = BT_LOG_LEVEL_ERROR;

	if (!log_level_env) {
		/* Keep default log level */
		return;
	}

	/* Try parsing the level as an integer first */
	log_level = strtoul(log_level_env, &endptr, 10);
	if (!errno && *endptr == '\0') {
		__bt_log_level = (enum bt_log_level) log_level;
		return;
	}

	/* Try parsing known strings */
	if (!strcmp(log_level_env, "DEBUG")) {
		__bt_log_level = BT_LOG_LEVEL_DEBUG;
	} else if (!strcmp(log_level_env, "WARNING")) {
		__bt_log_level = BT_LOG_LEVEL_WARNING;
	} else if (!strcmp(log_level_env, "ERROR")) {
		__bt_log_level = BT_LOG_LEVEL_ERROR;
	} else if (!strcmp(log_level_env, "DISABLED") ||
			!strcmp(log_level_env, "OFF")) {
		__bt_log_level = BT_LOG_LEVEL_DISABLED;
	}
}
