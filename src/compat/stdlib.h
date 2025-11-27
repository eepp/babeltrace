/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2015 Michael Jeanson <mjeanson@efficios.com>
 */

#ifndef BABELTRACE_COMPAT_STDLIB_H
#define BABELTRACE_COMPAT_STDLIB_H

/*!
@file

@brief
    Temporary file functions (compatibility layer).

@ingroup compat

@code{.c}
#include "compat/stdlib.h"
@endcode
*/

/*
 * This compat wrapper can be removed and replaced by g_mkdtemp() when we bump
 * the requirement on glib to version 2.30.
 */

#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <glib.h>

#ifdef HAVE_MKDTEMP

static inline
char *bt_mkdtemp(char *templ)
{
	return mkdtemp(templ);
}

#elif GLIB_CHECK_VERSION(2,30,0)

#include <glib/gstdio.h>
static inline
char *bt_mkdtemp(char *templ)
{
	return g_mkdtemp(templ);
}

#else

/*!
@brief
    Wrapper of <code>mkdtemp()</code>.

See \bt_ext_man{mkdtemp,3,3}.

@param[in] templ
    See \bt_ext_man{mkdtemp,3,3}.

@returns
    See \bt_ext_man{mkdtemp,3,3}.
*/
static inline
char *bt_mkdtemp(char *templ)
{
	char *ret;

	ret = mktemp(templ);
	if (!ret) {
		goto end;
	}

	if(mkdir(templ, 0700)) {
		ret = NULL;
		goto end;
	}

	ret = templ;
end:
	return ret;
}

#endif

#endif /* BABELTRACE_COMPAT_STDLIB_H */
