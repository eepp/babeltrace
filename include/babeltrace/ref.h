#ifndef BABELTRACE_REF_H
#define BABELTRACE_REF_H

/*
 * BabelTrace: common reference counting
 *
 * Copyright (c) 2015 EfficiOS Inc. and Linux Foundation
 * Copyright (c) 2015 Philippe Proulx <pproulx@efficios.com>
 * Copyright (c) 2015 Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

/**
 * @file
 * @brief Common reference counting for all Babeltrace objects
 *
 * The macros and functions in this file are everything that is needed
 * to handle the reference counting of Babeltrace objects.
 *
 * All Babeltrace objects can be shared by multiple owners thanks to
 * reference counting. A function returning a Babeltrace object owned
 * by another one will increment its reference count so that the caller
 * becomes an owner too.
 *
 * When a Babeltrace object is created, its reference count is
 * initialized to 1. It is the user's responsibility to discard the
 * object when it's not needed anymore using bt_put().
 *
 * The two macros BT_PUT() and BT_MOVE() operate on \em variables
 * rather than pointer values. It is recommended to use BT_PUT() instead
 * of bt_put() to avoid "double-puts". For the same reason, it is
 * recommended to use BT_MOVE() instead of performing manual
 * reference moves.
 *
 * @author	Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * @author	Philippe Proulx <pproulx@efficios.com>
 * @bug		No known bugs
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Calls bt_put() on variable \p _var, then sets \p _var to \c NULL.
 *
 * This macro is considered safer than bt_put() because it makes sure
 * that the variable which used to contain a reference to a Babeltrace
 * object is set to \c NULL so that a future BT_PUT() or bt_put() will
 * not cause another, unwanted reference decrementation.
 *
 * @param[in,out] _var	Variable containing a Babeltrace object address
 *			(can be \c NULL)
 */
#define BT_PUT(_var)		\
	do {			\
		bt_put(_var);	\
		(_var) = NULL;	\
	} while (0)

/**
 * Transfers the ownership of a Babeltrace object from variable
 * \p _var_src to variable \p _var_dst.
 *
 * This macro implements the following common pattern:
 *
 *   1. Call bt_put() on \p _var_dst to make sure the previous reference
 *      held by \p _var_dst is discarded.
 *   2. Assign \p _var_src to \p _var_dst.
 *   3. Set \p _var_src to \c NULL to avoid future, unwanted reference
 *      decrementation of \p _var_src.
 *
 * \warning
 * Do not use this macro when both \p _var_dst and \p _var_src point
 * to the same Babeltrace object and when the reference count of this
 * object is 1. The initial call to bt_put() on \p _var_dst would
 * destroy the object and leave a dangling pointer in \p _var_dst.
 *
 * @param[in,out] _var_dst	Destination variable, possibly
 *				containing the address of a Babeltrace
 *				object to put first
 * @param[in,out] _var_src	Source variable containing the address
 *				of a Babeltrace object to move
 */
#define BT_MOVE(_var_dst, _var_src)		\
	do {					\
		bt_put(_var_dst);		\
		(_var_dst) = (_var_src);	\
		(_var_src) = NULL;		\
	} while (0)

/**
 * Increments the reference count of the Babeltrace object \p obj.
 *
 * @param[in] obj	Babeltrace object of which to get a new
 *			reference (can be \c NULL)
 * @returns		\p obj
 */
void *bt_get(void *obj);

/**
 * Decrements the reference count of the Babeltrace object \p obj.
 *
 * When the object's reference count reaches 0, the object can no longer
 * be accessed and is considered destroyed.
 *
 * \note
 * It is recommended to use the BT_PUT() macro instead of bt_put() since
 * the former is generally safer.
 *
 * @param[in] obj	Babeltrace object of which to get drop a
 *			reference (can be \c NULL)
 */
void bt_put(void *obj);

#ifdef __cplusplus
}
#endif

#endif /* BABELTRACE_REF_H */
