#ifndef BABELTRACE_CTF_IR_CLOCK_H
#define BABELTRACE_CTF_IR_CLOCK_H

/*
 * BabelTrace - CTF IR: Clock
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
 *
 * The Common Trace Format (CTF) Specification is available at
 * http://www.efficios.com/ctf
 */

/*!
@defgroup clock CTF IR clock
@ingroup ctf-ir
@brief CTF IR clock.

A CTF IR <strong><em>clock</em></strong> represents one clock source
of a \link trace.h CTF IR trace\endlink.

A clock has the following properties:

  - A \b name, which must be unique amongst all the names of the
    clocks contained in the same trace.
  - A \b frequency.

    The frequency is expressed in clock cycles per second (Hz).

    By default, the frequency of a clock is
    1&nbsp;000&nbsp;000&nbsp;000&nbsp;Hz (1&nbsp;GHz).
  - A time \b value in nanoseconds.

    See clock's real value equation below this list.

    When a clock is created, its value is 0.
  - A textual \b description.

    By default, a clock has no description.
  - A \b precision, or an absolute error of the clock value, in
    clock cycles.

    For example, if the precision property is set to 30, then a
    clock cycle value of 90 is the approximation which covers all
    the exact values between 60 cycles and 120 cycles.

    By default, the precision of a clock is 0.
  - An <strong>offset expressed in seconds</strong>.

    See clock's real value equation below this list.

    By default, the offset in seconds of a clock is 0.
  - An <strong>offset expressed in clock cycles</strong>.

    See clock's real value equation below this list.

    By default, the offset in clock cycles is 0.
  - An \b absolute flag.

    If a clock is marked as absolute, then this clock is considered
    a global reference amongst all the clocks of its trace parent.

    By default, a clock is not absolute.
  - A \b UUID.

    A clock's UUID is used to uniquely identify the clock amongst all
    the clocks of all the traces.

    By default, a clock has no UUID.

The real current value of a clock, in nanoseconds since
<a href="https://en.wikipedia.org/wiki/Unix_time">Epoch</a>, is
computed as follows:

\f$1^9\times\left(\text{offset in seconds}+\frac{\text{offset in cycles}+\text{value in cycles}}{\text{frequency}}\right)\f$

A clock is created using bt_ctf_clock_create() and added to a
\link trace.h trace\endlink using bt_ctf_trace_add_clock(). A clock
must be added to a trace before it is used in any other object.

A clock can be mapped to an integer
\link field-types.h field type\endlink by calling
bt_ctf_field_type_integer_set_mapped_clock(). Setting the value of
an integer \link fields.h field\endlink created out of such an
integer field type has the side effect of also updating the current
value of the mapped clock.

When a trace is frozen, all its clocks are frozen as well. This
happens the first time a \link stream-class.h stream class\endlink
is added to a trace by calling bt_ctf_trace_add_stream_class().
The user cannot change the properties of a frozen clock, except for
its current value in cycles.

The following matrix shows which functions to use to get and set
clock properties:

<table>
  <tr>
    <th>Function role &rarr;<br>
        Property &darr;
    <th>Get
    <th>Set
  </tr>
  <tr>
    <th>Name
    <td>bt_ctf_clock_get_name()
    <td>Set once on creation time
  </tr>
  <tr>
    <th>Frequency
    <td>bt_ctf_clock_get_frequency()
    <td>bt_ctf_clock_set_frequency()
  </tr>
  <tr>
    <th>Current value
    <td>bt_ctf_clock_get_time()
    <td>bt_ctf_clock_set_time()
  </tr>
  <tr>
    <th>Textual description
    <td>bt_ctf_clock_get_description()
    <td>bt_ctf_clock_set_description()
  </tr>
  <tr>
    <th>Precision
    <td>bt_ctf_clock_get_precision()
    <td>bt_ctf_clock_set_precision()
  </tr>
  <tr>
    <th>Offset in seconds
    <td>bt_ctf_clock_get_offset_s()
    <td>bt_ctf_clock_set_offset_s()
  </tr>
  <tr>
    <th>Offset in cycles
    <td>bt_ctf_clock_get_offset()
    <td>bt_ctf_clock_set_offset()
  </tr>
  <tr>
    <th>Absolute flag
    <td>bt_ctf_clock_get_is_absolute()
    <td>bt_ctf_clock_set_is_absolute()
  </tr>
  <tr>
    <th>UUID
    <td>bt_ctf_clock_get_uuid()
    <td>bt_ctf_clock_set_uuid()
  </tr>
</table>

@sa clock.h

@author	Jérémie Galarneau <jeremie.galarneau@efficios.com>
*/

/*!
@file
@brief CTF IR clock type and functions.
@sa clock
*/

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup clock
@{
*/

/*!
@struct bt_ctf_clock
@brief A CTF IR clock.
@sa clock
*/
struct bt_ctf_clock;

/*!
@brief Creates a default CTF IR clock named \p name­.

On success, the clock's reference count is initialized to 1. The user
is responsible for calling bt_put() on it once done with the clock.

@param[in] name	Name of the clock (copied on success)
@returns	Created clock, or \c NULL on error
*/
extern struct bt_ctf_clock *bt_ctf_clock_create(const char *name);

/*!
@brief Returns the name of the CTF IR clock \p clock.

On success, \p clock remains the sole owner of the returned value.

@param[in] clock	Clock of which to get the name
@returns		Name of \p clock, or \c NULL on error
*/
extern const char *bt_ctf_clock_get_name(struct bt_ctf_clock *clock);

/*!
@brief Returns the frequency, in clock cycles per second, of the CTF IR
	clock \p clock.

@param[in] clock	Clock of which to get the frequency
@returns		Frequency of \p clock, or \c -1ULL on error
*/
extern uint64_t bt_ctf_clock_get_frequency(struct bt_ctf_clock *clock);

/*!
@brief Sets the frequency, in clock cycles per second, of the CTF IR
	clock \p clock to \p frequency.

@param[in] clock	Clock of which to set the frequency
@param[in] frequency	Frequency
@returns		0 on success, or a negative value on error
*/
extern int bt_ctf_clock_set_frequency(struct bt_ctf_clock *clock,
		uint64_t frequency);

/*!
@brief Returns the current value, in nanoseconds, of the CTF IR clock
	\p clock.

@param[in] clock	Clock of which to get the current value
@returns		Current value of \p clock, or \c -1ULL on error
*/
extern uint64_t bt_ctf_clock_get_time(struct bt_ctf_clock *clock);

/*!
@brief Sets the current value, in nanoseconds, of the CTF IR clock
	\p clock to \p value.

@param[in] clock	Clock of which to set the current value
@param[in] value	Current value
@returns		0 on success, or a negative value on error
*/
extern int bt_ctf_clock_set_time(struct bt_ctf_clock *clock,
		uint64_t value);

/*!
@brief Returns the textual description of the CTF IR clock \p clock.

On success, \p clock remains the sole owner of the returned value.

@param[in] clock	Clock of which to get the description
@returns		Description of \p clock, or \c NULL on error
*/
extern const char *bt_ctf_clock_get_description(struct bt_ctf_clock *clock);

/*!
@brief Sets the textual description of the CTF IR clock \p clock to
	\p description.

On success, \p description is copied.

@param[in] clock		Clock of which to set the description
@param[in] description	Description (copied on success)
@returns			0 on success, or a negative value
				on error
*/
extern int bt_ctf_clock_set_description(struct bt_ctf_clock *clock,
		const char *description);

/*!
@brief Returns the precision, or absolute error on the clock's value, of
	the CTF IR clock \p clock.

The precision is expressed in clock cycles per second (Hz).

@param[in] clock	Clock of which to get the precision
@returns		Precision of \p clock, or \c -1ULL on error
*/
extern uint64_t bt_ctf_clock_get_precision(struct bt_ctf_clock *clock);

/*!
@brief Sets the precision, or absolute error on the clock's value,
	of the CTF IR clock.

The precision is expressed in clock cycles per second (Hz).

@param[in] clock	Clock of which to set the precision
@param[in] precision	Precision
@returns		0 on success, or a negative value on error
*/
extern int bt_ctf_clock_set_precision(struct bt_ctf_clock *clock,
		uint64_t precision);

/*!
@brief Returns the offset in seconds of the CTF IR clock \p clock.

@param[in] clock	Clock of which to get the offset in seconds
@returns		Offset in seconds of \p clock,
			or \c -1ULL on error
*/
extern uint64_t bt_ctf_clock_get_offset_s(struct bt_ctf_clock *clock);

/*!
@brief Sets the offset in seconds of the CTF IR clock \p clock to
	\p offset_s.

@param[in] clock	Clock of which to set the offset in seconds
@param[in] offset_s	Offset in seconds
@returns		0 on success, or a negative value on error
*/
extern int bt_ctf_clock_set_offset_s(struct bt_ctf_clock *clock,
		uint64_t offset_s);

/*!
@brief Returns the offset in clock cycles of the CTF IR clock \p clock.

@param[in] clock	Clock of which to get the offset in clock cycles
@returns		Offset in clock cycles of \p clock,
			or \c -1ULL on error
*/
extern uint64_t bt_ctf_clock_get_offset(struct bt_ctf_clock *clock);

/*!
@brief Sets the offset in cycles of the CTF IR clock \p clock to
	\p offset.

@param[in] clock	Clock of which to set the offset in cycles
@param[in] offset	Offset in cycles
@returns		0 on success, or a negative value on error
*/
extern int bt_ctf_clock_set_offset(struct bt_ctf_clock *clock,
		uint64_t offset);

/*!
@brief Returns whether or not the CTF IR clock \p clock is considered an
	absolute clock.

@param[in] clock	Clock to check
@returns		1 if \p clock is absolute, 0 if \p clock is not
			absolute, or a negative value on error
*/
extern int bt_ctf_clock_get_is_absolute(struct bt_ctf_clock *clock);

/*!
@brief Sets the absolute flag of the CTF IR clock \p clock to
	\p is_absolute.

@param[in] clock		Clock of which to set the absolute flag
@param[in] is_absolute	Absolute flag (1 if absolute, 0 if not
				absolute)
@returns			0 on success, or a negative value
				on error
*/
extern int bt_ctf_clock_set_is_absolute(struct bt_ctf_clock *clock,
		int is_absolute);

/*!
@brief Returns the UUID of the CTF IR clock \p clock.

On success, the returned pointer points to the 16 bytes of the
UUID of \p clock, which remains the sole owner of this array.

@param[in] clock	Clock of which to get the UUID
@returns		UUID of \p clock, or \c NULL on error
*/
extern const unsigned char *bt_ctf_clock_get_uuid(struct bt_ctf_clock *clock);

/*!
@brief Sets the UUID of the CTF IR clock \p clock to \p uuid.

\p uuid points to the 16 bytes of the UUID to set. On success,
this array is copied.

@param[in] clock	Clock of which to set the UUID
@param[in] uuid	UUID (copied on success)
@returns		0 on success, or a negative value on error
*/
extern int bt_ctf_clock_set_uuid(struct bt_ctf_clock *clock,
		const unsigned char *uuid);

/*!
@}
*/

/*
 * Deprecated aliases of bt_get() and bt_put().
 *
 * See refs.h
 */
extern void bt_ctf_clock_get(struct bt_ctf_clock *clock);
extern void bt_ctf_clock_put(struct bt_ctf_clock *clock);

#ifdef __cplusplus
}
#endif

#endif /* BABELTRACE_CTF_IR_CLOCK_H */
