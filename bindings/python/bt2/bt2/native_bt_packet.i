/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016-2017 Philippe Proulx <pproulx@efficios.com>
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
struct bt_packet;

/* Enum */
enum bt_packet_previous_packet_availability {
	BT_PACKET_PREVIOUS_PACKET_AVAILABILITY_AVAILABLE,
	BT_PACKET_PREVIOUS_PACKET_AVAILABILITY_NOT_AVAILABLE,
	BT_PACKET_PREVIOUS_PACKET_AVAILABILITY_NONE,
};

enum bt_packet_property_availability {
	BT_PACKET_PROPERTY_AVAILABILITY_AVAILABLE,
	BT_PACKET_PROPERTY_AVAILABILITY_NOT_AVAILABLE,
};

/* Functions */
struct bt_packet *bt_packet_create(
		struct bt_stream *stream,
		enum bt_packet_previous_packet_availability prev_packet_avail,
		struct bt_packet *prev_packet);
struct bt_stream *bt_packet_borrow_stream(
		struct bt_packet *packet);
struct bt_stream *bt_packet_get_stream(
		struct bt_packet *packet);
struct bt_field *bt_packet_borrow_header(
		struct bt_packet *packet);
struct bt_field *bt_packet_borrow_context(
		struct bt_packet *packet);
enum bt_packet_property_availability
bt_packet_borrow_default_beginning_clock_value(struct bt_packet *packet,
		struct bt_clock_value **BTOUTCLOCKVALUE);
enum bt_packet_property_availability
bt_packet_borrow_default_end_clock_value(struct bt_packet *packet,
		struct bt_clock_value **BTOUTCLOCKVALUE);
enum bt_packet_previous_packet_availability
bt_packet_get_previous_packet_availability(struct bt_packet *packet);
enum bt_packet_property_availability
bt_packet_borrow_previous_packet_default_end_clock_value(
			struct bt_packet *packet, struct bt_clock_value **BTOUTCLOCKVALUE);
enum bt_packet_property_availability bt_packet_get_discarded_event_counter(
		struct bt_packet *packet, uint64_t *OUTPUTINIT);
enum bt_packet_property_availability bt_packet_get_sequence_number(
		struct bt_packet *packet, uint64_t *OUTPUTINIT);
enum bt_packet_property_availability bt_packet_get_discarded_event_count(
		struct bt_packet *packet, uint64_t *OUTPUTINIT);
enum bt_packet_property_availability bt_packet_get_discarded_packet_count(
		struct bt_packet *packet, uint64_t *OUTPUTINIT);
