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
struct bt_packet_header_field;
struct bt_packet_context_field;
struct bt_stream;
struct bt_clock_value;

/* Functions */
struct bt_packet *bt_packet_create(struct bt_stream *stream);
struct bt_stream *bt_packet_borrow_stream(struct bt_packet *packet);
struct bt_field *bt_packet_borrow_header_field(struct bt_packet *packet);
int bt_packet_move_header_field(struct bt_packet *packet,
		struct bt_packet_header_field *header);
struct bt_field *bt_packet_borrow_context_field(struct bt_packet *packet);
int bt_packet_move_context_field(struct bt_packet *packet,
		struct bt_packet_context_field *context);
enum bt_clock_value_status bt_packet_borrow_default_beginning_clock_value(
		struct bt_packet *packet, struct bt_clock_value **BTOUTCLOCKVALUE);
int bt_packet_set_default_beginning_clock_value(struct bt_packet *packet,
		uint64_t value_cycles);
enum bt_clock_value_status bt_packet_borrow_default_end_clock_value(
		struct bt_packet *packet, struct bt_clock_value **BTOUTCLOCKVALUE);
int bt_packet_set_default_end_clock_value(struct bt_packet *packet,
		uint64_t value_cycles);
enum bt_property_availability bt_packet_get_discarded_event_counter_snapshot(
		struct bt_packet *packet, uint64_t *OUTPUTINIT);
int bt_packet_set_discarded_event_counter_snapshot(struct bt_packet *packet,
		uint64_t value);
enum bt_property_availability bt_packet_get_packet_counter_snapshot(
		struct bt_packet *packet, uint64_t *OUTPUTINIT);
int bt_packet_set_packet_counter_snapshot(struct bt_packet *packet,
		uint64_t value);
