#ifndef BABELTRACE_CTF_IR_PACKET_READER_H
#define BABELTRACE_CTF_IR_PACKET_READER_H

/*
 * BabelTrace - CTF IR: Packet reader
 *
 * Copyright (c) 2015 EfficiOS Inc. and Linux Foundation
 * Copyright (c) 2015 Philippe Proulx <pproulx@efficios.com>
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
 * @file packet-reader.h
 *
 * This is an internal common API used by CTF reader plugins. It allows
 * a binary CTF packet to be deserialized as CTF IR data structures
 * using custom a custom back-end.
 *
 * This API only deals with \em individual packets, in that it does not
 * care about:
 *
 *   - sequences of packets
 *   - packet indexes
 *   - stream merging
 *
 * To use this API, you must first create a #bt_ctf_ir_packet_reader_ops
 * structure and fill it with the appropriate operations for your
 * specific back-end, and then pass it to
 * bt_ctf_ir_packet_reader_create() along with your user data.
 *
 * Call bt_ctf_ir_packet_reader_destroy() when you are done with the
 * packet reader.
 */

#include <stdint.h>
#include <stddef.h>
#include <babeltrace/ctf-ir/trace.h>
#include <babeltrace/ctf-ir/event-fields.h>
#include <babeltrace/ctf-ir/event.h>

/**
 * Packet reader API status code.
 */
enum bt_ctf_ir_packet_reader_status {
	/**
	 * End of packet.
	 *
	 * The packet reader function called by the user reached the
	 * end of the packet; there's no more events to be read.
	 */
	BT_CTF_IR_PACKET_READER_STATUS_EOP =	-4,

	/**
	 * There is no data available right now, try again later.
	 *
	 * Some condition resulted in the
	 * bt_ctf_ir_packet_reader_ops::get_next_buffer() user function
	 * not having access to any data now. You should retry calling
	 * the last called packet reader function once the situation is
	 * resolved.
	 */
	BT_CTF_IR_PACKET_READER_STATUS_AGAIN =	-3,

	/** Invalid argument. */
	BT_CTF_IR_PACKET_READER_STATUS_INVAL =	-2,

	/** General error. */
	BT_CTF_IR_PACKET_READER_STATUS_ERROR =	-1,

	/** Everything okay. */
	BT_CTF_IR_PACKET_READER_STATUS_OK =	0,
};

/**
 * Seek operation's reference position.
 */
enum bt_ctf_ir_packet_reader_seek_origin {
	/** Beginning of packet. */
	BT_CTF_IR_PACKET_READER_SEEK_SET = 0,
};

/**
 * Packet reader operations.
 *
 * Those user functions are called by the packet reader functions to
 * request back-end actions.
 */
struct bt_ctf_ir_packet_reader_ops {
	/**
	 * Returns the next buffer to be used by the packet reader to
	 * deserialize binary data.
	 *
	 * This function \em must be defined.
	 *
	 * The purpose of this function is to return a buffer of bytes
	 * to the packet reader, of a maximum of \p requested_len
	 * bytes. If this function cannot return a buffer of exactly
	 * \p requested_len bytes, it may return a smaller buffer. In
	 * either cases, \p buffer_len must be set to the returned
	 * buffer length.
	 *
	 * The returned buffer's ownership is the back-end defined by
	 * the user, in that it won't be freed by the packet reader
	 * functions. The returned buffer won't be modified by the
	 * packet reader functions.
	 *
	 * When this function is called for the first time for a given
	 * packet, the offset within the packet is 0. The next times
	 * this function is called, the returned buffer's offset within
	 * the complete packet must be the previous offset plus the
	 * last returned value of \p buffer_len.
	 *
	 * \p buffer_len must be set to one of the following values:
	 *
	 *   - <b>Positive value</b> (1 or more): size of returned
	 *     buffer.
	 *   - <b>0 or #BT_CTF_IR_PACKET_READER_STATUS_AGAIN</b>:
	 *     no data is available right now. In this case, the packet
	 *     reader function called by the user will return
	 *     #BT_CTF_IR_PACKET_READER_STATUS_AGAIN and it is the
	 *     user's responsability to make sure enough data becomes
	 *     available before calling the same packet reader function
	 *     again.
	 *   - <b>#BT_CTF_IR_PACKET_READER_STATUS_EOP</b>: the end of
	 *     the packet was reached, and no more events are available.
	 *     In this case, the packet reader function called by the
	 *     user will return #BT_CTF_IR_PACKET_READER_STATUS_EOP.
	 *   - <b>#BT_CTF_IR_PACKET_READER_STATUS_ERROR</b>: a fatal
	 *     error occured during this operation. In this case, the
	 *     packet reader function called by the user will return
	 *     #BT_CTF_IR_PACKET_READER_STATUS_ERROR.
	 *
	 * If \p buffer_len is not set to a positive value, this
	 * function's return value (buffer address) is not considered.
	 *
	 * @param requested_len	Requested buffer length (bytes)
	 * @param buffer_len	Returned buffer's length, or a status
	 * 			code (see description above)
	 * @param data		User data
	 * @returns		Buffer address, with at least
	 * 			\p buffer_len bytes available if
	 *			\p buffer_len is positive
	 */
	const void *(* get_next_buffer)(size_t requested_len,
		int* allocated_len, void *data);

	/**
	 * Moves the current packet offset.
	 *
	 * Set this member to \c NULL if seek operations are not
	 * possible for the given back-end.
	 *
	 * This function shall set the byte offset within the current
	 * packet, as follows:
	 *
	 *   - If \p whence is #BT_CTF_IR_PACKET_READER_SEEK_SET,
	 *     the byte offset within the packet shall be set to
	 *     \p offset bytes.
	 *
	 * Currently, only #BT_CTF_IR_PACKET_READER_SEEK_SET is valid
	 * for \p whence.
	 *
	 * Upon successful completion, the resulting offset, as measured
	 * in bytes from the beginning of the packet, shall be returned.
	 * If the resulting packet offset is invalid for the given
	 * back-end, #BT_CTF_IR_PACKET_READER_STATUS_INVAL must be
	 * returned, which cancels the seek operation. In this case,
	 * the packet offset shall remain unchanged.
	 *
	 * @param offset	Number of bytes to offset from origin
	 * @param whence	Reference position
	 * @param data		User data
	 * @returns		Resulting offset, as measured in bytes,
	 * 			from the beginning of the packet, or
	 * 			#BT_CTF_IR_PACKET_READER_STATUS_INVAL
	 * 			when it is not possible to seek
	 */
	int (* seek)(int offset,
		enum bt_ctf_ir_packet_reader_seek_origin whence,
		void *data);
};

/* Packet reader context */
struct bt_ctf_ir_packet_reader_ctx {
	/* back-end operations */
	struct bt_ctf_ir_packet_reader_ops ops;

	/* current offset in packet (bits) */
	size_t bit_offset;

	/* user data */
	void *data;
};

/**
 * Creates a packet reader.
 *
 * When created, the packet offset is assumed to be 0.
 *
 * Upon successful completion, the reference count of \p trace is
 * incremented.
 *
 * @param trace			Trace to read
 * @param max_request_len	Maximum buffer length to request to
 * 				bt_ctf_ir_packet_reader_ops::get_next_buffer()
 * 				at a time; set to 0 for the
 * 				implementation to make this decision
 * @param ops			Back-end operations
 * @param data			User data (given to back-end operations)
 * @returns			New packet reader context on success, or
 * 				\c NULL on error
 */
BT_HIDDEN
struct bt_ctf_ir_packet_reader_ctx *bt_ctf_ir_packet_reader_create(
	struct bt_ctf_trace *trace, size_t max_request_len,
	struct bt_ctf_ir_packet_reader_ops ops, void *data);

/**
 * Destroys a packet reader, freeing all internal resources.
 *
 * The registered trace's reference count is decremented.
 *
 * @param ctx	Packet reader context
 */
BT_HIDDEN
void bt_ctf_ir_packet_reader_destroy(struct bt_ctf_ir_packet_reader_ctx *ctx);

/**
 * Resets a packet reader.
 *
 * The packet reader's offset is reset to 0, so that the next call to
 * bt_ctf_ir_packet_reader_ops::get_next_buffer() is assumed to be
 * at offset 0.
 *
 * This function is used to switch the back-end's data source to a
 * new packet behind the scenes, avoiding the allocation of a new
 * packet reader sharing the same trace, back-end operations, and
 * user data.
 *
 * @param ctx	Packet reader context
 * @returns	One of #bt_ctf_ir_packet_reader_status values
 */
BT_HIDDEN
enum bt_ctf_ir_packet_reader_status bt_ctf_ir_packet_reader_reset(
	struct bt_ctf_ir_packet_reader_ctx *ctx);

/**
 * Returns the packet header.
 *
 * If the packet header is not decoded yet, it is first read and
 * decoded, then returned.
 *
 * Upon successful completion, the returned packet header's reference
 * count is incremented. The user is responsible for calling
 * bt_ctf_field_put() on it.
 *
 * @param ctx		Packet reader context
 * @param packet_header	Returned packet header
 * @returns		One of #bt_ctf_ir_packet_reader_status values
 */
enum bt_ctf_ir_packet_reader_status bt_ctf_ir_packet_reader_get_header(
	struct bt_ctf_ir_packet_reader_ctx *ctx,
	struct bt_ctf_field **packet_header);

/**
 * Returns the packet context.
 *
 * If the packet context is not decoded yet, it is first read and
 * decoded, then returned.
 *
 * Upon successful completion, the returned packet context's reference
 * count is incremented. The user is responsible for calling
 * bt_ctf_field_put() on it.
 *
 * @param ctx			Packet reader context
 * @param packet_context	Returned packet context
 * @returns			One of #bt_ctf_ir_packet_reader_status
 * 				values
 */
enum bt_ctf_ir_packet_reader_status bt_ctf_ir_packet_reader_get_context(
	struct bt_ctf_ir_packet_reader_ctx *ctx,
	struct bt_ctf_field **packet_context);

/**
 * Reads, decodes and returns the next event within the packet.
 *
 * Upon successful completion, the returned event's reference
 * count is incremented. The user is responsible for calling
 * bt_ctf_event_put() on it.
 *
 * @param ctx		Packet reader context
 * @param event		Returned event
 * @returns		One of #bt_ctf_ir_packet_reader_status values
 */
enum bt_ctf_ir_packet_reader_status bt_ctf_ir_packet_reader_get_next_event(
	struct bt_ctf_ir_packet_reader_ctx *ctx,
	struct bt_ctf_event **event);

#endif /* BABELTRACE_CTF_IR_PACKET_READER_H */
