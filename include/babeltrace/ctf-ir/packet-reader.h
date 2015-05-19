#ifndef BABELTRACE_CTF_IR_PACKET_READER_H
#define BABELTRACE_CTF_IR_PACKET_READER_H

/*
 * Babeltrace - CTF IR: Packet reader
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
 * using a user-provided stream reader.
 *
 * To use this API, you must first create a #bt_ctf_stream_reader_ops
 * structure and fill it with the appropriate operations for your
 * specific stream reader, and then pass it to
 * bt_ctf_packet_reader_create() along with your user data.
 *
 * Call bt_ctf_packet_reader_destroy() when you are done with the
 * packet reader.
 */

#include <stdint.h>
#include <stddef.h>
#include <babeltrace/ctf-ir/trace.h>
#include <babeltrace/ctf-ir/event-fields.h>
#include <babeltrace/ctf-ir/event.h>
#include <babeltrace/babeltrace-internal.h>

/**
 * Stream reader status code.
 *
 * Those status codes are returned by the stream reader operations.
 */
enum bt_ctf_stream_reader_status {
	/**
	 * End of stream.
	 *
	 * The stream reader function called by the packet reader
	 * function reached the end of the stream.
	 */
	BT_CTF_STREAM_READER_STATUS_EOS =	-4,

	/**
	 * There is no data available right now, try again later.
	 *
	 * Some condition resulted in the
	 * bt_ctf_stream_reader_ops::get_next_buffer() user function
	 * not having access to any data now. You should retry calling
	 * the last called packet reader function once the situation is
	 * resolved.
	 */
	BT_CTF_STREAM_READER_STATUS_AGAIN =	-3,

	/** Invalid argument. */
	BT_CTF_STREAM_READER_STATUS_INVAL =	-2,

	/** General error. */
	BT_CTF_STREAM_READER_STATUS_ERROR =	-1,

	/** Everything okay. */
	BT_CTF_STREAM_READER_STATUS_OK =	0,
};

/**
 * Packet reader API status code.
 */
enum bt_ctf_packet_reader_status {
	/**
	 * End of stream.
	 *
	 * The stream reader function called by the packet reader
	 * function reached the end of the stream.
	 */
	BT_CTF_PACKET_READER_STATUS_EOS =		-5,

	/**
	 * Packet header, packet context, or event not available.
	 */
	BT_CTF_PACKET_READER_STATUS_NOENT =		-4,

	/**
	 * There is no data available right now, try again later.
	 *
	 * Some condition resulted in the
	 * bt_ctf_stream_reader_ops::get_next_buffer() user function
	 * not having access to any data now. You should retry calling
	 * the last called packet reader function once the situation is
	 * resolved.
	 */
	BT_CTF_PACKET_READER_STATUS_AGAIN =		-3,

	/** Invalid argument. */
	BT_CTF_PACKET_READER_STATUS_INVAL =		-2,

	/** General error. */
	BT_CTF_PACKET_READER_STATUS_ERROR =		-1,

	/** Everything okay. */
	BT_CTF_PACKET_READER_STATUS_OK =		0,
};

/**
 * Seek operation's reference position.
 */
enum bt_ctf_stream_reader_seek_origin {
	/** Beginning of packet. */
	BT_CTF_STREAM_READER_SEEK_SET = 0,
};

/**
 * Stream reader operations.
 *
 * Those user functions are called by the packet reader functions to
 * request back-end actions.
 */
struct bt_ctf_stream_reader_ops {
	/**
	 * Returns the next buffer to be used by the packet reader to
	 * deserialize binary data.
	 *
	 * This function \em must be defined.
	 *
	 * The purpose of this function is to return a buffer of bits
	 * to the packet reader, of a maximum of \p requested_len
	 * bits. If this function cannot return a buffer of at least
	 * \p requested_len bits, it may return a smaller buffer. In
	 * either cases, \p buffer_len must be set to the returned
	 * buffer length (in bits), and \p buffer_offset must be set
	 * to the offset of the first significant bit from the beginning
	 * of the buffer, where 0 means the most significant bit of
	 * the first byte.
	 *
	 * For example, here's a returned buffer of 25 bits, starting
	 * at offset 3:
	 *
	 * <pre>
	 * bbbbbbbb bbbbbbbbb bbbbbbbb bbbbbbbbb bbbbbbbb bbbbbbbbb
	 *    ^                           ^
	 *  begin                        end (included)
	 * </pre>
	 *
	 * The returned buffer's ownership is the stream reader, in that
	 * it won't be freed by the packet reader functions. The
	 * returned buffer won't be modified by the packet reader
	 * functions either.
	 *
	 * When this function is called for the first time for a given
	 * stream, the offset within the stream is considered to be 0.
	 * The next times this function is called, the returned buffer's
	 * offset within the complete stream must be the previous offset
	 * plus the last returned value of \p buffer_len.
	 *
	 * The function must return one of the following statuses:
	 *
	 *   - <b>#BT_CTF_STREAM_READER_STATUS_OK</b>: everything
	 *     is okay, i.e. \p buffer_len is set to a positive value
	 *     reflecting the number of available bits in the buffer
	 *     starting at the address written in \p buffer plus the
	 *     value of \p buffer_offset.
	 *   - <b>#BT_CTF_STREAM_READER_STATUS_AGAIN</b>:
	 *     no data is available right now. In this case, the packet
	 *     reader function called by the user will return
	 *     #BT_CTF_PACKET_READER_STATUS_AGAIN, and it is the
	 *     user's responsibility to make sure enough data becomes
	 *     available before calling the same packet reader function
	 *     again to continue the decoding process.
	 *   - <b>#BT_CTF_STREAM_READER_STATUS_EOS</b>: the end of
	 *     the stream was reached, and no more data will ever be
	 *     available for this stream. In this case, the packet
	 *     reader function called by the user will return
	 *     #BT_CTF_PACKET_READER_STATUS_EOS. This must not be
	 *     returned when returning at least one bit of data to the
	 *     caller, i.e. this must be returned when there's
	 *     absolutely nothing left; should the request length be
	 *     larger than what's left in the stream, this function must
	 *     return what's left, setting \p buffer_len to the number
	 *     of remaining bits, and return
	 *     #BT_CTF_STREAM_READER_STATUS_EOS on the following call.
	 *   - <b>#BT_CTF_STREAM_READER_STATUS_ERROR</b>: a fatal
	 *     error occured during this operation. In this case, the
	 *     packet reader function called by the user will
	 *     return #BT_CTF_PACKET_READER_STATUS_ERROR.
	 *
	 * If #BT_CTF_STREAM_READER_STATUS_OK is not returned,
	 * the values of \p buffer_len, \p buffer_offset, and \p buffer
	 * are ignored by the caller.
	 *
	 * @param requested_len	Requested buffer length (bits)
	 * @param buffer_len	Returned buffer's length (bits)
	 * @param buffer_offset	Returned offset of the first significant
	 *			bit from the address written in
	 *			\p buffer
	 * @param buffer	Returned buffer
	 * @param data		User data
	 * @returns		Status code (see description above)
	 */
	enum bt_ctf_packet_reader_status (* get_next_bits)(
		size_t requested_len, size_t *buffer_len,
		size_t *buffer_offset, void **buffer, void *data);
};

/* Packet reader context */
struct bt_ctf_packet_reader_ctx;

/**
 * Creates a packet reader.
 *
 * Upon successful completion, the reference count of \p trace is
 * incremented.
 *
 * @param trace			Trace to read
 * @param max_request_len	Maximum buffer length, in bits, to
 *                              request to
 * 				bt_ctf_stream_reader_ops::get_next_bits()
 * 				at a time; set to 0 for the
 * 				implementation to make this decision
 * @param ops			Stream reader operations
 * @param data			User data (passed to stream reader
 *                              operations)
 * @returns			New packet reader context on success, or
 * 				\c NULL on error
 */
struct bt_ctf_packet_reader_ctx *bt_ctf_packet_reader_create(
	struct bt_ctf_trace *trace, size_t max_request_len,
	struct bt_ctf_stream_reader_ops ops, void *data);

/**
 * Destroys a packet reader, freeing all internal resources.
 *
 * The registered trace's reference count is decremented.
 *
 * @param ctx	Packet reader context
 */
void bt_ctf_packet_reader_destroy(struct bt_ctf_packet_reader_ctx *ctx);

/**
 * Returns the packet header.
 *
 * If the packet header is not decoded yet, it is first read and
 * decoded, then returned.
 *
 * Upon successful completion, #BT_CTF_STREAM_READER_STATUS_OK is
 * returned, and the returned packet header's reference count is
 * incremented. The user is responsible for calling bt_ctf_field_put()
 * on it.
 *
 * If there's no available packet header for the packet reader's
 * registered trace, #BT_CTF_PACKET_READER_STATUS_NOENT is returned.
 *
 * @param ctx		Packet reader context
 * @param packet_header	Returned packet header
 * @returns		One of #bt_ctf_packet_reader_status values
 */
enum bt_ctf_packet_reader_status bt_ctf_packet_reader_get_header(
	struct bt_ctf_packet_reader_ctx *ctx,
	struct bt_ctf_field **packet_header);

/**
 * Returns the packet context.
 *
 * If the packet context is not decoded yet, it is first read and
 * decoded, then returned.
 *
 * Upon successful completion, #BT_CTF_STREAM_READER_STATUS_OK is
 * returned, and the returned packet context's reference count is
 * incremented. The user is responsible for calling bt_ctf_field_put()
 * on it.
 *
 * If there's no available packet context for the packet reader's
 * current stream, #BT_CTF_PACKET_READER_STATUS_NOENT is returned.
 *
 * @param ctx			Packet reader context
 * @param packet_context	Returned packet context
 * @returns			One of #bt_ctf_packet_reader_status
 * 				values
 */
enum bt_ctf_packet_reader_status bt_ctf_packet_reader_get_context(
	struct bt_ctf_packet_reader_ctx *ctx,
	struct bt_ctf_field **packet_context);

/**
 * Reads, decodes and returns the next event within the current packet.
 *

 * Upon successful completion, #BT_CTF_STREAM_READER_STATUS_OK is
 * returned, and the returned event's reference count is incremented.
 * The user is responsible for calling bt_ctf_event_put() on it.
 *
 * If there's no more events within the current packet,
 * #BT_CTF_PACKET_READER_STATUS_NOENT is returned.
 *
 * The returned event, if any, remains valid as long as no packet reader
 * function is called with \p ctx. If a copy is needed for further
 * processing, get one using bt_ctf_event_copy(), which performs a deep
 * copy of an event.
 *
 * @param ctx		Packet reader context
 * @param event		Returned event
 * @returns		One of #bt_ctf_packet_reader_status values
 */
enum bt_ctf_packet_reader_status bt_ctf_packet_reader_get_next_event(
	struct bt_ctf_packet_reader_ctx *ctx,
	struct bt_ctf_event **event);

/**
 * Asks the stream reader to read as many bits as needed for its
 * current position to reach the end of the current packet.
 *
 * Once the stream reader's position reaches the end of the current
 * packet, this function returns #BT_CTF_STREAM_READER_STATUS_OK and
 * the packet reader's internal state is reset, prepared to read the
 * next packet. Further calls to this function would skip the next
 * packet, and so on.
 *
 * @param ctx		Packet reader context
 * @returns		One of #bt_ctf_packet_reader_status values
 */
enum bt_ctf_packet_reader_status bt_ctf_packet_reader_goto_next_packet(
	struct bt_ctf_packet_reader_ctx *ctx);

#endif /* BABELTRACE_CTF_IR_PACKET_READER_H */
