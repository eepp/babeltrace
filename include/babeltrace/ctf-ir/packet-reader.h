#ifndef BABELTRACE_CTF_IR_STREAM_READER_H
#define BABELTRACE_CTF_IR_STREAM_READER_H

/*
 * Babeltrace - CTF IR: Stream reader
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
 * @file stream-reader.h
 *
 * This is a common internal API used by CTF reader plugins. It allows
 * a binary CTF stream to be deserialized as CTF IR data structures
 * from a user-provided medium.
 *
 * To use this API, you must first create a #bt_ctf_medium_ops
 * structure and fill it with the appropriate operations for your
 * specific medium, and then pass it to bt_ctf_stream_reader_create()
 * along with your user data.
 *
 * Call bt_ctf_stream_reader_destroy() when you are done with the
 * stream reader.
 */

#include <stdint.h>
#include <stddef.h>
#include <babeltrace/ctf-ir/trace.h>
#include <babeltrace/ctf-ir/event-fields.h>
#include <babeltrace/ctf-ir/event.h>
#include <babeltrace/babeltrace-internal.h>

/**
 * Medium operations status codes.
 */
enum bt_ctf_medium_status {
	/**
	 * End of stream.
	 *
	 * The medium function called by the stream reader function
	 * reached the end of the stream.
	 */
	BT_CTF_MEDIUM_STATUS_EOS =	-4,

	/**
	 * There is no data available right now, try again later.
	 *
	 * Some condition resulted in the
	 * bt_ctf_medium_ops::get_next_bytes() user function not having
	 * access to any data now. You should retry calling the last
	 * called stream reader function once the situation is resolved.
	 */
	BT_CTF_MEDIUM_STATUS_AGAIN =	-3,

	/** Invalid argument. */
	BT_CTF_MEDIUM_STATUS_INVAL =	-2,

	/** General error. */
	BT_CTF_MEDIUM_STATUS_ERROR =	-1,

	/** Everything okay. */
	BT_CTF_MEDIUM_STATUS_OK =	0,
};

/**
 * Stream reader API status code.
 */
enum bt_ctf_stream_reader_status {
	/**
	 * End of stream.
	 *
	 * The stream reader function called by the stream reader
	 * function reached the end of the stream.
	 */
	BT_CTF_STREAM_READER_STATUS_EOS =	-5,

	/**
	 * Packet header, packet context, or event not available.
	 */
	BT_CTF_STREAM_READER_STATUS_NOENT =	-4,

	/**
	 * There is no data available right now, try again later.
	 *
	 * Some condition resulted in the
	 * bt_ctf_medium_ops::get_next_bytes() user function not having
	 * access to any data now. You should retry calling the last
	 * called stream reader function once the situation is
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
 * Medium operations.
 *
 * Those user functions are called by the stream reader functions to
 * request medium actions.
 */
struct bt_ctf_medium_ops {
	/**
	 * Returns the next byte buffer to be used by the stream reader
	 * to deserialize binary data.
	 *
	 * This function \em must be defined.
	 *
	 * The purpose of this function is to return a buffer of bytes
	 * to the stream reader, of a maximum of \p requested_len
	 * bytes. If this function cannot return a buffer of at least
	 * \p requested_len bytes, it may return a smaller buffer. In
	 * either cases, \p buffer_len must be set to the returned
	 * buffer length (in bytes).
	 *
	 * The returned buffer's ownership is the medium, in that it
	 * won't be freed by the stream reader functions. The returned
	 * buffer won't be modified by the stream reader functions
	 * either.
	 *
	 * When this function is called for the first time for a given
	 * stream, the offset within the stream is considered to be 0.
	 * The next times this function is called, the returned buffer's
	 * byte offset within the complete stream must be the previous
	 * offset plus the last returned value of \p buffer_len.
	 *
	 * The function must return one of the following statuses:
	 *
	 *   - <b>#BT_CTF_MEDIUM_STATUS_OK</b>: everything
	 *     is okay, i.e. \p buffer_len is set to a positive value
	 *     reflecting the number of available bytes in the buffer
	 *     starting at the address written in \p buffer_addr.
	 *   - <b>#BT_CTF_MEDIUM_STATUS_AGAIN</b>: no data is available
	 *     right now. In this case, the stream reader function
	 *     called by the user will return
	 *     #BT_CTF_STREAM_READER_STATUS_AGAIN, and it is the
	 *     user's responsibility to make sure enough data becomes
	 *     available before calling the same stream reader function
	 *     again to continue the decoding process.
	 *   - <b>#BT_CTF_MEDIUM_STATUS_EOS</b>: the end of
	 *     the stream was reached, and no more data will ever be
	 *     available for this stream. In this case, the stream
	 *     reader function called by the user will return
	 *     #BT_CTF_STREAM_READER_STATUS_EOS. This must not be
	 *     returned when returning at least one byte of data to the
	 *     caller, i.e. this must be returned when there's
	 *     absolutely nothing left; should the request length be
	 *     larger than what's left in the stream, this function must
	 *     return what's left, setting \p buffer_len to the number
	 *     of remaining bytes, and return
	 *     #BT_CTF_MEDIUM_STATUS_EOS on the following call.
	 *   - <b>#BT_CTF_MEDIUM_STATUS_ERROR</b>: a fatal
	 *     error occured during this operation. In this case, the
	 *     stream reader function called by the user will
	 *     return #BT_CTF_STREAM_READER_STATUS_ERROR.
	 *
	 * If #BT_CTF_MEDIUM_STATUS_OK is not returned, the values of
	 * \p buffer_len and \p buffer_addr are ignored by the caller.
	 *
	 * @param requested_len	Requested buffer length (bytes)
	 * @param buffer_len	Returned buffer's length (bytes)
	 * @param buffer_addr	Returned buffer address
	 * @param data		User data
	 * @returns		Status code (see description above)
	 */
	enum bt_ctf_medium_status (* get_next_bytes)(
		size_t requested_len, size_t *buffer_len,
		uint8_t **buffer_addr, void *data);
};

/* Stream reader context */
struct bt_ctf_stream_reader_ctx;

/**
 * Creates a stream reader.
 *
 * Upon successful completion, the reference count of \p trace is
 * incremented.
 *
 * @param trace			Trace to read
 * @param max_request_len	Maximum buffer length, in bytes, to
 *                              request to bt_ctf_medium_ops::get_next_bytes()
 * 				at a time; set to 0 for the
 * 				implementation to make this decision
 * @param ops			Medium operations
 * @param data			User data (passed to medium operations)
 * @returns			New stream reader context on success, or
 * 				\c NULL on error
 */
struct bt_ctf_stream_reader_ctx *bt_ctf_stream_reader_create(
	struct bt_ctf_trace *trace, size_t max_request_len,
	struct bt_ctf_medium_ops ops, void *data);

/**
 * Destroys a stream reader, freeing all internal resources.
 *
 * The registered trace's reference count is decremented.
 *
 * @param ctx	Stream reader context
 */
void bt_ctf_stream_reader_destroy(struct bt_ctf_stream_reader_ctx *ctx);

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
 * If there's no available packet header for the stream reader's
 * registered trace, #BT_CTF_STREAM_READER_STATUS_NOENT is returned.
 *
 * @param ctx		Stream reader context
 * @param packet_header	Returned packet header
 * @returns		One of #bt_ctf_stream_reader_status values
 */
enum bt_ctf_stream_reader_status bt_ctf_stream_reader_get_header(
	struct bt_ctf_stream_reader_ctx *ctx,
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
 * If there's no available packet context for the stream reader's
 * current stream, #BT_CTF_STREAM_READER_STATUS_NOENT is returned.
 *
 * @param ctx			Stream reader context
 * @param packet_context	Returned packet context
 * @returns			One of #bt_ctf_stream_reader_status
 * 				values
 */
enum bt_ctf_stream_reader_status bt_ctf_stream_reader_get_context(
	struct bt_ctf_stream_reader_ctx *ctx,
	struct bt_ctf_field **packet_context);

/**
 * Reads, decodes and returns the next event within the current packet.
 *
 * Upon successful completion, #BT_CTF_STREAM_READER_STATUS_OK is
 * returned, and the returned event's reference count is incremented.
 * The user is responsible for calling bt_ctf_event_put() on it.
 *
 * If there's no more events within the current packet,
 * #BT_CTF_STREAM_READER_STATUS_NOENT is returned.
 *
 * The returned event, if any, remains valid as long as no stream reader
 * function is called with \p ctx. If a copy is needed for further
 * processing, get one using bt_ctf_event_copy(), which performs a deep
 * copy of an event.
 *
 * @param ctx		Stream reader context
 * @param event		Returned event
 * @returns		One of #bt_ctf_stream_reader_status values
 */
enum bt_ctf_stream_reader_status bt_ctf_stream_reader_get_next_event(
	struct bt_ctf_stream_reader_ctx *ctx,
	struct bt_ctf_event **event);

/**
 * Asks the medium to read as many bytes as needed for its current
 * position to reach the end of the current packet.
 *
 * Once the medium's position reaches the end of the current packet,
 * this function returns #BT_CTF_STREAM_READER_STATUS_OK and the
 * stream reader's internal state is reset, prepared to read the
 * next packet. Further calls to this function would skip the next
 * packet, and so on.
 *
 * @param ctx		Stream reader context
 * @returns		One of #bt_ctf_stream_reader_status values
 */
enum bt_ctf_stream_reader_status bt_ctf_stream_reader_goto_next_packet(
	struct bt_ctf_stream_reader_ctx *ctx);

#endif /* BABELTRACE_CTF_IR_STREAM_READER_H */
