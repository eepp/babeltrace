#ifndef BABELTRACE_CTF_BIFIR_H
#define BABELTRACE_CTF_BIFIR_H

/*
 * Babeltrace - CTF binary file reader
 *                  ¯¯     ¯¯   ¯
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

#include <stdint.h>
#include <stddef.h>
#include <babeltrace/ctf-ir/trace.h>
#include <babeltrace/ctf-ir/event-fields.h>
#include <babeltrace/ctf-ir/event.h>
#include <babeltrace/babeltrace-internal.h>

/**
 * @file ctf-bifir.h
 *
 * CTF binary file reader (bifir).
 *     ¯¯     ¯¯   ¯
 * This is a common internal API used by CTF reader plugins. It allows
 * a binary CTF file (this does \em not have to be a file on disk) to
 * be deserialized as CTF IR data structures from a user-provided
 * medium.
 */

/**
 * Medium operations status codes.
 */
enum bt_ctf_bifir_medium_status {
	/**
	 * End of file.
	 *
	 * The medium function called by the binary file reader function
	 * reached the end of the file.
	 */
	BT_CTF_BIFIR_MEDIUM_STATUS_EOF =	-4,

	/**
	 * There is no data available right now, try again later.
	 */
	BT_CTF_BIFIR_MEDIUM_STATUS_AGAIN =	-3,

	/** Invalid argument. */
	BT_CTF_BIFIR_MEDIUM_STATUS_INVAL =	-2,

	/** General error. */
	BT_CTF_BIFIR_MEDIUM_STATUS_ERROR =	-1,

	/** Everything okay. */
	BT_CTF_BIFIR_MEDIUM_STATUS_OK =		0,
};

/**
 * Binary file reader API status code.
 */
enum bt_ctf_bifir_status {
	/**
	 * End of file.
	 *
	 * The medium function called by the binary file reader function
	 * reached the end of the file.
	 */
	BT_CTF_BIFIR_STATUS_EOF =	-4,

	/**
	 * Packet header, packet context, or event not available.
	 */
	BT_CTF_BIFIR_STATUS_NOENT =	-5,

	/**
	 * There is no data available right now, try again later.
	 *
	 * Some condition resulted in the
	 * bt_ctf_bifir_medium_ops::request_bytes() user function not
	 * having access to any data now. You should retry calling the
	 * last called SOPR function once the situation is resolved.
	 */
	BT_CTF_BIFIR_STATUS_AGAIN =	-3,

	/** Invalid argument. */
	BT_CTF_BIFIR_STATUS_INVAL =	-2,

	/** General error. */
	BT_CTF_BIFIR_STATUS_ERROR =	-1,

	/** Everything okay. */
	BT_CTF_BIFIR_STATUS_OK =	0,
};

/**
 * Medium operations.
 *
 * Those user functions are called by the binary file reader functions
 * to request medium actions.
 */
struct bt_ctf_bifir_medium_ops {
	/**
	 * Returns the next byte buffer to be used by the binary file
	 * reader to deserialize binary data.
	 *
	 * This function \em must be defined.
	 *
	 * The purpose of this function is to return a buffer of bytes
	 * to the binary file reader, of a maximum of \p request_sz
	 * bytes. If this function cannot return a buffer of at least
	 * \p request_sz bytes, it may return a smaller buffer. In
	 * either cases, \p buffer_sz must be set to the returned
	 * buffer size (in bytes).
	 *
	 * The returned buffer's ownership remains the medium, in that
	 * it won't be freed by the binary file reader functions. The
	 * returned buffer won't be modified by the binary file reader
	 * functions either.
	 *
	 * When this function is called for the first time for a given
	 * file, the offset within the file is considered to be 0.
	 * The next times this function is called, the returned buffer's
	 * byte offset within the complete file must be the previous
	 * offset plus the last returned value of \p buffer_sz by this
	 * medium.
	 *
	 * This function must return one of the following statuses:
	 *
	 *   - <b>#BT_CTF_BIFIR_MEDIUM_STATUS_OK</b>: everything
	 *     is okay, i.e. \p buffer_sz is set to a positive value
	 *     reflecting the number of available bytes in the buffer
	 *     starting at the address written in \p buffer_addr.
	 *   - <b>#BT_CTF_BIFIR_MEDIUM_STATUS_AGAIN</b>: no data is
	 *     available right now. In this case, the binary file reader
	 *     function called by the user will return
	 *     #BT_CTF_BIFIR_STATUS_AGAIN, and it is the
	 *     user's responsibility to make sure enough data becomes
	 *     available before calling the same binary file reader
	 *     function again to continue the decoding process.
	 *   - <b>#BT_CTF_BIFIR_MEDIUM_STATUS_EOF</b>: the end of
	 *     the file was reached, and no more data will ever be
	 *     available for this file. In this case, the file reader
	 *     function called by the user will return
	 *     #BT_CTF_BIFIR_STATUS_EOF. This must \em not be returned
	 *     when returning at least one byte of data to the
	 *     caller, i.e. this must be returned when there's
	 *     absolutely nothing left; should the request size be
	 *     larger than what's left in the file, this function must
	 *     return what's left, setting \p buffer_sz to the number
	 *     of remaining bytes, and return
	 *     #BT_CTF_BIFIR_MEDIUM_STATUS_EOF on the \em following call.
	 *   - <b>#BT_CTF_BIFIR_MEDIUM_STATUS_ERROR</b>: a fatal error
	 *     occured during this operation. In this case, the
	 *     binary file reader function called by the user will
	 *     return #BT_CTF_BIFIR_STATUS_ERROR.
	 *
	 * If #BT_CTF_BIFIR_MEDIUM_STATUS_OK is not returned, the values
	 * of \p buffer_sz and \p buffer_addr are ignored by the caller.
	 *
	 * @param request_sz	Requested buffer size (bytes)
	 * @param buffer_sz	Returned buffer's size (bytes)
	 * @param buffer_addr	Returned buffer address
	 * @param data		User data
	 * @returns		Status code (see description above)
	 */
	enum bt_ctf_bifir_medium_status (* request_bytes)(
		size_t request_sz, size_t *buffer_sz,
		uint8_t **buffer_addr, void *data);
};

/* CTF binary file reader */
struct bt_ctf_bifir;

/**
 * Creates a CTF binary file reader.
 *
 * Upon successful completion, the reference count of \p trace is
 * incremented.
 *
 * @param trace			Trace to read
 * @param max_request_sz	Maximum buffer size, in bytes, to
 *                              request to
 *				bt_ctf_bifir_medium_ops::request_bytes()
 * 				at a time; set to 0 for the
 * 				implementation to make this decision
 * @param medops		Medium operations
 * @param medops_data		User data (passed to medium operations)
 * @returns			New binary file reader on success, or
 * 				\c NULL on error
 */
struct bt_ctf_bifir *bt_ctf_bifir_create(struct bt_ctf_trace *trace,
	size_t max_request_sz, struct bt_ctf_bifir_medium_ops medops,
	void *medops_data);

/**
 * Destroys a CTF binary file reader, freeing all internal resources.
 *
 * The registered trace's reference count is decremented.
 *
 * @param bifir		Binary file reader
 */
void bt_ctf_bifir_destroy(struct bt_ctf_bifir *bifir);

/**
 * Resets the internal state of a binary file reader.
 *
 * This function can be used when it is desired to seek to the beginning
 * of another packet. It is expected that the next call to
 * bt_ctf_bifir_medium_ops::request_bytes() made by this binary file
 * reader will return the \em first bytes of a packet.
 *
 * @param bifir		Binary file reader
 */
void bt_ctf_bifir_reset(struct bt_ctf_bifir *bifir);

/**
 * Returns the current packet header.
 *
 * If the current packet header is not decoded yet, it is first read and
 * decoded, then returned.
 *
 * Upon successful completion, #BT_CTF_BIFIR_STATUS_OK is
 * returned, and the returned packet header's reference count is
 * incremented. The user is responsible for calling bt_ctf_field_put()
 * on it.
 *
 * If there's no available packet header for the binary file reader's
 * registered trace, #BT_CTF_BIFIR_STATUS_NOENT is returned.
 *
 * @param bifir			Binary file reader
 * @param packet_header		Returned packet header
 * @returns			One of #bt_ctf_bifir_status values
 */
enum bt_ctf_bifir_status bt_ctf_bifir_get_header(
	struct bt_ctf_bifir *bifir, struct bt_ctf_field **packet_header);

/**
 * Returns the packet context.
 *
 * If the packet context is not decoded yet, it is first read and
 * decoded, then returned.
 *
 * Upon successful completion, #BT_CTF_BIFIR_STATUS_OK is
 * returned, and the returned packet context's reference count is
 * incremented. The user is responsible for calling bt_ctf_field_put()
 * on it.
 *
 * If there's no available packet context for the binary file reader's
 * current stream, #BT_CTF_BIFIR_STATUS_NOENT is returned.
 *
 * @param bifir			Binary file reader
 * @param packet_context	Returned packet context
 * @returns			One of #bt_ctf_bifir_status
 * 				values
 */
enum bt_ctf_bifir_status bt_ctf_bifir_get_context(
	struct bt_ctf_bifir *bifir, struct bt_ctf_field **packet_context);

/**
 * Reads, decodes and returns the next event within the current packet.
 *
 * Upon successful completion, #BT_CTF_BIFIR_STATUS_OK is
 * returned, and the returned event's reference count is incremented.
 * The user is responsible for calling bt_ctf_event_put() on it.
 *
 * If there's no more events within the current packet,
 * #BT_CTF_BIFIR_STATUS_NOENT is returned.
 *
 * The returned event, if any, remains valid as long as no binary file
 * reader function is called with \p bifir. If a copy is needed for
 * further processing, the caller should get one using
 * bt_ctf_event_copy(), which performs a deep copy of an event.
 *
 * @param bifir		Binary file reader
 * @param event		Returned event
 * @returns		One of #bt_ctf_bifir_status values
 */
enum bt_ctf_bifir_status bt_ctf_bifir_get_next_event(
	struct bt_ctf_bifir *bifir, struct bt_ctf_event **event);

/**
 * Requests to the user-provided medium as many bytes as needed for
 * its current position to reach the end of the current packet.
 *
 * Once the medium's position reaches the end of the current packet,
 * this function returns #BT_CTF_BIFIR_STATUS_OK and the
 * binary file reader's internal state is reset, prepared to read the
 * next packet. Further calls to this function would skip the next
 * packet, and so on.
 *
 * @param bifir		Binary file reader
 * @returns		One of #bt_ctf_bifir_status values
 */
enum bt_ctf_bifir_status bt_ctf_bifir_goto_next_packet(
	struct bt_ctf_bifir *bifir);

#endif /* BABELTRACE_CTF_BIFIR_H */
