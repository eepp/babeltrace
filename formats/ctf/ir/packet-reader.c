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

#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <babeltrace/ctf-ir/packet-reader.h>
#include <glib.h>

/*
 * Hello, fellow developer, and welcome to another free lesson of
 * computer engineering!
 *
 * Today, you will learn how to implement a CTF packet reader which is
 * versatile enough to stop in the middle of the decoding of a CTF
 * event when no more data is available, and resume later when data
 * becomes available again.
 *
 *
 * Decoding fields
 * ===============
 *
 * This packet reader depends on a user-provided back-end, implementing
 * a function used by this reader to request more bytes of the current
 * packet. This user function, get_next_buffer(), might return the
 * BT_CTF_STREAM_READER_STATUS_AGAIN status code, in which case
 * the packet reader function (either bt_ctf_packet_reader_get_header(),
 * bt_ctf_packet_reader_get_context(), or
 * bt_ctf_packet_reader_get_next_event()) will also return this
 * status code to the caller and no bytes will be read. The caller is
 * then responsible for making sure that some data becomes available
 * to its back-end, and needs to call the same function again to resume
 * the decoding process.
 *
 * The ultimate job of this packet reader is converting a sequence of
 * bytes (the binary CTF packet) to CTF IR fields. When a buffer is
 * successfully returned by get_next_buffer(), the previous one is
 * not available anymore. Also, get_next_buffer() may return a buffer
 * of an arbitrary size. One solution would be to copy the buffers
 * returned from get_next_buffer() until we have enough data to
 * decode a whole event. This copy is, however, unnecessary, since the
 * "temporary data" can be held by the fields currently being built.
 *
 * There are a few challenges with this approach:
 *
 *   1. If there is, for example, 4 bytes left to read in the returned
 *      user buffer, and we need to read an 8-byte integer, how do we
 *      do this?
 *   2. If we have to stop in the middle of a decoding process because
 *      get_next_buffer() returned BT_CTF_STREAM_READER_STATUS_AGAIN,
 *      how do we remember where we were in the current field, and how
 *      do we continue from there?
 *
 * The solution for challenge #1 is easy: the bt_bitfield_readx_*()
 * functions take a _cont flag which can be set to 1 to continue the
 * bitfield decoding process using a previous result. When the next
 * atomic field's size is larger than what's left in the current user
 * buffer, call bt_bitfield_readx_*() with _cont set to 0 to begin the
 * bitfield decoding process, and save the temporary result. Call
 * this function again with _cont set to 1 until the total read size
 * is equal to the atomic field's size. The last result is the atomic
 * field's value.
 *
 * The current solution for challenge #2 is to keep a current visit
 * stack in the packet reader context. The top of the stack always
 * contains the current parent field of the next field to be visited.
 * This parent field will be either a structure, a variant, an array,
 * or a sequence. The top of the stack also contains the index, within
 * the parent field, of the next field to be visited. When this field is
 * an atomic, readable field (integer, floating point number,
 * enumeration, or string byte), and there's enough data left in the
 * user-provided buffer to decode it, depending on its size and
 * alignment, it is decoded, and the appropriate field is created with
 * this value. The basic field is then appended to the current parent
 * field. It the next field to read is a compound type (structure,
 * variant, array, sequence), the (empty) field is created, and pushed
 * on the visit stack as the new current parent field. In some cases,
 * the current position within the user-provided buffer could be updated
 * because of custom alignment of compound types.
 *
 *
 * Example
 * -------
 *
 * Let's try an example. For the sake of simplicity, we'll use field
 * sizes and alignments which are multiples of 8 bits (always fit in
 * whole bytes). Keep in mind, however, that this technique also works
 * with sizes and alignments which are multiple of one bit.
 *
 * The root field to create is:
 *
 *     struct              align = 8
 *         a: int          align = 8     size = 16
 *         b: int          align = 32    size = 32
 *         c: int          align = 8     size = 8
 *         d: struct       align = 64
 *             e: float    align = 32    size = 32
 *             f: array    length = 5
 *                 int     align = 8     size = 32
 *             g: int      align = 8     size = 64
 *         h: float        align = 32    size = 32
 *         j: array        length = 3
 *             enum        align = 8     size = 8
 *         k: int          align = 64    size = 64
 *
 * The bytes to decode are (`x` means one byte of padding):
 *
 *     +--------+-----------------+-------------+
 *     | Offset | Bytes           | Field       |
 *     +========+=================+=============+
 *     |      0 | i i             | root.a      |
 *     |      2 | x x             |             |
 *     |      4 | i i i i         | root.b      |
 *     |      8 | i               | root.c      |
 *     |      9 | x x x x x x x   |             |
 *     |     16 | f f f f         | root.d.e    |
 *     |     20 | i i i i         | root.d.f[0] |
 *     |     24 | i i i i         | root.d.f[1] |
 *     |     28 | i i i i         | root.d.f[2] |
 *     |     32 | i i i i         | root.d.f[3] |
 *     |     36 | i i i i         | root.d.f[4] |
 *     |     40 | i i i i i i i i | root.d.g    |
 *     |     48 | f f f f         | root.h      |
 *     |     52 | e               | root.j[0]   |
 *     |     53 | e               | root.j[1]   |
 *     |     54 | e               | root.j[2]   |
 *     |     55 | x               |             |
 *     |     56 | i i i i i i i i | root.k      |
 *     +--------+-----------------+-------------+
 *
 * Total buffer size is 64 bytes.
 *
 * We'll now simulate a complete decoding process. Three calls to the
 * packet reader API will be needed to finish the decoding, since two
 * calls will be interrupted by the back-end returning the infamous
 * BT_CTF_STREAM_READER_STATUS_AGAIN status code. Assume the maximum
 * length to request to the user back-end is 128 bits.
 *
 * Let's do this, in 28 easy steps:
 *
 *   1.  User calls the packet reader API function.
 *   2.  Root field is a structure. Create a structure field, and push
 *       it on the currently empty stack, as the current parent field.
 *       Set current index to 0.
 *
 *       Current stack is:
 *
 *           Structure (root)    Index = 0    <-- top

 *   3.  We need to read a 16-bit integer. Do we have at least 16 bits
 *       left in the user-provided buffer? No, 0 bits are left.
 *       Request 128 bits from the user. User returns 128 bits. Set
 *       current buffer position to 0. Read 16 bits, create integer
 *       field, set its value, and append it to the current parent
 *       field. Set current index to 1. Set current buffer position
 *       to 16.
 *   4.  We need to read a 32-bit integer after having skipped 16 bits
 *       of padding. Do we have at least 48 bits left in the buffer?
 *       Yes, 112 bits are left. Set current buffer position to 32. Read
 *       32 bits, create integer field, set its value, and append it to
 *       the current parent field. Set current index to 2. Set current
 *       buffer position to 64.
 *   5.  We need to read an 8-bit integer. Do we have at least 8 bits
 *       left in the buffer? Yes, 64 bits are left. Read 8 bits, create
 *       integer field, set its value, and append it to the current
 *       parent field. Set current index to 3. Set current buffer
 *       position to 72.
 *   6.  Field at index 3 is a structure. Create a structure field.
 *       Append it to the current parent field. Push it on the stack
 *       as the current parent field. Set current field index to 0. We
 *       need to skip 42 bits of padding. Do we have at least 42 bits
 *       left in the buffer? Yes, 42 bits are left. Set current buffer
 *       position to 128.
 *
 *       Current stack is:
 *
 *           Structure (d)       Index = 0    <-- top
 *           Structure (root)    Index = 3
 *
 *   7.  We need to read a 32-bit floating point number. Do we have at
 *       least 32 bits left in the buffer? No, 0 bits are left.
 *       Request 128 bits from the user. User returns the
 *       BT_CTF_STREAM_READER_STATUS_AGAIN status code. Packet reader
 *       API function returns BT_CTF_PACKET_READER_STATUS_AGAIN to
 *       the user.
 *   8.  User makes sure some data becomes available to its back-end.
 *       User calls the packet reader API function to continue.
 *   9.  We need to read a 32-bit floating point number. Do we have at
 *       least 32 bits left in the buffer? No, 0 bits are left.
 *       Request 128 bits to the user. User returns 80 bits. Set
 *       current buffer position to 0. Read 32 bits, create floating
 *       point number field, set its value, and append it to the
 *       current parent field. Set current index to 1. Set current
 *       buffer position to 32.
 *   10. Field at index 1 is an array. Create an array field. Append it
 *       to the current parent field. Push it on the stack as the
 *       current parent field. Set current index to 0.
 *
 *       Current stack is:
 *
 *           Array     (d.f)     Index = 0    <-- top
 *           Structure (d)       Index = 1
 *           Structure (root)    Index = 3
 *
 *   11. We need to read a 32-bit integer. Do we have at least 32 bits
 *       left in the buffer? Yes, 48 bits are left. Read 32 bits, create
 *       integer field, set its value, and append it to the current
 *       parent field. Set current index to 1. Set current buffer
 *       position to 64.
 *   12. We need to read a 32-bit integer. Do we have at least 32 bits
 *       left in the buffer? No, 16 bits are left. Read 16 bits,
 *       call bt_bitfield_readx_*() with _cont set to 0 to get a partial
 *       result. Set current buffer position to 80. Request 128 bits
 *       from the user. User returns 112 bits. Set current buffer
 *       position to 0. Read 16 bits, call bt_bitfield_readx_*() with
 *       _cont set to 1 and the previous result. Create integer field,
 *       set its value (from the last decoded result), and append the
 *       field to the current parent field. Set current index to 2. Set
 *       current buffer position to 16.
 *   13. We need to read a 32-bit integer. Do we have at least 32 bits
 *       left in the buffer? Yes, 96 bits are left. Read 32 bits,
 *       create integer field, set its value, and append it to the
 *       current parent field. Set current index to 3. Set current
 *       buffer position to 48.
 *   14. We need to read a 32-bit integer. Do we have at least 32 bits
 *       left in the buffer? Yes, 64 bits are left. Read 32 bits,
 *       create integer field, set its value, and append it to the
 *       current parent field. Set current index to 4. Set current
 *       buffer position to 80.
 *   15. We need to read a 32-bit integer. Do we have at least 32 bits
 *       left in the buffer? Yes, 32 bits are left. Read 32 bits,
 *       create integer field, set its value, and append it to the
 *       current parent field. Set current index to 5. Set current
 *       buffer position to 112.
 *   16. Current index equals parent field's length (5): pop stack's
 *       top entry. Set current index to 2.
 *
 *       Current stack is:
 *
 *           Structure (d)       Index = 2    <-- top
 *           Structure (root)    Index = 3
 *
 *   17. We need to read a 64-bit integer. Do we have at least 64 bits
 *       left in the buffer? No, 0 bits are left. Request 128 bits from
 *       the user. User returns the BT_CTF_STREAM_READER_STATUS_AGAIN
 *       status code. Packet reader API function returns
 *       BT_CTF_PACKET_READER_STATUS_AGAIN to the user.
 *   18. User makes sure some data becomes available to its back-end.
 *       User calls the packet reader API function to continue.
 *   19. We need to read a 64-bit integer. Do we have at least 64 bits
 *       left in the buffer? No, 0 bits are left. Request 128 bits from
 *       the user. User returns 128 bits. Set current buffer position to
 *       0. Read 64 bits, create integer field, set its value, and
 *       append it to the current parent field. Set current index to
 *       3. Set current buffer position to 64.
 *   20. Current index equals parent field's length (3): pop stack's
 *       top entry. Set current index to 4.
 *
 *       Current stack is:
 *
 *           Structure (root)    Index = 4    <-- top
 *
 *   21. We need to read a 32-bit floating point number. Do we have at
 *       least 32 bits left in the buffer? Yes, 64 bits are left.
 *       Read 32 bits, create floating point number field, set its
 *       value, and append it to the current parent field. Set current
 *       index to 5. Set current buffer position to 96.
 *   22. Field at index 5 is an array. Create an array field. Append it
 *       to the current parent field. Push it on the stack as the
 *       current parent field. Set current index to 0.
 *
 *       Current stack is:
 *
 *           Array     (j)       Index = 0    <-- top
 *           Structure (root)    Index = 5
 *
 *   23. We need to read an 8-bit enumeration. Do we have at least 8
 *       bits left in the buffer? Yes, 32 bits are left. Read 8 bit,
 *       create enumeration field, set its value, and append it to the
 *       current parent field. Set current index to 1. Set current
 *       buffer position to 104.
 *   24. We need to read an 8-bit enumeration. Do we have at least 8
 *       bits left in the buffer? Yes, 24 bits are left. Read 8 bit,
 *       create enumeration field, set its value, and append it to the
 *       current parent field. Set current index to 2. Set current
 *       buffer position to 112.
 *   25. We need to read an 8-bit enumeration. Do we have at least 8
 *       bits left in the buffer? Yes, 16 bits are left. Read 8 bit,
 *       create enumeration field, set its value, and append it to the
 *       current parent field. Set current index to 3. Set current
 *       buffer position to 120.
 *   26. Current index equals parent field's length (3): pop stack's
 *       top entry. Set current index to 6.
 *
 *       Current stack is:
 *
 *           Structure (root)    Index = 6    <-- top
 *
 *   27. We need to read a 64-bit integer after having skipped 8 bits
 *       of padding. Do we have at least 72 bits left in the buffer?
 *       No, 8 bits is left. Skip this 8 bit as padding. Request 64
 *       bits from the user. User returns 64 bits. Set current buffer
 *       position to 0. Read 64 bits, create integer field, set its
 *       value, and append it to the current parent field. Set current
 *       index to 7. Set current buffer position to 64.
 *   28. Current index equals parent field's length (7): pop stack's
 *       top entry. Current stack is empty. Return popped field to
 *       user.
 *
 *
 * Strings
 * -------
 *
 * We didn't explore how string fields are decoded yet. Get hold of
 * yourself, here it is. A CTF string is a special type since it is
 * considered a basic type as per the CTF specifications, yet it really
 * is a sequence of individual bytes.
 *
 * Let's say we need to read a 28-byte string, that is, 27 printable
 * bytes followed by one null byte. We begin by creating an empty
 * string field, and then we push it on top of the stack. The current
 * index for this stack entry is meaningless. Assume the maximum length
 * to request to the user back-end is 16 bytes.
 *
 * 16 bytes are requested and returned. A null byte is searched for in
 * the returned buffer. None is found, so the whole 16-byte block is
 * appended to the current string field. Since no null byte was found,
 * the string field remains incomplete. 16 bytes are requested and
 * returned. A null byte is searched for in the returned buffer, and
 * is found at position 11. Bytes from position 0 to 10 are appended
 * to the current string field. Since a null byte was found, the
 * string field is considered complete, and it is popped off the
 * stack. Byte 11, the null byte, is skipped, so the current buffer
 * position is set to 12.
 *
 *
 * Variants
 * --------
 *
 * Our 28-step example did not look into variants either. They are
 * pretty easy, in fact. When one is hit, create the variant field, and
 * push it as the current parent field. Continue the loop. When the
 * current parent field is a variant, try reading its currently selected
 * field. When done, pop the variant.
 *
 *
 * Packet reading
 * ==============
 *
 * So this demonstrated how to transform bits into fields with decoding
 * interrupt support. The process of decoding a whole CTF packet uses
 * this, but we also introduce a decoding state.
 *
 * The first thing we want to know when starting the decoding of a
 * packet is to which stream it belongs. There are two possibilities
 * here:
 *
 *   * We'll find the stream ID in the `stream_id` field of the
 *     packet header, if it exists.
 *   * If the `stream_id` field is missing from the packet header, or
 *     if the packet header does not exist, there must be a single
 *     stream.
 *
 * The first step is thus decoding the packet header. Since we don't
 * know the packet size yet (this information, if it exists, is in the
 * packet context, which immediately follows the packet header), though,
 * we need to be careful in how many bits to request from the user.
 * Assume a packet header size of 24 bytes, which is typical, and a
 * maximum size to request of 4096 bytes. We must not request more than
 * the packet header size, because we don't know what follows yet (this
 * depends on the packet's stream, which we don't know yet). Two
 * situations:
 *
 *   * Packet header has a fixed size (no sequence field, no variant
 *     field): request this size to the user.
 *   * Packet header has a variable size (at least one sequence field or
 *     one variant field): request only what's needed for the next
 *     atomic field until the whole packet header is read.
 *
 * Requesting just enough when the packet size is unknown is important,
 * because requesting too much could result in having requested bits
 * that belong to the next packet, or bits that do not exist, and there
 * is no way to tell the user that we requested too much.
 *
 * Once we have the stream ID, we can find the stream, and thus the
 * packet context type. We proceed with decoding the packet context.
 * Again: request the whole packet context size if it's fixed, otherwise
 * one atomic field at a time, until we get either the `content_size` or
 * the `packet_size` field (which sets how many bits we need to read in
 * the whole packet), or the end of the packet context.
 *
 * Once there, we have everything we need to start decoding events.
 * If we know the packet size, we will request the maximum request size
 * to the stream reader until this size is reached. Otherwise, we
 * always request the maximum request size until the stream reader
 * returns BT_CTF_STREAM_READER_STATUS_EOS (end of stream), in which
 * case we return BT_CTF_PACKET_READER_STATUS_EOP to the caller.
 *
 * When the packet reader context is created, we're at the initial
 * state: nothing is decoded yet. We always have to go through the
 * packet header and context decoding states before reading events, so
 * even if the first API call is bt_ctf_packet_reader_get_next_event(),
 * the packet reader will still decode the packet header and context
 * before eventually decoding the first event, and returning it. Then
 * subsequent calls to bt_ctf_packet_reader_get_header() and
 * bt_ctf_packet_reader_get_context() will simply return the previously
 * decoded fields.
 *
 *                          - T H E   E N D -
 */

struct stack_entry {
	/*
	 * Current base field, one of:
	 *
	 *   * structure
	 *   * array
	 *   * sequence
	 *   * variant
	 *   * string
	 */
	struct bt_ctf_field *cur_base;

	/* index of next field to read */
	uint64_t cur_index;
};

struct stack {
	/* entries (struct stack_entry *) (top is last element) */
	GPtrArray *entries;
};

enum decoding_state {
	DECODING_STATE_INIT,
	DECODING_STATE_HEADER,
	DECODING_STATE_CONTEXT,
	DECODING_STATE_EVENT,
	DECODING_STATE_DONE,
};

struct bt_ctf_packet_reader_ctx {
	/* back-end operations */
	struct bt_ctf_packet_reader_ops ops;

	/* trace (our own ref) */
	struct bt_ctf_trace *trace;

	/* current packet header (our own ref) */
	struct bt_ctf_field *header;

	/* current packet context (our own ref) */
	struct bt_ctf_field *context;

	/* current event (our own ref) */
	struct bt_ctf_event *event;

	/* current decoding state */
	enum decoding_state state;

	/* current user buffer */
	const void *buf;

	/* current user buffer's size (bytes) */
	size_t buf_size;

	/* current offset in user buffer (bits) */
	size_t at;

	/* maximum request length (bytes) */
	size_t max_request_len;

	/* current offset in packet (bits) */
	size_t at_packet;

	/* current packet size (bits) (-1 if unknown) */


	/* user data */
	void *user_data;
};

static
void stack_entry_free_func(gpointer data)
{
	struct stack_entry *entry = data;

	bt_ctf_field_put(entry->cur_base);
	g_free(entry);
}

static
struct stack *stack_new(void)
{
	struct stack *stack = NULL;

	stack = g_new0(struct stack, 1);

	if (!stack) {
		goto error;
	}

	stack->entries = g_ptr_array_new_with_free_func(stack_entry_free_func);

	if (!stack->entries) {
		goto error;
	}

	return stack;

error:
	g_free(stack);

	return NULL;
}

static
void stack_destroy(struct stack *stack)
{
	assert(stack);
	g_ptr_array_free(stack->entries, TRUE);
	g_free(stack);
}

static
int stack_push(struct stack *stack, struct bt_ctf_field *base)
{
	int ret = 0;
	struct stack_entry *entry;

	assert(stack);
	assert(base);
	entry = g_new0(struct stack_entry, 1);

	if (!entry) {
		ret = -1;
		goto end;
	}

	entry->cur_base = base;
	bt_ctf_field_get(entry->cur_base);

end:
	return ret;
}

static
unsigned int stack_size(struct stack *stack)
{
	assert(stack);

	return stack->entries->len;
}

static
void stack_pop(struct stack *stack)
{
	assert(stack);
	assert(stack_size(stack));
	g_ptr_array_remove_index(stack->entries, stack->entries->len - 1);
}

static
struct stack_entry *stack_top(struct stack *stack)
{
	assert(stack);
	assert(stack_size(stack));

	return g_ptr_array_index(stack->entries, stack->entries->len - 1);
}

/*
 * This is the entry point for converting bits to a complete
 * CTF IR field.
 */
static
int unserialize_field(struct bt_ctf_packet_reader_ctx *ctx,
	struct bt_ctf_field_type *type)
{
	return BT_CTF_PACKET_READER_STATUS_OK;
}

struct bt_ctf_packet_reader_ctx *bt_ctf_packet_reader_create(
	struct bt_ctf_trace *trace, size_t max_request_len,
	struct bt_ctf_packet_reader_ops ops, void *data)
{
	struct bt_ctf_packet_reader_ctx *ctx = NULL;

	ctx = g_new0(struct bt_ctf_packet_reader_ctx, 1);

	if (!ctx) {
		goto end;
	}

	ctx->ops = ops;
	ctx->max_request_len = max_request_len;
	ctx->trace = trace;
	ctx->state = DECODING_STATE_INIT;
	bt_ctf_trace_get(ctx->trace);
	ctx->user_data = data;

end:
	return ctx;
}

void bt_ctf_packet_reader_destroy(struct bt_ctf_packet_reader_ctx *ctx)
{
	bt_ctf_trace_put(ctx->trace);
	g_free(ctx);
}

enum bt_ctf_packet_reader_status bt_ctf_packet_reader_reset(
	struct bt_ctf_packet_reader_ctx *ctx)
{
	return 0;
}

static
enum bt_ctf_packet_reader_status decode_packet_header(
	struct bt_ctf_packet_reader_ctx *ctx)
{
	enum bt_ctf_packet_reader_status ret;

	/* packet header already decoded? */
	if (ctx->header_is_complete) {
		ret = BT_CTF_PACKET_READER_STATUS_OK;
		goto end;
	}

	/* continue decoding packet header */

end:
	return ret;
}

enum bt_ctf_packet_reader_status bt_ctf_packet_reader_get_header(
	struct bt_ctf_packet_reader_ctx *ctx,
	struct bt_ctf_field **packet_header)
{
	enum bt_ctf_packet_reader_status status;

	/* decode packet header*/
	status = decode_packet_header(ctx);

	/* packet header completely decoded? */
	if (status == BT_CTF_PACKET_READER_STATUS_OK) {
		*packet_header = ctx->header;
		bt_ctf_field_get(*packet_header);
	}

	return status;
}

static
enum bt_ctf_packet_reader_status decode_packet_context(
	struct bt_ctf_packet_reader_ctx *ctx)
{
	enum bt_ctf_packet_reader_status ret;

	/* packet context already decoded? */
	if (ctx->context_is_complete) {
		ret = BT_CTF_PACKET_READER_STATUS_OK;
		goto end;
	}

	/* continue decoding packet context */

end:
	return ret;
}

enum bt_ctf_packet_reader_status bt_ctf_packet_reader_get_context(
	struct bt_ctf_packet_reader_ctx *ctx,
	struct bt_ctf_field **packet_context)
{
	enum bt_ctf_packet_reader_status status;

	/* decode packet header*/
	status = decode_packet_context(ctx);

	/* packet header completely decoded? */
	if (status == BT_CTF_PACKET_READER_STATUS_OK) {
		*packet_context = ctx->context;
		bt_ctf_field_get(*packet_context);
	}

	return status;
}

enum bt_ctf_packet_reader_status bt_ctf_packet_reader_get_next_event(
	struct bt_ctf_packet_reader_ctx *ctx,
	struct bt_ctf_event **event)
{
	return BT_CTF_PACKET_READER_STATUS_OK;
}
