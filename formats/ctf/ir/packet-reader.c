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

#include <stdint.h>
#include <stddef.h>
#include <babeltrace/ctf-ir/packet-reader.h>
#include <glib.h>

/*
 * Hello, fellow developer, and welcome to another free computer
 * engineering lesson!
 *
 * Today, we'll learn how to implement a CTF packet reader which is
 * versatile enough to stop in the middle of the decoding of a CTF
 * event when no more data is available, and resume later when data
 * becomes available again.
 *
 * This packet reader depends on a user-provided back-end, implementing
 * a function used by this reader to request more bytes of the current
 * packet. This user function, get_next_buffer(), might return the
 * BT_CTF_IR_PACKET_READER_STATUS_AGAIN status code, in which case
 * the packet reader function (either bt_ctf_ir_packet_reader_get_header(),
 * bt_ctf_ir_packet_reader_get_context(), or
 * bt_ctf_ir_packet_reader_get_next_event()) will also return this
 * status code to the caller and no bytes will be read. The caller is
 * then responsible for making sure that some data becomes available
 * to its back-end, and needs to call the same function again to resume.
 *
 * The ultimate job of this packet reader is converting a sequence of
 * bytes (the binary CTF packet) to CTF IR fields. When a buffer is
 * successfully returned by get_next_buffer(), the previous one is
 * not available anymore. Also, get_next_buffer() may return a buffer
 * of an arbitrary size. One solution would be to copy the buffers
 * returned from get_next_buffer() until we have enough data to
 * decode a whole event. This copy is, however, unnecessary, since the
 * "temporary data" could be the fields currently being built.
 *
 * There are a few challenges with this approach:
 *
 *   1. If there is, for example, 4 bytes left to read in the returned
 *      user buffer, and we need to read an 8-byte integer, how do we
 *      do this?
 *   2. If we have to stop in the middle of a decoding process because
 *      get_next_buffer() returned BT_CTF_IR_PACKET_READER_STATUS_AGAIN,
 *      how do we remember where we were in the current field, and how
 *      do we continue from there?
 *
 * The solution for challenge #1 is easy: keep a "stitch buffer" with a
 * size equal to the maximum atomic field size (64-bit integer in this
 * version). When the next atomic field's size is larger than what's
 * left in the current user buffer, copy the remaining buffer bits
 * to the stitch buffer, incrementing the current stitch buffer's
 * internal position. Repeat this until the stitch buffer's occupied
 * size is equal to the next atomic field's size. Then, decode the
 * field from the stitch buffer. The stitch buffer should only be
 * used in stitch situations.
 *
 * The current solution for challenge #2 is to keep a current visit
 * stack in the packet reader context. The top of the stack always
 * contains the current parent field of the next field to be visited.
 * This parent field will be either a structure, an array, or a
 * sequence.


struct stack_entry {
	/*
	 * Current base field, one of:
	 *
	 *   * structure
	 *   * array
	 *   * sequence
	 */
	struct bt_ctf_field *cur_base;

	/*
	 * Current concrete type index in current base field:
	 *
	 *   * base field is a structure: field index
	 *   * base field is a sequence/array: element index
	 */
	uint64_t cur_index;
};

struct stack {
	/* entries (struct stack_entry *) (top is last element) */
	GPtrArray *entries;
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

struct bt_ctf_ir_packet_reader_ctx *bt_ctf_ir_packet_reader_create(
	struct bt_ctf_trace *trace, size_t max_request_len,
	struct bt_ctf_ir_packet_reader_ops ops, void *data)
{
	struct bt_ctf_ir_packet_reader_ctx *ctx = NULL;

	ctx = g_new0(struct bt_ctf_ir_packet_reader_ctx, 1);

	if (!ctx) {
		goto end;
	}

	ctx->ops = ops;
	ctx->max_request_len = max_request_len;
	ctx->trace = trace;
	bt_ctf_trace_get(ctx->trace);
	ctx->user_data = data;

end:
	return ctx;
}

void bt_ctf_ir_packet_reader_destroy(struct bt_ctf_ir_packet_reader_ctx *ctx)
{
	bt_ctf_trace_put(ctx->trace);
	g_free(ctx);
}

enum bt_ctf_ir_packet_reader_status bt_ctf_ir_packet_reader_reset(
	struct bt_ctf_ir_packet_reader_ctx *ctx)
{
	return 0;
}

static
enum bt_ctf_ir_packet_reader_status decode_packet_header(
	struct bt_ctf_ir_packet_reader_ctx *ctx)
{
	enum bt_ctf_ir_packet_reader_status ret;

	/* packet header already decoded? */
	if (ctx->header_is_complete) {
		ret = BT_CTF_IR_PACKET_READER_STATUS_OK;
		goto end;
	}

	/* continue decoding packet header */

end:
	return ret;
}

enum bt_ctf_ir_packet_reader_status bt_ctf_ir_packet_reader_get_header(
	struct bt_ctf_ir_packet_reader_ctx *ctx,
	struct bt_ctf_field **packet_header)
{
	enum bt_ctf_ir_packet_reader_status status;

	/* decode packet header*/
	status = decode_packet_header(ctx);

	/* packet header completely decoded? */
	if (status == BT_CTF_IR_PACKET_READER_STATUS_OK) {
		*packet_header = ctx->header;
		bt_ctf_field_get(*packet_header);
	}

	return status;
}

static
enum bt_ctf_ir_packet_reader_status decode_packet_context(
	struct bt_ctf_ir_packet_reader_ctx *ctx)
{
	enum bt_ctf_ir_packet_reader_status ret;

	/* packet context already decoded? */
	if (ctx->context_is_complete) {
		ret = BT_CTF_IR_PACKET_READER_STATUS_OK;
		goto end;
	}

	/* continue decoding packet context */

end:
	return ret;
}

enum bt_ctf_ir_packet_reader_status bt_ctf_ir_packet_reader_get_context(
	struct bt_ctf_ir_packet_reader_ctx *ctx,
	struct bt_ctf_field **packet_context)
{
	enum bt_ctf_ir_packet_reader_status status;

	/* decode packet header*/
	status = decode_packet_context(ctx);

	/* packet header completely decoded? */
	if (status == BT_CTF_IR_PACKET_READER_STATUS_OK) {
		*packet_context = ctx->context;
		bt_ctf_field_get(*packet_context);
	}

	return status;
}

enum bt_ctf_ir_packet_reader_status bt_ctf_ir_packet_reader_get_next_event(
	struct bt_ctf_ir_packet_reader_ctx *ctx,
	struct bt_ctf_event **event)
{
	return BT_CTF_IR_PACKET_READER_STATUS_OK;
}
