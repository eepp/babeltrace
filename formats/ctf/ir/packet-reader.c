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
	return BT_CTF_IR_PACKET_READER_STATUS_OK;
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

end:
	return status;
}

static
enum bt_ctf_ir_packet_reader_status decode_packet_context(
	struct bt_ctf_ir_packet_reader_ctx *ctx)
{
	return BT_CTF_IR_PACKET_READER_STATUS_OK;
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

end:
	return status;
}

enum bt_ctf_ir_packet_reader_status bt_ctf_ir_packet_reader_get_next_event(
	struct bt_ctf_ir_packet_reader_ctx *ctx,
	struct bt_ctf_event **event)
{
	return BT_CTF_IR_PACKET_READER_STATUS_OK;
}
