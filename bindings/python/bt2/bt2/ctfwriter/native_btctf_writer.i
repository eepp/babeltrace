/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2018 Francis Deslauriers <francis.deslauriers@efficios.com>
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

struct bt_ctf_writer;
struct bt_ctf_stream;
struct bt_ctf_stream_class;
struct bt_ctf_clock;

struct bt_ctf_writer *bt_ctf_writer_create(const char *path);
struct bt_ctf_trace *bt_ctf_writer_get_trace(
		struct bt_ctf_writer *writer);
struct bt_ctf_stream *bt_ctf_writer_create_stream(
		struct bt_ctf_writer *writer,
		struct bt_ctf_stream_class *stream_class);
int bt_ctf_writer_add_environment_field(struct bt_ctf_writer *writer,
		const char *name,
		const char *value);
int bt_ctf_writer_add_environment_field_int64(
		struct bt_ctf_writer *writer,
		const char *name,
		int64_t value);
int bt_ctf_writer_add_clock(struct bt_ctf_writer *writer,
		struct bt_ctf_clock *clock);
char *bt_ctf_writer_get_metadata_string(struct bt_ctf_writer *writer);
void bt_ctf_writer_flush_metadata(struct bt_ctf_writer *writer);
int bt_ctf_writer_set_byte_order(struct bt_ctf_writer *writer,
		enum bt_ctf_byte_order byte_order);
