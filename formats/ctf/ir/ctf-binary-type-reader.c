/*
 * Babeltrace - CTF binary type reader
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

/*
 * Hello, fellow developer, and welcome to another free lesson of
 * computer engineering!
 *
 * Today, you will learn how to implement a CTF binary type reader which
 * is versatile enough to stop in the middle of the decoding of a CTF
 * type when no more data is available, and resume later when data
 * becomes available again.
 *
 *
 * Decoding fields
 * ===============
 *
 * This CTF type binary reader depends on user-provided medium
 * operations, implementing a function used by this reader to request
 * more bytes of the file to decode. This medium function,
 * request_bytes(), might return the BT_CTF_BTR_MEDIUM_STATUS_AGAIN
 * status code, in which case the type reader function (either
 * bt_ctf_btr_decode() or bt_ctf_btr_continue(), will return an
 * analogous status code to the caller and no bytes will be read. The
 * caller is then responsible for making sure that some data becomes
 * available from its medium, and needs to call bt_ctf_btr_continue()
 * to resume the decoding process.
 *
 * The ultimate job of this type reader is to convert a sequence of
 * bytes (a binary CTF file) to a sequence of user callback function
 * calls. There is one such user callback function per basic CTF type,
 * and two per compound type: one which signals the beginning of the
 * type, and the other signals the end.
 *
 * When a buffer is successfully returned by request_bytes(), the
 * previous one is not available anymore. Also, request_bytes() may
 * return a buffer of an arbitrary size.
 *
 * There are a few challenges with the chosen approach:
 *
 *   1. If there is, for example, 4 bytes left to read in the returned
 *      user buffer, and we need to read an 8-byte integer, how do we
 *      do this?
 *   2. If we have to stop in the middle of a decoding process because
 *      request_bytes() returned BT_CTF_BTR_MEDIUM_STATUS_AGAIN, how do
 *	we remember where we were in the current compound type, and how
 *	do we continue from there later?
 *
 * The solution for challenge #1 is easy: keep a stitch buffer, in which
 * bytes from different buffers are appended until everything is there
 * to decode a whole _basic_ type.
 *
 * The current solution for challenge #2 is to keep a current visit
 * stack in the type reader context. The top of the stack always
 * contains the current parent type of the next type to be visited.
 * This parent type will be either a structure, a variant, an array,
 * or a sequence. The top of the stack also contains the index, within
 * the parent type, of the next type to be visited. When this type is
 * a basic, readable one (integer, floating point number, enumeration,
 * or string byte), and there's enough data left in the medium buffer
 * to decode it, depending on its size and alignment, it is decoded,
 * and the appropriate user callback function is called with its raw
 * value. If the next type to read is a compound type (structure,
 * variant, array, sequence), the begin user callback function for this
 * type is called and then the type is pushed on the visit stack as the
 * new current parent type. In some cases, the current position within
 * the medium buffer could be updated because of custom alignment of
 * compound types.
 *
 *
 * Example
 * -------
 *
 * Let's try an example. For the sake of simplicity, we'll use type
 * sizes and alignments which are multiples of 8 bits (always fit in
 * whole bytes). Keep in mind, however, that this technique also works
 * with sizes and alignments which are multiple of one bit.
 *
 * The root type to decode is:
 *
 *     struct            align = 8
 *       a: int	         align = 8     size = 16
 *       b: int	         align = 32    size = 32
 *       c: int	         align = 8     size = 8
 *       d: struct       align = 64
 *           e: float    align = 32    size = 32
 *           f: array    length = 5
 *             int       align = 8     size = 32
 *           g: int      align = 8     size = 64
 *       h: float        align = 32    size = 32
 *       j: array        length = 3
 *           enum        align = 8     size = 8
 *       k: int          align = 64    size = 64
 *
 * The bytes to decode are (`x` means one byte of padding):
 *
 *     +--------+-----------------+--------------+
 *     | Offset | Bytes	          | Struct field |
 *     +========+=================+==============+
 *     |      0 | i i             | root.a       |
 *     |      2 | x x             |              |
 *     |      4 | i i i i         | root.b       |
 *     |      8 | i               | root.c       |
 *     |      9 | x x x x x x x   |              |
 *     |     16 | f f f f         | root.d.e     |
 *     |     20 | i i i i         | root.d.f[0]  |
 *     |     24 | i i i i         | root.d.f[1]  |
 *     |     28 | i i i i         | root.d.f[2]  |
 *     |     32 | i i i i         | root.d.f[3]  |
 *     |     36 | i i i i         | root.d.f[4]  |
 *     |     40 | i i i i i i i i | root.d.g     |
 *     |     48 | f f f f         | root.h       |
 *     |     52 | e               | root.j[0]    |
 *     |     53 | e               | root.j[1]    |
 *     |     54 | e               | root.j[2]    |
 *     |     55 | x               |              |
 *     |     56 | i i i i i i i i | root.k       |
 *     +--------+-----------------+--------------+
 *
 * Total buffer size is 64 bytes.
 *
 * We'll now simulate a complete decoding process. Three calls to the
 * type reader API will be needed to finish the decoding, since two
 * calls will be interrupted by the medium returning the infamous
 * BT_CTF_BTR_MEDIUM_STATUS_AGAIN status code. Assume the maximum length
 * to request to the medium is 16 bytes.
 *
 * Let's do this, in 28 easy steps:
 *
 *   1.  User calls bt_ctf_btr_decode() with the type shown above.
 *   2.  Root type is a structure. Call struct_begin(). Push type on
 *       the currently (empty) stack, as the current parent type. Set
 *       current index to 0.
 *
 *       Current stack is:
 *
 *           Structure (root)    Index = 0    <-- top
 *
 *   3.  We need to read a 2-byte integer. Do we have at least 2 bytes
 *       left in the medium-provided buffer? No, 0 bytes are left.
 *       Request 16 bytes from the medium. Medium returns 16 bytes. Set
 *       current buffer position to 0. Read 2 bytes. Call
 *       unsigned_integer() with integer value. Set current index to 1.
 *       Set current buffer position to 2.
 *   4.  We need to read a 4-byte integer after having skipped 2 bytes
 *       of padding. Do we have at least 6 bytes left in the buffer?
 *       Yes, 14 bytes are left. Set current buffer position to 4. Read
 *       4 bytes. Call unsigned_integer() with integer value. Set
 *       current index to 2. Set current buffer position to 8.
 *   5.  We need to read a 1-byte integer. Do we have at least 1 byte
 *       left in the buffer? Yes, 8 bytes are left. Read 1 byte. Call
 *       unsigned_integer() with integer value. Set current index to 3.
 *       Set current buffer position to 9.
 *   6.  Type at index 3 is a structure. Call struct_begin(). Push type
 *       on the stack as the current parent type. Set current index to
 *       0. We need to skip 5 bytes of padding. Do we have at least 5
 *       bytes left in the buffer? Yes, 5 bytes are left. Set current
 *       buffer position to 16.
 *
 *       Current stack is:
 *
 *           Structure (d)       Index = 0    <-- top
 *           Structure (root)    Index = 3
 *
 *   7.  We need to read a 4-byte floating point number. Do we have at
 *       least 4 bytes left in the buffer? No, 0 bytes are left.
 *       Request 16 bytes from the medium. User returns the
 *       BT_CTF_BTR_MEDIUM_STATUS_AGAIN status code. bt_ctf_btr_decode()
 *       returns BT_CTF_BTR_STATUS_AGAIN to the user.
 *   8.  User makes sure some data becomes available from its medium.
 *       User calls bt_ctf_btr_continue() to continue.
 *   9.  We need to read a 4-byte floating point number. Do we have at
 *       least 4 bytes left in the buffer? No, 0 bytes are left.
 *       Request 16 bytes from the medium. Medium returns 10 bytes. Set
 *       current buffer position to 0. Read 4 bytes. Call
 *       floating_point() with floating point number value. Set current
 *       index to 1. Set current buffer position to 4.
 *   10. Type at index 1 is an array. Call array_begin(). Push type on
 *       the stack as the current parent type. Set current index to 0.
 *
 *       Current stack is:
 *
 *           Array     (d.f)     Index = 0    <-- top
 *           Structure (d)       Index = 1
 *           Structure (root)    Index = 3
 *
 *   11. We need to read a 4-byte integer. Do we have at least 4 bytes
 *       left in the buffer? Yes, 6 bytes are left. Read 4 bytes. Call
 *       unsigned_integer() with integer value. Set current index to 1.
 *       Set current buffer position to 8.
 *   12. We need to read a 4-byte integer. Do we have at least 4 bytes
 *       left in the buffer? No, 2 bytes are left. Read 2 bytes,
 *       and append them to the stitch buffer. Set current buffer
 *       position to 10. Request 16 bytes from the medium. Medium
 *       returns 14 bytes. Set current buffer position to 0. Read 2
 *       bytes, and append them to the stitch buffer. Decode the 4-byte
 *       integer in the stitch buffer. Call unsigned_integer() with
 *       integer value. Set current index to 2. Set current buffer
 *       position to 2.
 *   13. We need to read a 4-byte integer. Do we have at least 4 bytes
 *       left in the buffer? Yes, 12 bytes are left. Read 4 bytes. Call
 *       unsigned_integer() with integer value. Set current index to 3.
 *       Set current buffer position to 6.
 *   14. We need to read a 4-byte integer. Do we have at least 4 bytes
 *       left in the buffer? Yes, 8 bytes are left. Read 4 bytes. Call
 *       unsigned_integer() with integer value. Set current index to 4.
 *       Set current buffer position to 10.
 *   15. We need to read a 4-byte integer. Do we have at least 4 bytes
 *       left in the buffer? Yes, 4 bytes are left. Read 4 bytes. Call
 *       unsigned_integer() with integer value. Set current index to 5.
 *       Set current buffer position to 14.
 *   16. Current index equals parent type's length (5): pop stack's
 *       top entry. Call array_end(). Set current index to 2.
 *
 *       Current stack is:
 *
 *           Structure (d)       Index = 2    <-- top
 *           Structure (root)    Index = 3
 *
 *   17. We need to read an 8-byte integer. Do we have at least 8 bytes
 *       left in the buffer? No, 0 bytes are left. Request 16 bytes from
 *       the medium. Medium returns the BT_CTF_BTR_MEDIUM_STATUS_AGAIN
 *       status code. bt_ctf_btr_continue() returns
 *       BT_CTF_BTR_STATUS_AGAIN to the user.
 *   18. User makes sure some data becomes available from its medium.
 *       User calls bt_ctf_btr_continue() to continue.
 *   19. We need to read an 8-byte integer. Do we have at least 8 bytes
 *       left in the buffer? Nol, 0 bytes are left. Request 16 bytes from
 *       the user. User returns 16 bytes. Set current buffer position to
 *       0. Read 8 bytes, create integer field, set its value, and
 *       append it to the current parent field. Set current index to
 *       3. Set current buffer position to 8.
 *   20. Current index equals parent field's length (3): pop stack's
 *       top entry. Set current index to 4.
 *
 *       Current stack is:
 *
 *           Structure (root)    Index = 4    <-- top
 *
 *   21. We need to read a 4-byte floating point number. Do we have at
 *       least 4 bytes left in the buffer? Yes, 8 bytes are left.
 *       Read 4 bytes, create floating point number field, set its
 *       value, and append it to the current parent field. Set current
 *       index to 5. Set current buffer position to 12.
 *   22. Field at index 5 is an array. Create an array field. Append it
 *       to the current parent field. Push it on the stack as the
 *       current parent field. Set current index to 0.
 *
 *       Current stack is:
 *
 *           Array     (j)       Index = 0    <-- top
 *           Structure (root)    Index = 5
 *
 *   23. We need to read a 1-byte enumeration. Do we have at least 1
 *       byte left in the buffer? Yes, 4 bytes are left. Read 1 byte,
 *       create enumeration field, set its value, and append it to the
 *       current parent field. Set current index to 1. Set current
 *       buffer position to 13.
 *   24. We need to read a 1-byte enumeration. Do we have at least 1
 *       byte left in the buffer? Yes, 3 bytes are left. Read 1 byte,
 *       create enumeration field, set its value, and append it to the
 *       current parent field. Set current index to 2. Set current
 *       buffer position to 14.
 *   25. We need to read a 1-byte enumeration. Do we have at least 1
 *       byte left in the buffer? Yes, 2 bytes are left. Read 1 byte,
 *       create enumeration field, set its value, and append it to the
 *       current parent field. Set current index to 3. Set current
 *       buffer position to 14.
 *   26. Current index equals parent field's length (3): pop stack's
 *       top entry. Set current index to 6.
 *
 *       Current stack is:
 *
 *           Structure (root)    Index = 6    <-- top
 *
 *   27. We need to read an 8-byte integer after having skipped 1 byte
 *       of padding. Do we have at least 9 bytes left in the buffer?
 *       No, 1 byte is left. Skip this byte as padding. Request 16
 *       bytes from the user. User returns 8 bytes. Set current buffer
 *       position to 0. Read 8 bytes, create integer field, set its
 *       value, and append it to the current parent field. Set current
 *       index to 7. Set current buffer position to 8.
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
 * string field, and then we set it as the current basic field. Assume
 * the maximum length to request to the user back-end is 16 bytes.
 *
 * 16 bytes are requested and returned. A null byte is searched for in
 * the returned buffer. None is found, so the whole 16-byte block is
 * appended to the current string field. Since no null byte was found,
 * the string field remains incomplete. 16 bytes are requested again,
 * and returned. A null byte is searched for in the returned buffer, and
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
 * TODO: this whole subsection is to be rewritten.
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
 * returns BT_CTF_MEDIUM_STATUS_EOS (end of stream), in which
 * case we return BT_CTF_STREAM_READER_STATUS_EOP to the caller.
 *
 * When the packet reader context is created, we're at the initial
 * state: nothing is decoded yet. We always have to go through the
 * packet header and context decoding states before reading events, so
 * even if the first API call is bt_ctf_stream_reader_get_next_event(),
 * the packet reader will still decode the packet header and context
 * before eventually decoding the first event, and returning it. Then
 * subsequent calls to bt_ctf_stream_reader_get_header() and
 * bt_ctf_stream_reader_get_context() will simply return the previously
 * decoded fields.
 *
 *                        - T H E   E N D -
 */

#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <babeltrace/ctf-ir/packet-reader.h>
#include <babeltrace/bitfield.h>
#include <babeltrace/ctf-ir/event-types.h>
#include <babeltrace/ctf-ir/event-fields.h>
#include <babeltrace/ctf-ir/stream-class.h>
#include <babeltrace/align.h>
#include <glib.h>

#define BYTES_TO_BITS(x)		((x) * 8)
#define BITS_TO_BYTES_FLOOR(x)		((x) >> 3)
#define BITS_TO_BYTES_CEIL(x)		(((x) + 7) >> 3)
#define IN_BYTE_OFFSET(at)		((at) & 7)

/*
 * A stack entry.
 */
struct stack_entry {
	/*
	 * Current base field, one of:
	 *
	 *   * structure
	 *   * array
	 *   * sequence
	 *   * variant
	 *
	 * Field is owned by this.
	 */
	struct bt_ctf_field *base;

	/* current base field type (owned by this) */
	struct bt_ctf_field_type *base_type;

	/* length of base field */
	int64_t base_len;

	/* index of next field to read */
	int64_t index;
};

/*
 * Visit stack.
 */
struct stack {
	/* entries (struct stack_entry *) (top is last element) */
	GPtrArray *entries;
};

/*
 * Global decoding state, as such:
 *
 *   * GDS_INIT: initializes the context to begin the decoding of an
 *     an entity. The entity to decode is ctx->entity. This state
 *     creates the first field for this entity's field type, and pushes
 *     it to the visit stack as its root entry.
 *   * GDS_DECODE: decode phase. The field decoding state handler is
 *     called here as long as it needs to continue, that is, as long as
 *     there's something on the visit stack.
 */
enum global_decoding_state {
	GDS_INIT,
	GDS_DECODE,
	GDS_DONE,
};

/*
 * Decoding entities.
 */
enum decoding_entity {
	ENTITY_TRACE_PACKET_HEADER,
	ENTITY_STREAM_PACKET_CONTEXT,
	ENTITY_STREAM_EVENT_HEADER,
	ENTITY_STREAM_EVENT_CONTEXT,
	ENTITY_EVENT_CONTEXT,
	ENTITY_EVENT_PAYLOAD,
};

/*
 * Field decoding state, as such:
 *
 *   * FDS_INIT: checks the current situation and takes an action.
 *     If there's no more field to decode for the current base, pops
 *     the stack and continues. If there's no more entry in the stack,
 *     sets the context's last decoded entity and stops. Otherwise,
 *     creates the next field to decode and changes to FDS_SKIP_PADDING.
 *   * FDS_SKIP_PADDING: skips the padding before the next field to
 *     decode. If padding was skipped for a compound type, goes back
 *     to FDS_INIT. Otherwise, goes to FDS_DECODE_*_FIELD_BEGIN.
 *   * FDS_DECODE_*_FIELD_BEGIN: begins decoding a basic field,
 *     possibly decoding it entirely, in which case it goes back to
 *     FDS_INIT.
 *   * FDS_DECODE_*_FIELD_CONTINUE: continues decoding a basic field
 *     When done, sets the next field's value to the decoded value,
 *     and goes back to FDS_INIT.
 */
enum field_decoding_state {
	FDS_INIT,
	FDS_SKIP_PADDING,
	FDS_DECODE_BASIC_FIELD,
	FDS_DECODE_INTEGER_FIELD_BEGIN,
	FDS_DECODE_INTEGER_FIELD_CONTINUE,
	FDS_DECODE_FLOAT_FIELD_BEGIN,
	FDS_DECODE_FLOAT_FIELD_CONTINUE,
	FDS_DECODE_ENUM_FIELD_BEGIN,
	FDS_DECODE_ENUM_FIELD_CONTINUE,
	FDS_DECODE_STRING_FIELD_BEGIN,
	FDS_DECODE_STRING_FIELD_CONTINUE,
};

enum state_machine_action {
	SMA_CONTINUE,
	SMA_DONE,
	SMA_ERROR,
};

/*
 * Packet reader context, where everything important lives.
 */
struct bt_ctf_stream_reader_ctx {
	/* visit stack */
	struct stack *stack;

	/*
	 * Last decoded entity.
	 *
	 * This variable is only used for communication between the
	 * decoding functions and the state handling function. It must
	 * be NULL whenever a packet reader API function is entered or
	 * exited.
	 */
	struct bt_ctf_field *last_decoded_entity;

	/* current basic field being decoded stuff */
	struct {
		struct bt_ctf_field *field;
		struct bt_ctf_field_type *field_type;
	} cur_basic;

	/* stitch buffer stuff */
	struct {
		uint8_t buf[16];
		size_t offset;
		size_t length;
	} stitch;

	/* trace and classes (owned by this) */
	struct {
		struct bt_ctf_trace *trace;
		struct bt_ctf_stream_class *stream_class;
		struct bt_ctf_event_class *event_class;
	} meta;

	/* current concrete stuff (owned by this) */
	struct {
		struct bt_ctf_field *trace_packet_header;
		struct bt_ctf_field *stream_packet_context;
		struct bt_ctf_field *stream_event_header;
		struct bt_ctf_field *stream_event_context;
		struct bt_ctf_field *event_context;
		struct bt_ctf_field *event_payload;
	} entities;

	/* state variables */
	struct {
		/* current global decoding state */
		enum global_decoding_state global;

		/* current entity being decoded */
		enum decoding_entity entity;

		/* current field decoding state */
		enum field_decoding_state field;

		/* true to skip the padding of the current base field */
		bool skip_base_padding;
	} state;

	/* user buffer stuff */
	struct {
		const uint8_t *addr;
		size_t stream_offset;
		size_t at;
		size_t length;
	} buf;

	/* stream reader stuff */
	struct {
		struct bt_ctf_medium_ops ops;
		size_t max_request_len;
		void *user_data;
	} medium;

	/* current packet size (bits) (-1 if unknown) */
	size_t cur_packet_size;

	/* current content size (bits) (-1 if unknown) */
	size_t cur_content_size;
};

static
void stack_entry_free_func(gpointer data)
{
	struct stack_entry *entry = data;

	bt_ctf_field_put(entry->base);
	bt_ctf_field_type_put(entry->base_type);
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
int stack_push(struct stack *stack, struct bt_ctf_field *base,
	struct bt_ctf_field_type *base_type, int64_t base_len)
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

	entry->base = base;
	bt_ctf_field_get(entry->base);
	entry->base_type = base_type;
	bt_ctf_field_type_get(entry->base_type);
	entry->base_len = base_len;
	g_ptr_array_add(stack->entries, entry);

end:
	return ret;
}

static inline
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

static inline
struct stack_entry *stack_top(struct stack *stack)
{
	assert(stack);
	assert(stack_size(stack));

	return g_ptr_array_index(stack->entries, stack->entries->len - 1);
}

static inline
bool stack_empty(struct stack *stack)
{
	return stack_size(stack) == 0;
}

static inline
enum bt_ctf_stream_reader_status sr_status_from_m_status(
	enum bt_ctf_medium_status m_status)
{
	enum bt_ctf_stream_reader_status sr_status;

	switch (m_status) {
	case BT_CTF_MEDIUM_STATUS_AGAIN:
		sr_status = BT_CTF_STREAM_READER_STATUS_AGAIN;
		break;

	case BT_CTF_MEDIUM_STATUS_ERROR:
		sr_status = BT_CTF_STREAM_READER_STATUS_ERROR;
		break;

	case BT_CTF_MEDIUM_STATUS_INVAL:
		sr_status = BT_CTF_STREAM_READER_STATUS_INVAL;
		break;

	case BT_CTF_MEDIUM_STATUS_EOS:
		sr_status = BT_CTF_STREAM_READER_STATUS_EOS;
		break;

	default:
		sr_status = BT_CTF_STREAM_READER_STATUS_OK;
		break;
	}

	return sr_status;
}

static inline
size_t available_bits(struct bt_ctf_stream_reader_ctx *ctx)
{
	return ctx->buf.length - ctx->buf.at;
}

static inline
void consume_bits(struct bt_ctf_stream_reader_ctx *ctx, size_t incr)
{
	ctx->buf.at += incr;
}

static inline
bool has_enough_bits(struct bt_ctf_stream_reader_ctx *ctx, size_t len)
{
	return available_bits(ctx) >= len;
}

static
enum bt_ctf_stream_reader_status request_bytes(
	struct bt_ctf_stream_reader_ctx *ctx)
{
	uint8_t *buffer_addr;
	size_t buffer_len;
	enum bt_ctf_medium_status m_status;

	m_status = ctx->medium.ops.get_next_bytes(ctx->medium.max_request_len,
		&buffer_len, &buffer_addr, ctx->medium.user_data);

	if (m_status == BT_CTF_MEDIUM_STATUS_OK) {
		ctx->buf.stream_offset += ctx->buf.length;
		ctx->buf.at = 0;
		ctx->buf.length = BYTES_TO_BITS(buffer_len);
		ctx->buf.addr = buffer_addr;
	}

	return sr_status_from_m_status(m_status);
}

static inline
enum bt_ctf_stream_reader_status ensure_available_bits(
	struct bt_ctf_stream_reader_ctx *ctx)
{
	enum bt_ctf_stream_reader_status status =
		BT_CTF_STREAM_READER_STATUS_OK;

	if (available_bits(ctx) == 0) {
		/*
		 * This cannot return BT_CTF_STREAM_READER_STATUS_OK
		 * and no bits.
		 */
		status = request_bytes(ctx);
	}

	return status;
}

static inline
size_t stream_at(struct bt_ctf_stream_reader_ctx *ctx)
{
	return ctx->buf.stream_offset + ctx->buf.at;
}

static inline
int64_t get_field_length(struct bt_ctf_stream_reader_ctx *ctx,
	struct bt_ctf_field_type *field_type)
{
	int64_t length;

	switch (bt_ctf_field_type_get_type_id(field_type)) {
	case CTF_TYPE_STRUCT:
		length = (int64_t) bt_ctf_field_type_structure_get_field_count(
			field_type);
		break;

	case CTF_TYPE_VARIANT:
		length = (int64_t) bt_ctf_field_type_variant_get_field_count(
			field_type);
		break;

	case CTF_TYPE_ARRAY:
		length = bt_ctf_field_type_array_get_length(field_type);
		break;

	default:
		length = -1;
	}

	return length;
}

static inline
int get_basic_field_length(struct bt_ctf_field_type *field_type)
{
	int size;

	switch (bt_ctf_field_type_get_type_id(field_type)) {
	case CTF_TYPE_INTEGER:
		size = bt_ctf_field_type_integer_get_size(field_type);
		break;

	case CTF_TYPE_FLOAT:
	{
		int exp_dig, mant_dig;

		exp_dig =
			bt_ctf_field_type_floating_point_get_exponent_digits(
				field_type);
		mant_dig =
			bt_ctf_field_type_floating_point_get_mantissa_digits(
				field_type);

		if (exp_dig < 0 || mant_dig < 0) {
			size = -1;
		}

		size = exp_dig + mant_dig;
		break;
	}

	case CTF_TYPE_ENUM:
	{
		struct bt_ctf_field_type *int_type;

		int_type = bt_ctf_field_type_enumeration_get_container_type(
			field_type);

		if (!int_type) {
			size = -1;
			goto end;
		}

		size = get_basic_field_length(int_type);
		bt_ctf_field_type_put(int_type);
		break;
	}

	case CTF_TYPE_STRING:
		size = 8;
		break;

	default:
		size = -1;
		break;
	}

end:
	return size;
}

static
void stitch_reset(struct bt_ctf_stream_reader_ctx *ctx)
{
	ctx->stitch.offset = 0;
	ctx->stitch.length = 0;
}

static
void stitch_append_from_buf(struct bt_ctf_stream_reader_ctx *ctx, size_t length)
{
	size_t stitch_byte_at =
		BITS_TO_BYTES_FLOOR(ctx->stitch.offset + ctx->stitch.length);
	size_t buf_byte_at = BITS_TO_BYTES_FLOOR(ctx->buf.at);
	size_t nb_bytes = BITS_TO_BYTES_CEIL(length);

	assert(nb_bytes > 0);
	memcpy(&ctx->stitch.buf[stitch_byte_at], &ctx->buf.addr[buf_byte_at],
		nb_bytes);
	ctx->stitch.length += length;
	consume_bits(ctx, length);
}

static
void stitch_append_from_remaining_buf(struct bt_ctf_stream_reader_ctx *ctx)
{
	stitch_append_from_buf(ctx, available_bits(ctx));
}

static
void stitch_set_from_remaining_buf(struct bt_ctf_stream_reader_ctx *ctx)
{
	stitch_reset(ctx);
	ctx->stitch.offset = IN_BYTE_OFFSET(ctx->buf.at);
	stitch_append_from_remaining_buf(ctx);
}

#if 0
static inline
enum bt_ctf_stream_reader_status decode_integer(
	struct bt_ctf_stream_reader_ctx *ctx, struct bt_ctf_field *field,
	struct bt_ctf_field_type *field_type, int read_len)
{
	int ret;
	int signd;
	enum bt_ctf_byte_order bo;
	enum bt_ctf_stream_reader_status status =
		BT_CTF_STREAM_READER_STATUS_OK;

	signd = bt_ctf_field_type_integer_get_signed(field_type);

	if (signd < 0) {
		status = BT_CTF_STREAM_READER_STATUS_ERROR;
		goto end;
	}

	bo = bt_ctf_field_type_get_byte_order(field_type);

	if (bo == BT_CTF_BYTE_ORDER_BIG_ENDIAN ||
			bo == BT_CTF_BYTE_ORDER_NETWORK) {
		if (signd) {
			int64_t v;

			bt_bitfield_read_be(ctx->buf, uint8_t,
				ctx->at, read_len, &v);
			ret = bt_ctf_field_signed_integer_set_value(
				field, v);
		} else {
			uint64_t v;

			bt_bitfield_read_be(ctx->buf, uint8_t,
				ctx->at, read_len, &v);
			ret = bt_ctf_field_unsigned_integer_set_value(
				field, v);
		}
	} else if (bo == BT_CTF_BYTE_ORDER_LITTLE_ENDIAN) {
		if (signd) {
			int64_t v;

			bt_bitfield_read_le(ctx->buf, uint8_t,
				ctx->at, read_len, &v);
			ret = bt_ctf_field_signed_integer_set_value(
				field, v);
		} else {
			uint64_t v;

			bt_bitfield_read_le(ctx->buf, uint8_t,
				ctx->at, read_len, &v);
			ret = bt_ctf_field_unsigned_integer_set_value(
				field, v);
		}
	} else {
		status = BT_CTF_STREAM_READER_STATUS_ERROR;
		goto end;
	}

	if (ret < 0) {
		status = BT_CTF_STREAM_READER_STATUS_ERROR;
		goto end;
	}

end:
	return status;
}

static inline
enum bt_ctf_stream_reader_status decode_float(
	struct bt_ctf_stream_reader_ctx *ctx, struct bt_ctf_field *field,
	struct bt_ctf_field_type *field_type, int read_len)
{
	int ret;
	double dblval;
	enum bt_ctf_byte_order bo;
	enum bt_ctf_stream_reader_status status =
		BT_CTF_STREAM_READER_STATUS_OK;

	union {
		uint32_t u;
		float f;
	} f32;

	union {
		uint64_t u;
		double f;
	} f64;

	bo = bt_ctf_field_type_get_byte_order(field_type);

	switch (read_len) {
	case 32:
	{
		if (bo == BT_CTF_BYTE_ORDER_BIG_ENDIAN ||
				bo == BT_CTF_BYTE_ORDER_NETWORK) {
			bt_bitfield_read_be(ctx->buf, uint8_t,
					ctx->at, read_len, &f32.u);
		} else if (bo == BT_CTF_BYTE_ORDER_LITTLE_ENDIAN) {
			bt_bitfield_read_le(ctx->buf, uint8_t,
					ctx->at, read_len, &f32.u);
		} else {
			status = BT_CTF_STREAM_READER_STATUS_ERROR;
			goto end;
		}

		dblval = (double) f32.f;
		break;
	}

	case 64:
	{
		if (bo == BT_CTF_BYTE_ORDER_BIG_ENDIAN ||
				bo == BT_CTF_BYTE_ORDER_NETWORK) {
			bt_bitfield_read_be(ctx->buf, uint8_t,
					ctx->at, read_len, &f64.u);
		} else if (bo == BT_CTF_BYTE_ORDER_LITTLE_ENDIAN) {
			bt_bitfield_read_le(ctx->buf, uint8_t,
					ctx->at, read_len, &f64.u);
		} else {
			status = BT_CTF_STREAM_READER_STATUS_ERROR;
			goto end;
		}

		dblval = f64.f;
		break;
	}

	default:
		status = BT_CTF_STREAM_READER_STATUS_ERROR;
		goto end;
	}

	ret = bt_ctf_field_floating_point_set_value(field, dblval);

	if (ret < 0) {
		status = BT_CTF_STREAM_READER_STATUS_ERROR;
		goto end;
	}

end:
	return status;
}

static inline
enum bt_ctf_stream_reader_status decode_atomic_field(
	struct bt_ctf_stream_reader_ctx *ctx, struct stack_entry *top,
	struct bt_ctf_field *field, struct bt_ctf_field_type *field_type)
{
	int read_len;
	enum bt_ctf_stream_reader_status status =
		BT_CTF_STREAM_READER_STATUS_OK;

	read_len = get_basic_field_length(field_type);

	if (read_len <= 0) {
		status = BT_CTF_STREAM_READER_STATUS_ERROR;
		goto end;
	}

	/* request bits if needed */
	if (!has_enough_bits(ctx, read_len)) {
		enum bt_ctf_medium_status m_status;
		size_t request_len;

		if (ctx->step_by_step) {
			request_len = read_len;
		} else {
			// TODO: min(ctx->max_request_len, content_size)
			request_len = ctx->max_request_len;
		}

		m_status = request_bits(ctx, request_len);
		status = sr_status_from_m_status(m_status);
		goto end;
	}

	/* read atomic field */
	switch (bt_ctf_field_type_get_type_id(field_type)) {
	case CTF_TYPE_INTEGER:
		status = decode_integer(ctx, field, field_type, read_len);

		if (status != BT_CTF_STREAM_READER_STATUS_OK) {
			goto end;
		}
		break;

	case CTF_TYPE_FLOAT:
		status = decode_float(ctx, field, field_type, read_len);

		if (status != BT_CTF_STREAM_READER_STATUS_OK) {
			goto end;
		}
		break;

	default:
		status = BT_CTF_STREAM_READER_STATUS_ERROR;
		goto end;
	}

	/* update current buffer position */
	ctx->at += read_len;

	/* we decoded the field: increment stack top entry's index */
	top->index++;

end:
	return status;
}
#endif

static inline
enum state_machine_action handle_fds_init(struct bt_ctf_stream_reader_ctx *ctx,
	enum bt_ctf_stream_reader_status *status)
{
	struct bt_ctf_field_type *next_field_type = NULL;
	enum state_machine_action action = SMA_CONTINUE;
	struct bt_ctf_field *next_field = NULL;
	struct stack_entry *top;
	int64_t field_length;
	int ret;

	*status = BT_CTF_STREAM_READER_STATUS_OK;
	top = stack_top(ctx->stack);

	/* are we done decoding the fields of the base field? */
	if (top->index == top->base_len) {
		/* decoded the whole root field? */
		if (stack_size(ctx->stack) == 1) {
			/* set last decoded entity */
			ctx->last_decoded_entity = top->base;
			bt_ctf_field_get(ctx->last_decoded_entity);
			action = SMA_DONE;
		}

		stack_pop(ctx->stack);
		goto end;
	}

	/* create next field */
	switch (bt_ctf_field_type_get_type_id(top->base_type)) {
	case CTF_TYPE_STRUCT:
		next_field = bt_ctf_field_structure_get_field_by_index(
			top->base, top->index);
		break;

	case CTF_TYPE_ARRAY:
		next_field = bt_ctf_field_array_get_field(
			top->base, top->index);
		break;

	default:
		break;
	}

	if (!next_field) {
		action = SMA_ERROR;
		goto end;
	}

	/* get next field's type */
	next_field_type = bt_ctf_field_get_type(next_field);

	if (!next_field_type) {
		action = SMA_ERROR;
		goto end;
	}

	switch (bt_ctf_field_type_get_type_id(next_field_type)) {
	case CTF_TYPE_STRUCT:
	case CTF_TYPE_ARRAY:
	case CTF_TYPE_SEQUENCE:
	case CTF_TYPE_VARIANT:
		field_length = get_field_length(ctx, next_field_type);
		ret = stack_push(ctx->stack, next_field, next_field_type,
			field_length);

		if (ret) {
			action = SMA_ERROR;
			goto end;
		}

		top->index++;
		ctx->state.skip_base_padding = true;
		break;

	case CTF_TYPE_INTEGER:
	case CTF_TYPE_FLOAT:
	case CTF_TYPE_ENUM:
	case CTF_TYPE_STRING:
		ctx->state.skip_base_padding = false;
		bt_ctf_field_put(ctx->cur_basic.field);
		ctx->cur_basic.field = next_field;
		next_field = NULL;
		bt_ctf_field_type_put(ctx->cur_basic.field_type);
		ctx->cur_basic.field_type = next_field_type;
		next_field_type = NULL;
		break;

	default:
		assert(false);
		break;
	}

	ctx->state.field = FDS_SKIP_PADDING;

end:
	if (next_field) {
		bt_ctf_field_put(next_field);
	}

	if (next_field_type) {
		bt_ctf_field_type_put(next_field_type);
	}

	return action;
}

static inline
enum state_machine_action handle_fds_skip_padding(
	struct bt_ctf_stream_reader_ctx *ctx,
	enum bt_ctf_stream_reader_status *status)
{
	int field_alignment;
	unsigned int skip_bits;
	size_t aligned_stream_at;
	struct bt_ctf_field_type *field_type;
	enum state_machine_action action = SMA_CONTINUE;

	*status = BT_CTF_STREAM_READER_STATUS_OK;

	if (ctx->state.skip_base_padding) {
		struct stack_entry *top = stack_top(ctx->stack);

		field_type = top->base_type;
	} else {
		field_type = ctx->cur_basic.field_type;
	}

	/* get field's alignment */
	field_alignment = bt_ctf_field_type_get_alignment(field_type);

	if (field_alignment < 0) {
		action = SMA_ERROR;
		goto end;
	}

	/* compute how many bits we need to skip */
	aligned_stream_at = ALIGN(stream_at(ctx), field_alignment);
	skip_bits = aligned_stream_at - stream_at(ctx);

	/* nothing to skip? done */
	if (skip_bits == 0) {
		if (ctx->state.skip_base_padding) {
			ctx->state.field = FDS_INIT;
		} else {
			ctx->state.field = FDS_DECODE_BASIC_FIELD;
		}

		goto end;
	}

	*status = ensure_available_bits(ctx);

	if (*status != BT_CTF_STREAM_READER_STATUS_OK) {
		if (*status == BT_CTF_STREAM_READER_STATUS_ERROR) {
			action = SMA_ERROR;
		}

		goto end;
	}

	/* consume as many bits as possible in what's left */
	consume_bits(ctx, MIN(available_bits(ctx), skip_bits));

end:
	return action;
}

static inline
int decode_and_set_cur_basic_integer_field(
	struct bt_ctf_stream_reader_ctx *ctx,
	const uint8_t *buf, size_t at)
{
	int ret;
	int signd;
	int64_t field_length;
	enum bt_ctf_byte_order bo;

	signd = bt_ctf_field_type_integer_get_signed(ctx->cur_basic.field_type);
	field_length = get_basic_field_length(ctx->cur_basic.field_type);
	bo = bt_ctf_field_type_get_byte_order(ctx->cur_basic.field_type);

	if (signd) {
		int64_t v;

		if (bo == BT_CTF_BYTE_ORDER_BIG_ENDIAN ||
				bo == BT_CTF_BYTE_ORDER_NETWORK) {
			bt_bitfield_read_be(buf, uint8_t, at, field_length,
				&v);
		} else if (bo == BT_CTF_BYTE_ORDER_LITTLE_ENDIAN) {
			bt_bitfield_read_le(buf, uint8_t, at, field_length,
				&v);
		} else {
			ret = -1;
			goto end;
		}

		ret = bt_ctf_field_signed_integer_set_value(
			ctx->cur_basic.field, v);
	} else {
		uint64_t v;

		if (bo == BT_CTF_BYTE_ORDER_BIG_ENDIAN ||
				bo == BT_CTF_BYTE_ORDER_NETWORK) {
			bt_bitfield_read_be(buf, uint8_t, at, field_length,
				&v);
		} else if (bo == BT_CTF_BYTE_ORDER_LITTLE_ENDIAN) {
			bt_bitfield_read_le(buf, uint8_t, at, field_length,
				&v);
		} else {
			ret = -1;
			goto end;
		}

		ret = bt_ctf_field_unsigned_integer_set_value(
			ctx->cur_basic.field, v);
	}

end:
	return ret;
}

static inline
enum state_machine_action handle_fds_decode_integer_field_continue(
	struct bt_ctf_stream_reader_ctx *ctx,
	enum bt_ctf_stream_reader_status *status)
{
	size_t available;
	int64_t field_length;
	int64_t needed_bits;
	enum state_machine_action action = SMA_CONTINUE;

	field_length = get_basic_field_length(ctx->cur_basic.field_type);
	*status = ensure_available_bits(ctx);

	if (*status != BT_CTF_STREAM_READER_STATUS_OK) {
		if (*status == BT_CTF_STREAM_READER_STATUS_ERROR) {
			action = SMA_ERROR;
		}

		goto end;
	}

	available = available_bits(ctx);
	needed_bits = field_length - ctx->stitch.length;

	if (needed_bits <= available) {
		int ret;

		/* we have all the bits; append to stitch, then decode/set */
		stitch_append_from_buf(ctx, needed_bits);
		ret = decode_and_set_cur_basic_integer_field(ctx,
			ctx->stitch.buf, ctx->stitch.offset);

		if (ret) {
			action = SMA_ERROR;
			goto end;
		}

		stack_top(ctx->stack)->index++;
		ctx->state.field = FDS_INIT;
		goto end;
	}

	/* we are here; it means we don't have enough data to decode this */
	stitch_append_from_remaining_buf(ctx);

end:
	return action;
}

static inline
enum state_machine_action handle_fds_decode_integer_field_begin(
	struct bt_ctf_stream_reader_ctx *ctx,
	enum bt_ctf_stream_reader_status *status)
{
	size_t available;
	int64_t field_length;
	enum state_machine_action action = SMA_CONTINUE;

	field_length = get_basic_field_length(ctx->cur_basic.field_type);
	*status = ensure_available_bits(ctx);

	if (*status != BT_CTF_STREAM_READER_STATUS_OK) {
		if (*status == BT_CTF_STREAM_READER_STATUS_ERROR) {
			action = SMA_ERROR;
		}

		goto end;
	}

	available = available_bits(ctx);

	if (field_length <= available) {
		/* we have all the bits; decode and set now */
		int ret = decode_and_set_cur_basic_integer_field(ctx,
			ctx->buf.addr, ctx->buf.at);

		if (ret) {
			action = SMA_ERROR;
			goto end;
		}

		stack_top(ctx->stack)->index++;
		consume_bits(ctx, field_length);
		ctx->state.field = FDS_INIT;
		goto end;
	}

	/* we are here; it means we don't have enough data to decode this */
	stitch_set_from_remaining_buf(ctx);
	ctx->state.field = FDS_DECODE_INTEGER_FIELD_CONTINUE;

end:
	return action;
}

static inline
enum state_machine_action handle_fds_decode_basic_field(
	struct bt_ctf_stream_reader_ctx *ctx,
	enum bt_ctf_stream_reader_status *status)
{
	switch (bt_ctf_field_type_get_type_id(ctx->cur_basic.field_type)) {
	case CTF_TYPE_INTEGER:
		ctx->state.field = FDS_DECODE_INTEGER_FIELD_BEGIN;
		break;

	case CTF_TYPE_FLOAT:
		ctx->state.field = FDS_DECODE_FLOAT_FIELD_BEGIN;
		break;

	case CTF_TYPE_ENUM:
		ctx->state.field = FDS_DECODE_ENUM_FIELD_BEGIN;
		break;

	case CTF_TYPE_STRING:
		ctx->state.field = FDS_DECODE_STRING_FIELD_BEGIN;
		break;

	default:
		assert(false);
	}

	return SMA_CONTINUE;
}

static inline
enum state_machine_action handle_fd_state(struct bt_ctf_stream_reader_ctx *ctx,
	enum bt_ctf_stream_reader_status *status)
{
	enum state_machine_action action;

	switch (ctx->state.field) {
	case FDS_INIT:
		action = handle_fds_init(ctx, status);
		break;

	case FDS_SKIP_PADDING:
		action = handle_fds_skip_padding(ctx, status);
		break;

	case FDS_DECODE_BASIC_FIELD:
		action = handle_fds_decode_basic_field(ctx, status);
		break;

	case FDS_DECODE_INTEGER_FIELD_BEGIN:
		action = handle_fds_decode_integer_field_begin(ctx, status);
		break;

	case FDS_DECODE_INTEGER_FIELD_CONTINUE:
		action = handle_fds_decode_integer_field_continue(ctx, status);
		break;
	}

	return action;
}

static inline
struct bt_ctf_field_type *get_ctx_entity_field_type(
	struct bt_ctf_stream_reader_ctx *ctx)
{
	struct bt_ctf_field_type *field_type = NULL;

	switch (ctx->state.entity) {
	case ENTITY_TRACE_PACKET_HEADER:
		field_type =
			bt_ctf_trace_get_packet_header_type(ctx->meta.trace);
		break;

	case ENTITY_STREAM_PACKET_CONTEXT:
		field_type =
			bt_ctf_stream_class_get_packet_context_type(
				ctx->meta.stream_class);
		break;

	case ENTITY_STREAM_EVENT_HEADER:
		field_type = bt_ctf_stream_class_get_event_header_type(
			ctx->meta.stream_class);
		break;

	case ENTITY_STREAM_EVENT_CONTEXT:
		field_type = bt_ctf_stream_class_get_event_context_type(
			ctx->meta.stream_class);
		break;

	case ENTITY_EVENT_CONTEXT:
		field_type = bt_ctf_event_class_get_context_type(
			ctx->meta.event_class);
		break;

	case ENTITY_EVENT_PAYLOAD:
		field_type = bt_ctf_event_class_get_payload_type(
			ctx->meta.event_class);
		break;
	}

	return field_type;
}

static inline
void move_last_decoded_entity_to_entity(struct bt_ctf_stream_reader_ctx *ctx)
{
	struct bt_ctf_field **dest_entity;

	assert(ctx->last_decoded_entity);

	switch (ctx->state.entity) {
	case ENTITY_TRACE_PACKET_HEADER:
		dest_entity = &ctx->entities.trace_packet_header;
		ctx->state.entity = ENTITY_STREAM_PACKET_CONTEXT;
		break;

	case ENTITY_STREAM_PACKET_CONTEXT:
		dest_entity = &ctx->entities.stream_packet_context;
		ctx->state.entity = ENTITY_STREAM_EVENT_HEADER;
		break;

	case ENTITY_STREAM_EVENT_HEADER:
		dest_entity = &ctx->entities.stream_event_header;
		ctx->state.entity = ENTITY_STREAM_EVENT_CONTEXT;
		break;

	case ENTITY_STREAM_EVENT_CONTEXT:
		dest_entity = &ctx->entities.stream_event_context;
		ctx->state.entity = ENTITY_EVENT_CONTEXT;
		break;

	case ENTITY_EVENT_CONTEXT:
		dest_entity = &ctx->entities.event_context;
		ctx->state.entity = ENTITY_EVENT_PAYLOAD;
		break;

	case ENTITY_EVENT_PAYLOAD:
		dest_entity = &ctx->entities.event_payload;
		ctx->state.entity = ENTITY_STREAM_EVENT_HEADER;
		break;
	}

	bt_ctf_field_put(*dest_entity);
	*dest_entity = ctx->last_decoded_entity;
	ctx->last_decoded_entity = NULL;
}

static inline
enum bt_ctf_stream_reader_status handle_gd_state(
	struct bt_ctf_stream_reader_ctx *ctx)
{
	int ret;
	int64_t length;
	enum state_machine_action action;
	struct bt_ctf_field *field = NULL;
	enum bt_ctf_stream_reader_status status;
	struct bt_ctf_field_type *field_type = NULL;

	status = BT_CTF_STREAM_READER_STATUS_OK;

	switch (ctx->state.global) {
	case GDS_INIT:
		/* get the appropriate field type for the current entity */
		field_type = get_ctx_entity_field_type(ctx);

		if (!field_type) {
			status = BT_CTF_STREAM_READER_STATUS_ERROR;
			goto end;
		}

		/* create the root field of the current entity */
		field = bt_ctf_field_create(field_type);

		if (!field) {
			status = BT_CTF_STREAM_READER_STATUS_ERROR;
			goto end;
		}

		length = get_field_length(ctx, field_type);

		if (length < 0) {
			status = BT_CTF_STREAM_READER_STATUS_ERROR;
			goto end;
		}

		/* push root field on stack */
		assert(stack_size(ctx->stack) == 0);
		ret = stack_push(ctx->stack, field, field_type, length);
		bt_ctf_field_put(field);
		field = NULL;
		bt_ctf_field_type_put(field_type);
		field_type = NULL;

		if (ret) {
			status = BT_CTF_STREAM_READER_STATUS_ERROR;
			goto end;
		}

		assert(!ctx->last_decoded_entity);
		ctx->cur_packet_size = -1;
		ctx->cur_content_size = -1;
		ctx->state.field = FDS_SKIP_PADDING;
		ctx->state.global = GDS_DECODE;
		ctx->state.skip_base_padding = true;
		break;

	case GDS_DECODE:
		action = handle_fd_state(ctx, &status);

		switch (action) {
		case SMA_ERROR:
			status = BT_CTF_STREAM_READER_STATUS_ERROR;
			goto end;

		case SMA_DONE:
			ctx->state.global = GDS_INIT;

			/* move current field to appropriate member */
			move_last_decoded_entity_to_entity(ctx);
			break;

		case SMA_CONTINUE:
			break;
		}
		break;

	case GDS_DONE:
		assert(false);
		break;
	}

end:
	if (field_type) {
		bt_ctf_field_type_put(field_type);
	}

	if (field) {
		bt_ctf_field_put(field);
	}

	return status;
}

struct bt_ctf_stream_reader_ctx *bt_ctf_stream_reader_create(
	struct bt_ctf_trace *trace, size_t max_request_len,
	struct bt_ctf_medium_ops ops, void *data)
{
	struct bt_ctf_stream_reader_ctx *ctx = NULL;

	ctx = g_new0(struct bt_ctf_stream_reader_ctx, 1);

	if (!ctx) {
		goto end;
	}

	ctx->meta.trace = trace;
	bt_ctf_trace_get(ctx->meta.trace);
	ctx->state.global = GDS_INIT;
	ctx->state.entity = ENTITY_TRACE_PACKET_HEADER;
	ctx->state.field = FDS_INIT;
	ctx->medium.ops = ops;

	if (max_request_len == 0) {
		ctx->medium.max_request_len = 4096;
	} else {
		ctx->medium.max_request_len = max_request_len;
	}

	ctx->medium.user_data = data;
	ctx->stack = stack_new();

	if (!ctx->stack) {
		bt_ctf_stream_reader_destroy(ctx);
		ctx = NULL;
		goto end;
	}

end:
	return ctx;
}

void bt_ctf_stream_reader_destroy(struct bt_ctf_stream_reader_ctx *ctx)
{
	bt_ctf_field_put(ctx->cur_basic.field);
	bt_ctf_field_type_put(ctx->cur_basic.field_type);
	bt_ctf_trace_put(ctx->meta.trace);
	bt_ctf_stream_class_put(ctx->meta.stream_class);
	bt_ctf_event_class_put(ctx->meta.event_class);
	bt_ctf_field_put(ctx->entities.trace_packet_header);
	bt_ctf_field_put(ctx->entities.stream_packet_context);
	bt_ctf_field_put(ctx->entities.stream_event_header);
	bt_ctf_field_put(ctx->entities.stream_event_context);
	bt_ctf_field_put(ctx->entities.event_context);
	bt_ctf_field_put(ctx->entities.event_payload);
	assert(!ctx->last_decoded_entity);
	stack_destroy(ctx->stack);
	g_free(ctx);
}

static
enum bt_ctf_stream_reader_status decode_packet_header(
	struct bt_ctf_stream_reader_ctx *ctx)
{
	enum bt_ctf_stream_reader_status status =
		BT_CTF_STREAM_READER_STATUS_OK;

	/* continue decoding packet header if needed */
	while (!ctx->entities.trace_packet_header) {
		status = handle_gd_state(ctx);

		if (status == BT_CTF_STREAM_READER_STATUS_AGAIN ||
				status == BT_CTF_STREAM_READER_STATUS_ERROR ||
				status == BT_CTF_STREAM_READER_STATUS_EOS) {
			goto end;
		}
	}

end:
	return status;
}

enum bt_ctf_stream_reader_status bt_ctf_stream_reader_get_header(
	struct bt_ctf_stream_reader_ctx *ctx,
	struct bt_ctf_field **packet_header)
{
	enum bt_ctf_stream_reader_status status;

	/* continue decoding packet header */
	status = decode_packet_header(ctx);

	if (ctx->entities.trace_packet_header) {
		*packet_header = ctx->entities.trace_packet_header;
		bt_ctf_field_get(*packet_header);
	}

	return status;
}

static
enum bt_ctf_stream_reader_status decode_packet_context(
	struct bt_ctf_stream_reader_ctx *ctx)
{
	enum bt_ctf_stream_reader_status status =
		BT_CTF_STREAM_READER_STATUS_OK;

	/* continue decoding packet context if needed */
	while (!ctx->entities.stream_packet_context) {
		status = handle_gd_state(ctx);

		if (status == BT_CTF_STREAM_READER_STATUS_AGAIN ||
				status == BT_CTF_STREAM_READER_STATUS_ERROR ||
				status == BT_CTF_STREAM_READER_STATUS_EOS) {
			goto end;
		}
	}

end:
	return status;
}

enum bt_ctf_stream_reader_status bt_ctf_stream_reader_get_context(
	struct bt_ctf_stream_reader_ctx *ctx,
	struct bt_ctf_field **packet_context)
{
	enum bt_ctf_stream_reader_status status;

	/* continue decoding packet context */
	status = decode_packet_context(ctx);

	if (ctx->entities.stream_packet_context) {
		*packet_context = ctx->entities.stream_packet_context;
		bt_ctf_field_get(*packet_context);
	}

	return status;
}

enum bt_ctf_stream_reader_status bt_ctf_stream_reader_get_next_event(
	struct bt_ctf_stream_reader_ctx *ctx,
	struct bt_ctf_event **event)
{
	return BT_CTF_STREAM_READER_STATUS_NOENT;
}
