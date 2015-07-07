#ifndef BABELTRACE_CTF_BTR_H
#define BABELTRACE_CTF_BTR_H

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

#include <stdint.h>
#include <stddef.h>
#include <babeltrace/ctf-ir/event-fields.h>
#include <babeltrace/babeltrace-internal.h>

/**
 * @file ctf-btr.h
 *
 * This is a common, internal API used by CTF reader plugins. It allows
 * a binary CTF type to be deserialized as CTF IR data structures
 * from user-provided buffers. As the type is decoded, user callback
 * functions are called.
 */

/**
 * Binary type reader API status codes.
 */
enum bt_ctf_btr_status {
	/** Invalid argument. */
	BT_CTF_BTR_STATUS_INVAL =	-2,

	/** General error. */
	BT_CTF_BTR_STATUS_ERROR =	-1,

	/** Everything okay. */
	BT_CTF_BTR_STATUS_OK =		0,
};

/** Type reader. */
struct bt_ctf_btr;

/*
 * Type reader user callback functions.
 */
struct bt_ctf_btr_cbs {
	/**
	 * Type callback functions.
	 *
	 * The following functions are called during the decoding process,
	 * either when a compound type begins/ends, or when a basic type
	 * is completely decoded (along with its value).
	 *
	 * Each function also receives the CTF IR field type associated with
	 * the call, and user data (registered to the type reader calling
	 * them).
	 *
	 * Actual CTF IR fields are \em not created here; this would be the
	 * responsibility of a type reader's user (the implementor of those
	 * callback functions).
	 */
	struct {
		/**
		 * Called when a signed integer type is completely decoded.
		 *
		 * @param value		Signed integer value
		 * @param type		Integer type
		 * @param data		User data
		 */
		void (* signed_int)(int64_t value,
			struct bt_ctf_field_type *type, void *data);

		/**
		 * Called when an unsigned integer type is completely decoded.
		 *
		 * @param value		Unsigned integer value
		 * @param type		Integer type
		 * @param data		User data
		 */
		void (* unsigned_int)(uint64_t value,
			struct bt_ctf_field_type *type, void *data);

		/**
		 * Called when a floating point number type is completely
		 * decoded.
		 *
		 * @param value		Floating point number value
		 * @param type		Floating point number type
		 * @param data		User data
		 */
		void (* floating_point)(double value,
			struct bt_ctf_field_type *type, void *data);

		/**
		 * Called when the supporting signed integer type of
		 * an enumeration type is completely decoded.
		 *
		 * @param value		Enumeration's supporting signed
		 *			integer's value
		 * @param type		Enumeration type
		 * @param data		User data
		 */
		void (* signed_enum)(int64_t value,
			struct bt_ctf_field_type *type, void *data);

		/**
		 * Called when the supporting unsigned integer type of
		 * an enumeration type is completely decoded.
		 *
		 * @param value		Enumeration's supporting unsigned
		 *			integer's value
		 * @param type		Enumeration type
		 * @param data		User data
		 */
		void (* unsigned_enum)(uint64_t value,
			struct bt_ctf_field_type *type, void *data);

		/**
		 * Called when a string type begins.
		 *
		 * All the following user callback function calls will
		 * be made to bt_ctf_btr_cbs::types::string(), each of
		 * them providing one substring of the complete string
		 * type's value.
		 *
		 * @param type		Beginning string type
		 * @param data		User data
		 */
		void (* string_begin)(struct bt_ctf_field_type *type,
			void *data);

		/**
		 * Called when a string type's substring is decoded
		 * (between a call to bt_ctf_btr_cbs::types::string_begin()
		 * and bt_ctf_btr_cbs::types::string_end()).
		 *
		 * @param value		String value (\em not null-terminated)
		 * @param len		String value length
		 * @param type		String type
		 * @param data		User data
		 */
		void (* string)(const char *value, size_t len,
			struct bt_ctf_field_type *type, void *data);

		/**
		 * Called when a string type ends.
		 *
		 * @param type		Ending string type
		 * @param data		User data
		 */
		void (* string_end)(struct bt_ctf_field_type *type, void *data);

		/**
		 * Called when an array type begins.
		 *
		 * All the following type callback function calls will
		 * signal sequential elements of this array type, until
		 * the next corresponding bt_ctf_btr_cbs::types::array_end().
		 *
		 * @param type		Beginning array type
		 * @param data		User data
		 */
		void (* array_begin)(struct bt_ctf_field_type *type,
			void *data);

		/**
		 * Called when an array type ends.
		 *
		 * @param type		Ending array type
		 * @param data		User data
		 */
		void (* array_end)(struct bt_ctf_field_type *type, void *data);

		/**
		 * Called when a sequence type begins.
		 *
		 * All the following type callback function calls will
		 * signal sequential elements of this sequence type,
		 * until the next corresponding
		 * bt_ctf_btr_cbs::types::sequence_end().
		 *
		 * @param type		Beginning sequence type
		 * @param data		User data
		 */
		void (* sequence_begin)(struct bt_ctf_field_type *type,
			void *data);

		/**
		 * Called when a sequence type ends.
		 *
		 * @param type		Ending sequence type
		 * @param data		User data
		 */
		void (* sequence_end)(struct bt_ctf_field_type *type,
			void *data);

		/**
		 * Called when a structure type begins.
		 *
		 * All the following type callback function calls will
		 * signal sequential fields of this structure type,
		 * until the next corresponding
		 * bt_ctf_btr_cbs::types::struct_end().
		 *
		 * @param type		Beginning sequence type
		 * @param data		User data
		 */
		void (* struct_begin)(struct bt_ctf_field_type *type,
			void *data);

		/**
		 * Called when a structure type ends.
		 *
		 * @param type		Ending structure type
		 * @param data		User data
		 */
		void (* struct_end)(struct bt_ctf_field_type *type, void *data);

		/**
		 * Called when a variant type is to be decoded.
		 *
		 * The following call will indicate the selected type
		 * of this variant type.
		 *
		 * @param type		Variant type
		 * @param data		User data
		 */
		void (* variant)(struct bt_ctf_field_type *type, void *data);
	} types;

	/**
	 * Query callback functions are used when the type reader needs
	 * dynamic information, i.e. a sequence type's current length
	 * or a variant type's current selected type.
	 */
	struct {
		/**
		 * Called to query the current length of a given sequence
		 * type.
		 *
		 * @param type		Sequence type
		 * @param data		User data
		 * @returns		Sequence length, or
		 *			#BT_CTF_BTR_STATUS_ERROR on error
		 */
		int64_t (* get_sequence_length)(struct bt_ctf_field_type *type,
			void *data);

		/**
		 * Called to query the current selected type of a given
		 * variant type.
		 *
		 * @param type		Variant type
		 * @param data		User data
		 * @returns		Current selected type, or
		 *			\a NULL on error
		 */
		struct bt_ctf_field_type * (* get_variant_type)(
			struct bt_ctf_field_type *type, void *data);
	} query;
};

/**
 * Creates a type reader.
 *
 * @param cbs		User callback functions
 * @param data		User data (passed to medium operations and
 *			user callback functions)
 * @returns		New binary type reader on success, or
 * 			\c NULL on error
 */
struct bt_ctf_btr *bt_ctf_btr_create(struct bt_ctf_btr_cbs cbs, void *data);

/**
 * Destroys a binary type reader, freeing all internal resources.
 *
 * @param ctx	Binary type reader
 */
void bt_ctf_btr_destroy(struct bt_ctf_btr *tr);

/**
 * Decodes a given CTF type.
 *
 * Upon successful completion, the number of consumed bytes is returned
 * and all the appropriate user callback functions have been called.
 *
 * If the number of consumed bytes is equal to \p len, and if it is
 * known that the type has not been decoded completely, then
 * bt_ctf_btr_continue() must be called until it returns 0.
 *
 * If the number of consumed bytes is lesser than \p len, then too
 * many bytes were given to the function. In this case, the remaining
 * bytes must be passed to the following call to bt_ctf_btr_decode().
 *
 * Note that this function may return 0 and still call a user callback
 * function. This is because only the number of \em completely consumed
 * bytes is returned. If the type to decode fits in the buffer's first
 * byte, then this byte was not consumed entirely, and thus must be
 * passed again to bt_ctf_btr_continue() if need be.
 *
 * @param type		Type to decode
 * @param buf		Buffer
 * ­@returns		Number of completely consumed bytes or one the
 *			positive values of #bt_ctf_btr_status
 */
int64_t bt_ctf_btr_decode(struct bt_ctf_field_type *type,
	const uint8_t *buf, size_t len);

/**
 * Continues the decoding process a given CTF type.
 *
 * Upon successful completion, #BT_CTF_BTR_STATUS_OK is returned and
 * all the appropriate user callback functions have been called.
 *
 * If #BT_CTF_BTR_STATUS_AGAIN is returned, the caller needs to make
 * sure that enough data becomes available to its medium and call
 * bt_ctf_btr_continue() again to continue.
 *
 * ­@returns		One of #bt_ctf_btr_status values
 */
enum bt_ctf_btr_status bt_ctf_btr_continue(void);

#endif /* BABELTRACE_CTF_BTR_H */
