/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2022 EfficiOS Inc. and Linux Foundation
 */

#ifndef BABELTRACE2_TRACE_IR_FIELD_LOCATION_H
#define BABELTRACE2_TRACE_IR_FIELD_LOCATION_H

#ifndef __BT_IN_BABELTRACE_H
# error "Please include <babeltrace2/babeltrace.h> instead."
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*!
@brief
    Field location scopes.
*/
typedef enum bt_field_location_scope {
	/*!
	@brief
	    Packet context.
	*/
	BT_FIELD_LOCATION_SCOPE_PACKET_CONTEXT		= 0,

	/*!
	@brief
	    Event common context.
	*/
	BT_FIELD_LOCATION_SCOPE_EVENT_COMMON_CONTEXT	= 1,

	/*!
	@brief
	    Event specific context.
	*/
	BT_FIELD_LOCATION_SCOPE_EVENT_SPECIFIC_CONTEXT	= 2,

	/*!
	@brief
	    Event payload.
	*/
	BT_FIELD_LOCATION_SCOPE_EVENT_PAYLOAD		= 3,
} bt_field_location_scope;

extern bt_field_location *bt_field_location_create(
		bt_trace_class *trace_class,
		bt_field_location_scope scope,
		const char *const *items,
		uint64_t item_count);

extern bt_field_location_scope bt_field_location_get_root_scope(
		const bt_field_location *field_location);

extern uint64_t bt_field_location_get_item_count(
		const bt_field_location *field_location);

extern const char *bt_field_location_get_item_by_index(
		const bt_field_location *field_location, uint64_t index);

extern void bt_field_location_get_ref(const bt_field_location *field_location);
extern void bt_field_location_put_ref(const bt_field_location *field_location);

#define BT_FIELD_LOCATION_PUT_REF_AND_RESET(_field_location)	\
	do {							\
		bt_field_location_put_ref(_field_location);	\
		(_field_location) = NULL;			\
	} while (0)

#define BT_FIELD_LOCATION_MOVE_REF(_dst, _src)		\
	do {						\
		bt_field_location_put_ref(_dst);	\
		(_dst) = (_src);			\
		(_src) = NULL;				\
	} while (0)

#ifdef __cplusplus
}
#endif

#endif /* BABELTRACE2_TRACE_IR_FIELD_LOCATION_H */
