#ifndef _BABELTRACE_DEBUGINFO_H
#define _BABELTRACE_DEBUGINFO_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

struct debug_info_source {
	/* Strings are owned by this */
	char *func;
	long long unsigned int line_no;
	char *filename;
};

struct debug_info;
struct ctf_event_definition;

int debug_info_init(void);

struct debug_info *debug_info_create(void);

void debug_info_destroy(struct debug_info *debug_info);

void debug_info_handle_event(struct debug_info *debug_info,
		struct ctf_event_definition *event);

#endif /* _BABELTRACE_DEBUGINFO_H */
