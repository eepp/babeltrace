/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2018 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef _CTF_META_VISITORS_H
#define _CTF_META_VISITORS_H

#include <babeltrace2/babeltrace.h>
#include "common/macros.h"

#include "ctf-meta.hpp"
#include "cpp-common/log-cfg.hpp"

int ctf_trace_class_resolve_field_classes(struct ctf_trace_class *tc,
                                          const bt2_common::LogCfg& logCfg);

int ctf_trace_class_update_default_clock_classes(struct ctf_trace_class *ctf_tc,
                                                 const bt2_common::LogCfg& logCfg);

int ctf_trace_class_update_meanings(struct ctf_trace_class *ctf_tc);

int ctf_trace_class_update_text_array_sequence(struct ctf_trace_class *ctf_tc);

int ctf_trace_class_update_alignments(struct ctf_trace_class *ctf_tc);

int ctf_trace_class_validate(struct ctf_trace_class *ctf_tc, const bt2_common::LogCfg& logCfg);

void ctf_trace_class_warn_meaningless_header_fields(struct ctf_trace_class *ctf_tc,
                                                    const bt2_common::LogCfg& logCfg);

#endif /* _CTF_META_VISITORS_H */
