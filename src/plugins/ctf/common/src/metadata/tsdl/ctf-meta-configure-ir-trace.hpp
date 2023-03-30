/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef _CTF_META_CONFIGURE_IR_TRACE_H
#define _CTF_META_CONFIGURE_IR_TRACE_H

#include "common/macros.h"

#include "ctf-meta.hpp"
#include "cpp-common/bt2/trace-ir.hpp"
#include "cpp-common/log-cfg.hpp"
#include "plugins/ctf/common/src/metadata/ctf-ir.hpp"

void ctf_trace_class_configure_ir_trace(struct ctf_trace_class *tc, bt2::Trace ir_trace);

void ctf_trace_class_configure_ir_trace(const ctf::src::TraceCls& tc, bt2::Trace irTrace,
                                        const bt2_common::LogCfg& logCfg);

#endif /* _CTF_META_CONFIGURE_IR_TRACE_H */
