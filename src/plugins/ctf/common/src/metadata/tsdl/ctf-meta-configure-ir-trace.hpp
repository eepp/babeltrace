/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef CTF_COMMON_SRC_METADATA_TSDL_CTF_META_CONFIGURE_IR_TRACE_HPP
#define CTF_COMMON_SRC_METADATA_TSDL_CTF_META_CONFIGURE_IR_TRACE_HPP

#include "../ctf-ir.hpp"

namespace bt2c {

class Logger;

} /* namespace bt2c */

void ctf_trace_class_configure_ir_trace(struct ctf_trace_class *tc, bt2::Trace ir_trace);

void ctf_trace_class_configure_ir_trace(const ctf::src::TraceCls& tc, bt2::Trace irTrace,
                                        bt_self_component *selfComp,
                                        const bt2c::Logger& parentLogger);

#endif /* CTF_COMMON_SRC_METADATA_TSDL_CTF_META_CONFIGURE_IR_TRACE_HPP */
