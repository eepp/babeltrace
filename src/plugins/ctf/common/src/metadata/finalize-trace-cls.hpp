/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2022 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef _CTF_SRC_METADATA_FINALIZE_TRACE_IR_HPP
#define _CTF_SRC_METADATA_FINALIZE_TRACE_IR_HPP

#include <babeltrace2/babeltrace.h>

#include "ctf-ir.hpp"

namespace ctf {
namespace src {

/*
 * Finalizes `traceCls` after its creation or when it gets new data
 * stream classes or event record classes.
 *
 * This function:
 *
 * • Sets the value saving indexes of dependencies (field classes) and
 *   the saved value index of dependent (dynamic-length, optional, and
 *   variant) field classes.
 *
 * • If `selfComp` is not `nullptr`, translates the contained objects to
 *   their trace IR equivalents.
 */
void finalizeTraceCls(TraceCls& traceCls, bt_self_component *selfComp = nullptr);

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_FINALIZE_TRACE_IR_HPP */
