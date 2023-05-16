/*
 * Copyright (c) 2023 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _CTF_SRC_METADATA_JSON_NORMALIZE_FIELD_LOCS_HPP
#define _CTF_SRC_METADATA_JSON_NORMALIZE_FIELD_LOCS_HPP

#include "cpp-common/log-cfg.hpp"
#include "cpp-common/text-loc-str.hpp"
#include "../ctf-ir.hpp"

namespace ctf {
namespace src {

/*
 * Converts all the relative field locations in `scopeFc` into absolute
 * field locations.
 *
 * `scopeFc` is a scope field class for the scope `scope`.
 *
 * This function doesn't guarantee that the normalized field locations
 * are valid.
 *
 * Appends one or more causes to the error of the current thread using
 * `logCfg` and `textLocStrFmt` and throws `bt2_common::Error` when any
 * relative field location in `scopeFc` is invalid.
 */
void normalizeFieldLocs(Fc& scopeFc, ir::FieldLocScope scope, const bt2_common::LogCfg& logCfg,
                        bt2_common::TextLocStrFmt textLocStrFmt);

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_JSON_NORMALIZE_FIELD_LOCS_HPP */
