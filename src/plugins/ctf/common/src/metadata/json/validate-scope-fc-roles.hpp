/*
 * Copyright (c) 2022-2023 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _CTF_SRC_METADATA_JSON_VALIDATE_SCOPE_FC_ROLES_HPP
#define _CTF_SRC_METADATA_JSON_VALIDATE_SCOPE_FC_ROLES_HPP

#include <unordered_set>

#include "cpp-common/log-cfg.hpp"
#include "cpp-common/text-loc-str.hpp"
#include "../ctf-ir.hpp"

namespace ctf {
namespace src {

/*
 * Validates that:
 *
 * • If any unsigned integer field class within `fc` has one or more
 *   roles, then those roles are part of the `allowedRoles` set.
 *
 * • If any static-length BLOB field class within `fc` has the metadata
 *   stream UUID role, then `allowMetadataStreamUuidRole` is true.
 *
 * Appends one or more causes to the error of the current thread using
 * `logCfg` and `textLocStrFmt` and throws `bt2_common::Error` when `fc`
 * is invalid.
 */
void validateScopeFcRoles(const Fc& fc, const ir::UIntFieldRoles& allowedRoles,
                          bool allowMetadataStreamUuidRole, const bt2_common::LogCfg& logCfg,
                          bt2_common::TextLocStrFmt textLocStrFmt);

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_JSON_VALIDATE_SCOPE_FC_ROLES_HPP */
