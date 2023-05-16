/*
 * Copyright (c) 2022-2023 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _CTF_SRC_METADATA_JSON_FCS_WITH_ROLE_HPP
#define _CTF_SRC_METADATA_JSON_FCS_WITH_ROLE_HPP

#include <unordered_set>
#include <string>

#include "cpp-common/json-val.hpp"
#include "../ctf-ir.hpp"

namespace ctf {
namespace src {

/*
 * Returns a set of all the field classes having at least one role
 * amongst `roles` and/or the "metadata stream UUID" role if
 * `withMetadataStreamUuidRole` is true for a static-length BLOB field
 * class.
 */
std::unordered_set<const Fc *> fcsWithRole(const Fc& fc,
                                           const std::unordered_set<ir::UIntFieldRole>& roles,
                                           bool withMetadataStreamUuidRole);

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_JSON_FCS_WITH_ROLE_HPP */
