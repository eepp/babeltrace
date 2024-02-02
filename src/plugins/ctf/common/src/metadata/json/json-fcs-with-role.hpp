/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _CTF_SRC_METADATA_JSON_JSON_FCS_WITH_ROLE_HPP
#define _CTF_SRC_METADATA_JSON_JSON_FCS_WITH_ROLE_HPP

#include <string>
#include <unordered_set>

#include "cpp-common/bt2c/json-val.hpp"

namespace ctf {
namespace src {

/*
 * Returns a set of all the JSON field class values having at least one
 * role amongst `roleNames` and/or the "metadata stream UUID" role if
 * `withMetadataStreamUuidRole` is true for a JSON static-length BLOB
 * field class.
 */
std::unordered_set<const bt2c::JsonVal *>
jsonFcsWithRole(const bt2c::JsonVal& jsonFc, const std::unordered_set<std::string>& roleNames,
                bool withMetadataStreamUuidRole);

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_JSON_JSON_FCS_WITH_ROLE_HPP */
