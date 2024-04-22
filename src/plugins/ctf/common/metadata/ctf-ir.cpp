/*
 * Copyright (c) 2023-2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include "ctf-ir.hpp"

namespace ctf {
namespace ir {

constexpr const char *ClkOrigin::_unixEpochNs = "babeltrace.org,2020";
constexpr const char *ClkOrigin::_unixEpochName = "unix-epoch";
constexpr const char *ClkOrigin::_unixEpochUid = "";
constexpr const char *defaultBlobMediaType = "application/octet-stream";

} /* namespace ir */
} /* namespace ctf */
