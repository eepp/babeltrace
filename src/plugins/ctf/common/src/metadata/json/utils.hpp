/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _CTF_SRC_METADATA_JSON_UTILS_HPP
#define _CTF_SRC_METADATA_JSON_UTILS_HPP

#include <string>
#include <sstream>

#include "common/common.h"
#include "cpp-common/json-val.hpp"

namespace ctf {
namespace src {

/*
 * Throws a text parsing error using the location of the JSON value
 * `jsonVal`.
 */
[[noreturn]] void throwTextParseError(std::string msg, const bt2_common::JsonVal& jsonVal);

[[noreturn]] void throwTextParseError(const std::ostringstream& ss,
                                      const bt2_common::JsonVal& jsonVal);

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_JSON_UTILS_HPP */
