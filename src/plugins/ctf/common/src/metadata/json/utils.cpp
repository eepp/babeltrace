/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include "cpp-common/text-parse-error.hpp"
#include "utils.hpp"

namespace ctf {
namespace src {

namespace bt2c = bt2_common;

[[noreturn]] void throwTextParseError(std::string msg, const bt2c::JsonVal& jsonVal)
{
    throw bt2c::TextParseError {std::move(msg), jsonVal.loc()};
}

[[noreturn]] void throwTextParseError(const std::ostringstream& ss, const bt2c::JsonVal& jsonVal)
{
    throwTextParseError(ss.str(), jsonVal);
}

} /* namespace src */
} /* namespace ctf */
