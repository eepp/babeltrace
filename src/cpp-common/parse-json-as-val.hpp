/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_PARSE_JSON_AS_VAL_HPP
#define BABELTRACE_CPP_COMMON_PARSE_JSON_AS_VAL_HPP

#include <cstdlib>
#include <string>

#include "parse-json.hpp"
#include "json-val.hpp"

namespace bt2_common {

/*
 * Parses the JSON text between `begin` and `end` (excluded) and returns
 * the resulting JSON value, adding `baseOffset` to the text location
 * offset of all the created JSON values.
 *
 * Throws `TextParseError` on error.
 */
JsonVal::UP parseJson(const char *begin, const char *end, std::size_t baseOffset = 0);

/*
 * Parses the null-terminated JSON text `str` and returns the resulting
 * JSON value, adding `baseOffset` to the text location offset of all
 * the created JSON values.
 *
 * Throws `TextParseError` on error.
 */
static inline JsonVal::UP parseJson(const char * const str, const std::size_t baseOffset = 0)
{
    return parseJson(str, str + std::strlen(str), baseOffset);
}

/*
 * Parses the JSON string `str` and returns the resulting JSON value,
 * adding `baseOffset` to the text location offset of all the created
 * JSON values.
 *
 * Throws `TextParseError` on error.
 */
static inline JsonVal::UP parseJson(const std::string& str, const std::size_t baseOffset = 0)
{
    return parseJson(str.data(), str.data() + str.size(), baseOffset);
}

} /* namespace bt2_common */

#endif /* BABELTRACE_CPP_COMMON_PARSE_JSON_AS_VAL_HPP */
