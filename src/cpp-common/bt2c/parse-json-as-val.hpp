/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_BT2C_PARSE_JSON_AS_VAL_HPP
#define BABELTRACE_CPP_COMMON_BT2C_PARSE_JSON_AS_VAL_HPP

#include <cstdlib>
#include <string>

#include "logging.hpp"

#include "json-val.hpp"
#include "text-loc-str.hpp"

namespace bt2c {

/*
 * Parses the JSON text between `begin` and `end` (excluded) and returns
 * the resulting JSON value, adding `baseOffset` to the text location
 * offset of all the created JSON values.
 *
 * When this function logs or appends a cause to the error of the
 * current thread, it uses `baseOffset` and `textLocStrFmt` to format
 * the text location part of the message.
 */
JsonVal::UP parseJson(const char *begin, const char *end, std::size_t baseOffset,
                      const bt2c::Logger& logger,
                      TextLocStrFmt textLocStrFmt = TextLocStrFmt::LineColNosAndOffset);

static inline JsonVal::UP
parseJson(const char *begin, const char *end, const bt2c::Logger& logger,
          const TextLocStrFmt textLocStrFmt = TextLocStrFmt::LineColNosAndOffset)
{
    return parseJson(begin, end, 0, logger, textLocStrFmt);
}

/*
 * Parses the null-terminated JSON text `str` and returns the resulting
 * JSON value, adding `baseOffset` to the text location offset of all
 * the created JSON values.
 *
 * When this function logs or appends a cause to the error of the
 * current thread, it uses `baseOffset` and `textLocStrFmt` to format
 * the text location part of the message.
 */
static inline JsonVal::UP
parseJson(const char * const str, const std::size_t baseOffset, const bt2c::Logger& logger,
          const TextLocStrFmt textLocStrFmt = TextLocStrFmt::LineColNosAndOffset)
{
    return parseJson(str, str + std::strlen(str), baseOffset, logger, textLocStrFmt);
}

static inline JsonVal::UP
parseJson(const char * const str, const bt2c::Logger& logger,
          const TextLocStrFmt textLocStrFmt = TextLocStrFmt::LineColNosAndOffset)
{
    return parseJson(str, static_cast<std::size_t>(0), logger, textLocStrFmt);
}

/*
 * Parses the JSON string `str` and returns the resulting JSON value,
 * adding `baseOffset` to the text location offset of all the created
 * JSON values.
 *
 * When this function logs or appends a cause to the error of the
 * current thread, it uses `baseOffset` and `textLocStrFmt` to format
 * the text location part of the message.
 */
static inline JsonVal::UP
parseJson(const std::string& str, const std::size_t baseOffset, const bt2c::Logger& logger,
          const TextLocStrFmt textLocStrFmt = TextLocStrFmt::LineColNosAndOffset)
{
    return parseJson(str.data(), str.data() + str.size(), baseOffset, logger, textLocStrFmt);
}

static inline JsonVal::UP
parseJson(const std::string& str, const bt2c::Logger& logger,
          const TextLocStrFmt textLocStrFmt = TextLocStrFmt::LineColNosAndOffset)
{
    return parseJson(str, 0, logger, textLocStrFmt);
}

} /* namespace bt2c */

#endif /* BABELTRACE_CPP_COMMON_BT2C_PARSE_JSON_AS_VAL_HPP */
