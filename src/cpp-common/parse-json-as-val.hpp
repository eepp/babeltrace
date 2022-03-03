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
#include "text-loc.hpp"
#include "text-loc-str.hpp"
#include "log-cfg.hpp"

namespace bt2_common {

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
                      const LogCfg& logCfg,
                      TextLocStrFmt textLocStrFmt = TextLocStrFmt::LINE_COL_NOS_AND_OFFSET);

static inline JsonVal::UP
parseJson(const char *begin, const char *end, const LogCfg& logCfg,
          const TextLocStrFmt textLocStrFmt = TextLocStrFmt::LINE_COL_NOS_AND_OFFSET)
{
    return parseJson(begin, end, 0, logCfg, textLocStrFmt);
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
parseJson(const char * const str, const std::size_t baseOffset, const LogCfg& logCfg,
          const TextLocStrFmt textLocStrFmt = TextLocStrFmt::LINE_COL_NOS_AND_OFFSET)
{
    return parseJson(str, str + std::strlen(str), baseOffset, logCfg, textLocStrFmt);
}

static inline JsonVal::UP
parseJson(const char * const str, const LogCfg& logCfg,
          const TextLocStrFmt textLocStrFmt = TextLocStrFmt::LINE_COL_NOS_AND_OFFSET)
{
    return parseJson(str, static_cast<std::size_t>(0), logCfg, textLocStrFmt);
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
parseJson(const std::string& str, const std::size_t baseOffset, const LogCfg& logCfg,
          const TextLocStrFmt textLocStrFmt = TextLocStrFmt::LINE_COL_NOS_AND_OFFSET)
{
    return parseJson(str.data(), str.data() + str.size(), baseOffset, logCfg, textLocStrFmt);
}

static inline JsonVal::UP
parseJson(const std::string& str, const LogCfg& logCfg,
          const TextLocStrFmt textLocStrFmt = TextLocStrFmt::LINE_COL_NOS_AND_OFFSET)
{
    return parseJson(str, 0, logCfg, textLocStrFmt);
}

} /* namespace bt2_common */

#endif /* BABELTRACE_CPP_COMMON_PARSE_JSON_AS_VAL_HPP */
