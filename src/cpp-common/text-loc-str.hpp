/*
 * Copyright (c) 2016-2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_TEXT_LOC_STR_HPP
#define BABELTRACE_CPP_COMMON_TEXT_LOC_STR_HPP

#include <string>

#include "text-loc.hpp"

namespace bt2_common {

/*
 * Text location string format.
 */
enum class TextLocStrFmt
{
    OFFSET,
    LINE_COL_NOS_AND_OFFSET,
    LINE_COL_NOS,
};

/*
 * Formats the text location `loc` as a string following the format
 * `fmt`.
 */
std::string textLocStr(const TextLoc& loc, TextLocStrFmt fmt);

} /* namespace bt2_common */

#endif /* BABELTRACE_CPP_COMMON_TEXT_LOC_STR_HPP */
