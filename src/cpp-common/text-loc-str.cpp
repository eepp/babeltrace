/*
 * Copyright (c) 2016-2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <sstream>

#include "text-loc-str.hpp"

namespace bt2_common {

std::string textLocStr(const TextLoc& loc, const TextLocStrFmt fmt)
{
    std::ostringstream ss;

    if (fmt == TextLocStrFmt::LINE_COL_NOS_AND_OFFSET || fmt == TextLocStrFmt::LINE_COL_NOS) {
        ss << loc.naturalLineNo() << ':' << loc.naturalColNo();

        if (fmt == TextLocStrFmt::LINE_COL_NOS_AND_OFFSET) {
            ss << ' ';
        }
    }

    if (fmt == TextLocStrFmt::OFFSET || fmt == TextLocStrFmt::LINE_COL_NOS_AND_OFFSET) {
        ss << "@ " << loc.offset() << " bytes";
    }

    return ss.str();
}

} /* namespace bt2_common */
