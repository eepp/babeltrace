/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include "finalize-trace-cls.hpp"
#include "metadata-stream-parser.hpp"

namespace ctf {
namespace src {

MetadataStreamParser::MetadataStreamParser(bt_self_component * const selfComp) noexcept :
    _mSelfComp {selfComp}
{
}

void MetadataStreamParser::parseSection(const uint8_t * const begin, const uint8_t * const end)
{
    this->_parseSection(begin, end);

    if (_mTraceCls) {
        finalizeTraceCls(*_mTraceCls, _mSelfComp);
    }
}

} /* namespace src */
} /* namespace ctf */
