/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include "common/assert.h"
#include "cpp-common/make-unique.hpp"
#include "tsdl/ctf-1-metadata-stream-parser.hpp"
#include "json/ctf-2-metadata-stream-parser.hpp"
#include "metadata-stream-parser-utils.hpp"

namespace ctf {
namespace src {

MetadataStreamMajorVersion getMetadataStreamMajorVersion(const std::uint8_t * const data) noexcept
{
    BT_ASSERT(data);

    /* CTF 2 if it starts with an RS byte, otherwise CTF 1 */
    return (*data == 30) ? MetadataStreamMajorVersion::V2 : MetadataStreamMajorVersion::V1;
}

std::unique_ptr<MetadataStreamParser>
createMetadataStreamParser(const MetadataStreamMajorVersion majorVersion,
                           const ClkClsCfg& clkClsCfg, bt_self_component * const selfComp,
                           const bt2_common::LogCfg& logCfg)
{
    if (majorVersion == MetadataStreamMajorVersion::V1) {
        return bt2_common::makeUnique<Ctf1MetadataStreamParser>(clkClsCfg, selfComp, logCfg);
    } else {
        BT_ASSERT(majorVersion == MetadataStreamMajorVersion::V2);
        return bt2_common::makeUnique<Ctf2MetadataStreamParser>(selfComp, logCfg);
    }
}

std::unique_ptr<MetadataStreamParser> createMetadataStreamParser(const std::uint8_t * const data,
                                                                 const ClkClsCfg& clkClsCfg,
                                                                 bt_self_component * const selfComp,
                                                                 const bt2_common::LogCfg& logCfg)
{
    return createMetadataStreamParser(getMetadataStreamMajorVersion(data), clkClsCfg, selfComp,
                                      logCfg);
}

} /* namespace src */
} /* namespace ctf */
