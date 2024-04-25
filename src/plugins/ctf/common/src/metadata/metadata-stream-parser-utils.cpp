/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include "common/assert.h"
#include "cpp-common/bt2s/make-unique.hpp"

#include "json/ctf-2-metadata-stream-parser.hpp"
#include "metadata-stream-parser-utils.hpp"
#include "tsdl/ctf-1-metadata-stream-parser.hpp"

namespace ctf {
namespace src {

MetadataStreamMajorVersion
getMetadataStreamMajorVersion(const bt2s::span<const std::uint8_t> buffer) noexcept
{
    BT_ASSERT(buffer.data());

    /* CTF 2 if it starts with an RS byte, otherwise CTF 1 */
    return (buffer[0] == 30) ? MetadataStreamMajorVersion::V2 : MetadataStreamMajorVersion::V1;
}

std::unique_ptr<MetadataStreamParser>
createMetadataStreamParser(const MetadataStreamMajorVersion majorVersion,
                           const ClkClsCfg& clkClsCfg,
                           const bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp,
                           const bt2c::Logger& parentLogger)
{
    if (majorVersion == MetadataStreamMajorVersion::V1) {
        return bt2s::make_unique<Ctf1MetadataStreamParser>(clkClsCfg, selfComp, parentLogger);
    } else {
        BT_ASSERT(majorVersion == MetadataStreamMajorVersion::V2);
        return bt2s::make_unique<Ctf2MetadataStreamParser>(clkClsCfg, selfComp, parentLogger);
    }
}

std::unique_ptr<MetadataStreamParser>
createMetadataStreamParser(const bt2s::span<const std::uint8_t> buffer, const ClkClsCfg& clkClsCfg,
                           const bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp,
                           const bt2c::Logger& parentLogger)
{
    return createMetadataStreamParser(getMetadataStreamMajorVersion(buffer), clkClsCfg, selfComp,
                                      parentLogger);
}

MetadataStreamParser::ParseRet
parseMetadataStream(const ClkClsCfg& clkClsCfg,
                    const bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp,
                    const bt2s::span<const std::uint8_t> buffer, const bt2c::Logger& parentLogger)
{
    const auto majorVersion = getMetadataStreamMajorVersion(buffer);

    if (majorVersion == MetadataStreamMajorVersion::V1) {
        return Ctf1MetadataStreamParser::parse(clkClsCfg, selfComp, buffer, parentLogger);
    } else {
        BT_ASSERT(majorVersion == MetadataStreamMajorVersion::V2);
        return Ctf2MetadataStreamParser::parse(clkClsCfg, selfComp, buffer, parentLogger);
    }
}

} /* namespace src */
} /* namespace ctf */
