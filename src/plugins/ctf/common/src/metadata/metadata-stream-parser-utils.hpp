/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2022 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef _CTF_SRC_METADATA_METADATA_STREAM_PARSER_UTILS_HPP
#define _CTF_SRC_METADATA_METADATA_STREAM_PARSER_UTILS_HPP

#include <cstdint>
#include <memory>

#include "cpp-common/bt2c/logging.hpp"
#include "cpp-common/bt2s/span.hpp"

#include "../clk-cls-cfg.hpp"
#include "metadata-stream-parser.hpp"

namespace ctf {
namespace src {

enum class MetadataStreamMajorVersion
{
    V1 = 1,
    V2,
};

/*
 * Returns the major CTF version (1 or 2) of the metadata stream
 * in `buffer`.
 */
MetadataStreamMajorVersion
getMetadataStreamMajorVersion(bt2s::span<const std::uint8_t> buffer) noexcept;

/*
 * Creates and returns a CTF metadata stream parser of which the
 * concrete class depends on `majorVersion`.
 *
 * Forwards other parameters to the CTF metadata stream parser
 * constructor.
 */
std::unique_ptr<MetadataStreamParser>
createMetadataStreamParser(MetadataStreamMajorVersion majorVersion, const ClkClsCfg& clkClsCfg,
                           bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp,
                           const bt2c::Logger& parentLogger);

/*
 * Creates and returns a CTF metadata stream parser of which the
 * concrete class depends on the first byte of `buffer`, the beginning of
 * the metadata stream.
 *
 * Forwards other parameters to the CTF metadata stream parser
 * constructor.
 */
std::unique_ptr<MetadataStreamParser>
createMetadataStreamParser(bt2s::span<const std::uint8_t> buffer, const ClkClsCfg& clkClsCfg,
                           bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp,
                           const bt2c::Logger& parentLogger);

/*
 * Parses the metadata stream in `buffer` using a parser of which the
 * concrete class depends on the first byte of `buffer`, the beginning
 * of the metadata stream.
 *
 * Forwards other parameters to the CTF metadata stream parser
 * constructor.
 */
MetadataStreamParser::ParseRet
parseMetadataStream(const ClkClsCfg& clkClsCfg,
                    bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp,
                    bt2s::span<const std::uint8_t> buffer, const bt2c::Logger& parentLogger);

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_METADATA_STREAM_PARSER_UTILS_HPP */
