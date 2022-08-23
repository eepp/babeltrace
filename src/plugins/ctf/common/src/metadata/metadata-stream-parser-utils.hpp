/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2022 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef _CTF_SRC_METADATA_METADATA_STREAM_PARSER_UTILS_HPP
#define _CTF_SRC_METADATA_METADATA_STREAM_PARSER_UTILS_HPP

#include <cstdint>
#include <memory>

#include "metadata-stream-parser.hpp"
#include "cpp-common/log-cfg.hpp"
#include "../clk-cls-cfg.hpp"

namespace ctf {
namespace src {

enum class MetadataStreamMajorVersion
{
    V1 = 1,
    V2,
};

/*
 * Returns the major CTF version (1 or 2) of the metadata stream
 * starting with `data`.
 */
MetadataStreamMajorVersion getMetadataStreamMajorVersion(const std::uint8_t *data) noexcept;

/*
 * Creates and returns a CTF metadata stream parser of which the
 * concrete class depends on `majorVersion`.
 *
 * Forwards other parameters to the CTF metadata stream parser
 * constructor.
 */
std::unique_ptr<MetadataStreamParser>
createMetadataStreamParser(MetadataStreamMajorVersion majorVersion, const ClkClsCfg& clkClsCfg,
                           bt_self_component *selfComp, const bt2_common::LogCfg& logCfg);

/*
 * Creates and returns a CTF metadata stream parser of which the
 * concrete class depends on the first byte of `data`, the beginning of
 * the metadata stream.
 *
 * Forwards other parameters to the CTF metadata stream parser
 * constructor.
 */
std::unique_ptr<MetadataStreamParser> createMetadataStreamParser(const std::uint8_t *data,
                                                                 const ClkClsCfg& clkClsCfg,
                                                                 bt_self_component *selfComp,
                                                                 const bt2_common::LogCfg& logCfg);

/*
 * Parses the metadata stream between `begin` and `end` using a parser
 * of which the concrete class depends on the first byte of `begin`, the
 * beginning of the metadata stream.
 *
 * Forwards other parameters to the CTF metadata stream parser
 * constructor.
 */
MetadataStreamParser::ParseRet parseMetadataStream(const ClkClsCfg& clkClsCfg,
                                                   bt_self_component *selfComp,
                                                   const uint8_t *begin, const uint8_t *end,
                                                   const bt2_common::LogCfg& logCfg);

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_METADATA_STREAM_PARSER_UTILS_HPP */
