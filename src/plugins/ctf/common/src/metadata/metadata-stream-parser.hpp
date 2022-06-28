/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef _CTF_SRC_METADATA_METADATA_STREAM_PARSER_HPP
#define _CTF_SRC_METADATA_METADATA_STREAM_PARSER_HPP

#include <cstdint>
#include <memory>

#include "cpp-common/optional.hpp"
#include "cpp-common/uuid.hpp"
#include "ctf-ir.hpp"

namespace ctf {
namespace src {

/*
 * Abstract base CTF metadata stream parser class.
 */
class MetadataStreamParser
{
protected:
    explicit MetadataStreamParser(bt_self_component *selfComp) noexcept;

public:
    using UP = std::unique_ptr<MetadataStreamParser>;

    virtual ~MetadataStreamParser() = default;

    /*
     * Parses the section of metadata stream between `begin` and `end`
     * (excluded), creating or updating the current trace class.
     */
    void parseSection(const uint8_t *begin, const uint8_t *end);

    /*
     * Current trace class, or `nullptr` if none exists at this point.
     */
    const TraceCls *traceCls() const noexcept
    {
        return _mTraceCls.get();
    }

    /*
     * Current metadata stream UUID, or `nonstd::nullopt` if none exists
     * at this point.
     */
    const nonstd::optional<bt2_common::Uuid>& metadataStreamUuid() const noexcept
    {
        return _mMetadataStreamUuid;
    }

private:
    virtual void _parseSection(const uint8_t *begin, const uint8_t *end) = 0;

protected:
    /* Trace class */
    std::unique_ptr<TraceCls> _mTraceCls;

    /* Metadata stream UUID */
    nonstd::optional<bt2_common::Uuid> _mMetadataStreamUuid;

private:
    /* Self component, used to finalize `*_mTraceCls` */
    bt_self_component *_mSelfComp;
};

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_METADATA_STREAM_PARSER_HPP */
