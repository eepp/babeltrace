/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef _CTF_SRC_METADATA_METADATA_STREAM_PARSER_HPP
#define _CTF_SRC_METADATA_METADATA_STREAM_PARSER_HPP

#include <cstdint>
#include <memory>
#include <utility>

#include "cpp-common/optional.hpp"
#include "cpp-common/uuid.hpp"
#include "ctf-ir.hpp"
#include "../clk-cls-cfg.hpp"

namespace ctf {
namespace src {

/*
 * Abstract base CTF metadata stream parser class.
 */
class MetadataStreamParser
{
public:
    using UP = std::unique_ptr<MetadataStreamParser>;
    using ParseRet = std::pair<std::unique_ptr<TraceCls>, nonstd::optional<bt2_common::Uuid>>;

protected:
    explicit MetadataStreamParser(const ClkClsCfg& clkClsCfg, bt_self_component *selfComp) noexcept;

public:
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
     * Releases the current trace class, or `nullptr` if none exists at
     * this point.
     */
    std::unique_ptr<TraceCls> releaseTraceCls() noexcept
    {
        return std::move(_mTraceCls);
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

    /*
     * Finalizes `*_mTraceCls` after its creation or when it gets new
     * data stream classes or event record classes.
     *
     * This function:
     *
     * • Sets the value saving indexes of dependencies (field classes)
     *   and the saved value index of dependent (dynamic-length,
     *   optional, and variant) field classes.
     *
     * • Reconfigures the clock classes of `*_mTraceCls` using
     *   `_mClkClsCfg`.
     *
     * • Normalizes the offsets of the clock classes of `*_mTraceCls` so
     *   that the cycle part is less than the frequency.
     *
     * • If `selfComp` is not `nullptr`, translates the contained
     *   objects to their trace IR equivalents.
     */
    void _finalizeTraceCls();

    /*
     * Applies the clock offset of `_mClkClsCfg` to `clkCls`.
     */
    void _adjustClkClsOffset(ClkCls& clkCls) noexcept;

    /*
     * Reconfigures `clkCls` using `_mClkClsCfg`.
     */
    void _adjustClkCls(ClkCls& clkCls) noexcept;

protected:
    /* Trace class */
    std::unique_ptr<TraceCls> _mTraceCls;

    /* Metadata stream UUID */
    nonstd::optional<bt2_common::Uuid> _mMetadataStreamUuid;

private:
    /* Clock class configuration */
    ClkClsCfg _mClkClsCfg;

    /*
     * Clock classes to which we have already applied the config and
     * normalized.
     */
    std::unordered_set<const ClkCls *> _mAdjustedClkClasses;

    /* Self component, used to finalize `*_mTraceCls` */
    bt_self_component *_mSelfComp;
};

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_METADATA_STREAM_PARSER_HPP */
