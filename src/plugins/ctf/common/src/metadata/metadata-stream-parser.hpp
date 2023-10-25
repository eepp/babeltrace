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

#include "cpp-common/bt2/self-component-port.hpp"
#include "cpp-common/bt2c/uuid.hpp"

#include "../clk-cls-cfg.hpp"
#include "ctf-ir.hpp"

namespace ctf {
namespace src {

/*
 * Abstract base CTF metadata stream parser class.
 */
class MetadataStreamParser
{
public:
    using UP = std::unique_ptr<MetadataStreamParser>;
    struct ParseRet
    {
        std::unique_ptr<TraceCls> traceCls;
        bt2s::optional<bt2c::Uuid> uuid;
    };

protected:
    explicit MetadataStreamParser(
        const ClkClsCfg& clkClsCfg,
        bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp) noexcept;

public:
    virtual ~MetadataStreamParser() = default;

    /*
     * Parses the section of metadata stream in `buffer` creating or
     * updating the current trace class.
     */
    void parseSection(bt2s::span<const std::uint8_t> buffer);

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
     * Current metadata stream UUID, or `bt2s::nullopt` if none exists
     * at this point.
     */
    const bt2s::optional<bt2c::Uuid>& metadataStreamUuid() const noexcept
    {
        return _mMetadataStreamUuid;
    }

private:
    virtual void _parseSection(bt2s::span<const std::uint8_t> buffer) = 0;

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
    bt2s::optional<bt2c::Uuid> _mMetadataStreamUuid;

private:
    /* Clock class configuration */
    ClkClsCfg _mClkClsCfg;

    /*
     * Clock classes to which we have already applied the config and
     * normalized.
     */
    std::unordered_set<const ClkCls *> _mAdjustedClkClasses;

    /* Self component, used to finalize `*_mTraceCls` */
    bt2::OptionalBorrowedObject<bt2::SelfComponent> _mSelfComp;
};

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_METADATA_STREAM_PARSER_HPP */
