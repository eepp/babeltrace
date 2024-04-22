/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2022 EfficiOS, Inc.
 */

#ifndef CTF_COMMON_SRC_METADATA_SRC_NORMALIZE_CLK_OFFSET_HPP
#define CTF_COMMON_SRC_METADATA_SRC_NORMALIZE_CLK_OFFSET_HPP

#include <utility>

namespace ctf {
namespace src {

/*
 * Normalizes `offsetSeconds` and `offsetCycles` so that the cycle part
 * is less than the frequency `freq` and returns the new offset parts.
 */
std::pair<long long, unsigned long long> normalizeClkOffset(long long offsetSeconds,
                                                            unsigned long long offsetCycles,
                                                            unsigned long long freq) noexcept;

} /* namespace src */
} /* namespace ctf */

#endif /* CTF_COMMON_SRC_METADATA_SRC_NORMALIZE_CLK_OFFSET_HPP */
