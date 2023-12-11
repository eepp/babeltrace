/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2022 EfficiOS, Inc.
 */

#ifndef _CTF_SRC_NORMALIZE_CLK_OFFSET_HPP
#define _CTF_SRC_NORMALIZE_CLK_OFFSET_HPP

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

#endif /* _CTF_SRC_NORMALIZE_CLK_OFFSET_HPP */
