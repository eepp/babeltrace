/*
 * Copyright (c) 2023 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_CONTAINS_HPP
#define BABELTRACE_CPP_COMMON_CONTAINS_HPP

namespace bt2_common {

template <typename T, typename V>
bool contains(const T& container, const V& val) noexcept
{
    return container.find(val) != container.end();
}

} /* namespace bt2_common */

#endif /* BABELTRACE_CPP_COMMON_CONTAINS_HPP */
