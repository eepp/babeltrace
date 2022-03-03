/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_BT2_VALUE_FROM_JSON_VAL_HPP
#define BABELTRACE_CPP_COMMON_BT2_VALUE_FROM_JSON_VAL_HPP

#include <string>

#include "bt2/value.hpp"
#include "json-val.hpp"

namespace bt2_common {

/*
 * Converts the JSON value `jsonVal` to an equivalent Babeltrace 2 value
 * object and returns it.
 */
bt2::Value::Shared bt2ValueFromJsonVal(const JsonVal& jsonVal);

} /* namespace bt2_common */

#endif /* BABELTRACE_CPP_COMMON_BT2_VALUE_FROM_JSON_VAL_HPP */
