/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _CTF_SRC_METADATA_JSON_SCOPE_FC_FROM_JSON_VAL_HPP
#define _CTF_SRC_METADATA_JSON_SCOPE_FC_FROM_JSON_VAL_HPP

#include "cpp-common/bt2c/json-val.hpp"
#include "cpp-common/bt2c/logging.hpp"

#include "../ctf-ir.hpp"

namespace ctf {
namespace src {

Fc::UP scopeFcFromJsonVal(const bt2c::JsonObjVal& jsonFc, const bt2c::JsonObjVal *jsonTraceCls,
                          const bt2c::JsonObjVal *jsonDataStreamCls,
                          const bt2c::JsonObjVal *jsonEventRecordCls,
                          const bt2c::Logger& parentLogger);

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_JSON_SCOPE_FC_FROM_JSON_VAL_HPP */
