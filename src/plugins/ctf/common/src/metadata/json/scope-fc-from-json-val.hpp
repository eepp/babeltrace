/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _CTF_SRC_METADATA_JSON_SCOPE_FC_FROM_JSON_VAL_HPP
#define _CTF_SRC_METADATA_JSON_SCOPE_FC_FROM_JSON_VAL_HPP

#include "cpp-common/json-val.hpp"
#include "../ctf-ir.hpp"

namespace ctf {
namespace src {

Fc::UP scopeFcFromJsonVal(const bt2_common::JsonObjVal& jsonFc,
                          const bt2_common::JsonObjVal *jsonTraceCls,
                          const bt2_common::JsonObjVal *jsonDataStreamCls,
                          const bt2_common::JsonObjVal *jsonEventRecordCls);

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_JSON_SCOPE_FC_FROM_JSON_VAL_HPP */
