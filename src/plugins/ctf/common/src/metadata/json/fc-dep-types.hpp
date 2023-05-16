/*
 * Copyright (c) 2023 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _CTF_SRC_METADATA_JSON_FC_DEP_TYPES_HPP
#define _CTF_SRC_METADATA_JSON_FC_DEP_TYPES_HPP

#include <unordered_map>

#include "cpp-common/log-cfg.hpp"
#include "cpp-common/text-loc-str.hpp"
#include "../ctf-ir.hpp"

namespace ctf {
namespace src {

/* Dependency (length/selector field class) type */
enum class FcDepType
{
    BOOL,
    UINT,
    SINT,
};

/* Map of dependent field class to dependency type */
using FcDepTypes = std::unordered_map<const Fc *, FcDepType>;

/*
 * Returns the (validated) dependency types of all the dependent field
 * classes within `scopeFc`.
 *
 * `scopeFc` is a scope field class for the scope `scope`.
 *
 * `pktHeaderFc`, `pktCtxFc`, `eventRecordHeaderFc`,
 * `commonEventRecordCtxFc`, `specEventRecordCtxFc`, and
 * `eventRecordPayloadFc` are the current packet header, packet context,
 * event record header, common event record context, specific event
 * record context, and event record payload field classes. Any of them
 * may be `nullptr`.
 *
 * The field locations within `scopeFc` must be absolute.
 *
 * Appends one or more causes to the error of the current thread using
 * `logCfg` and `textLocStrFmt` and throws `bt2_common::Error` when any
 * field location in `scopeFc` is invalid.
 */
FcDepTypes fcDepTypes(const Fc& scopeFc, ir::FieldLocScope scope, const Fc *pktHeaderFc,
                      const Fc *pktCtxFc, const Fc *eventRecordHeaderFc,
                      const Fc *commonEventRecordCtxFc, const Fc *specEventRecordCtxFc,
                      const Fc *eventRecordPayloadFc, const bt2_common::LogCfg& logCfg,
                      bt2_common::TextLocStrFmt textLocStrFmt);

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_JSON_FC_DEP_TYPES_HPP */
