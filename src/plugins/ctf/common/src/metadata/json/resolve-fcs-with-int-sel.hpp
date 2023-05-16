/*
 * Copyright (c) 2023 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _CTF_SRC_METADATA_JSON_RESOLVE_FCS_WITH_INT_SEL_HPP
#define _CTF_SRC_METADATA_JSON_RESOLVE_FCS_WITH_INT_SEL_HPP

#include "cpp-common/log-cfg.hpp"
#include "cpp-common/text-loc-str.hpp"
#include "../ctf-ir.hpp"

namespace ctf {
namespace src {

/*
 * Replaces all the field classes within `scopeFc` having the type
 * `OPTIONAL_WITH_UINT_SEL` or `VARIANT_WITH_UINT_SEL` with the correct
 * versions, keeping their children as is.
 *
 * `scopeFc` is a scope field class for the scope `scope`.
 *
 * Also validates the dynamic-length field classes.
 *
 * This function uses fcDepTypes() behind the scenes, therefore all the
 * preconditions of the latter apply.
 *
 * Appends one or more causes to the error of the current thread using
 * `logCfg` and `textLocStrFmt` and throws `bt2_common::Error` when any
 * field class in `scopeFc` is invalid.
 */
void resolveFcsWithIntSel(Fc& scopeFc, ir::FieldLocScope scope, const Fc *pktHeaderFc,
                          const Fc *pktCtxFc, const Fc *eventRecordHeaderFc,
                          const Fc *commonEventRecordCtxFc, const Fc *specEventRecordCtxFc,
                          const Fc *eventRecordPayloadFc, const bt2_common::LogCfg& logCfg,
                          bt2_common::TextLocStrFmt textLocStrFmt);

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_JSON_RESOLVE_FCS_WITH_INT_SEL_HPP */
