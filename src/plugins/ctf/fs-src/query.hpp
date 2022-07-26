/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * BabelTrace - CTF on File System Component
 */

#ifndef BABELTRACE_PLUGIN_CTF_FS_QUERY_H
#define BABELTRACE_PLUGIN_CTF_FS_QUERY_H

#include "common/macros.h"
#include "cpp-common/log-cfg.hpp"
#include <babeltrace2/babeltrace.h>
#include "cpp-common/bt2/value.hpp"

bt2::Value::Shared metadata_info_query(bt2::ConstMapValue params, const bt2_common::LogCfg& logCfg);

bt2::Value::Shared trace_infos_query(bt2::ConstMapValue params, const bt2_common::LogCfg& logCfg);

bt2::Value::Shared support_info_query(bt2::ConstMapValue params, const bt2_common::LogCfg& logCfg);

#endif /* BABELTRACE_PLUGIN_CTF_FS_QUERY_H */
