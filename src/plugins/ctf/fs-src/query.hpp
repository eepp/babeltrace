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

bt_component_class_query_method_status metadata_info_query(const bt_value *params,
                                                           const bt2_common::LogCfg& logCfg,
                                                           const bt_value **result);

bt_component_class_query_method_status trace_infos_query(const bt_value *params,
                                                         const bt2_common::LogCfg& logCfg,
                                                         const bt_value **result);

bt_component_class_query_method_status support_info_query(const bt_value *params,
                                                          const bt2_common::LogCfg& logCfg,
                                                          const bt_value **result);

#endif /* BABELTRACE_PLUGIN_CTF_FS_QUERY_H */
