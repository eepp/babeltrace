/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2016 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef CTF_FS_METADATA_H
#define CTF_FS_METADATA_H

#include <stdbool.h>
#include <stdio.h>
#include <glib.h>
#include "common/macros.h"
#include "cpp-common/log-cfg.hpp"
#include "../common/src/clk-cls-cfg.hpp"
#include <babeltrace2/babeltrace.h>

#define CTF_FS_METADATA_FILENAME "metadata"

struct ctf_fs_trace;
struct ctf_fs_metadata;

int ctf_fs_metadata_set_trace_class(struct ctf_fs_trace *ctf_fs_trace,
                                    ctf::src::ClkClsCfg clkClsCfg, bt_self_component *selfComp,
                                    const bt2_common::LogCfg& logCfg);

FILE *ctf_fs_metadata_open_file(const char *trace_path);

bool ctf_metadata_is_packetized(FILE *fp, int *byte_order);

#endif /* CTF_FS_METADATA_H */
