/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Efficios Inc.
 */

#ifndef SRC_PLUGINS_CTF_COMMON_METADATA_DECODER_PACKETIZED_FILE_STREAM_TO_BUF
#define SRC_PLUGINS_CTF_COMMON_METADATA_DECODER_PACKETIZED_FILE_STREAM_TO_BUF

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <babeltrace2/babeltrace.h>
#include "cpp-common/log-cfg.hpp"

int ctf_metadata_decoder_packetized_file_stream_to_buf(FILE *fp, char **buf, int byte_order,
                                                       bool *is_uuid_set, uint8_t *uuid,
                                                       const bt2_common::LogCfg& logCfg);

#endif /* SRC_PLUGINS_CTF_COMMON_METADATA_DECODER_PACKETIZED_FILE_STREAM_TO_BUF */
