/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2016 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef CTF_FS_FILE_H
#define CTF_FS_FILE_H

#include <stdio.h>
#include <glib.h>
#include <memory>
#include <string>
#include "common/macros.h"
#include "cpp-common/log-cfg.hpp"
#include "cpp-common/libc-up.hpp"

struct ctf_fs_file_deleter
{
    void operator()(struct ctf_fs_file *file);
};

struct ctf_fs_file
{
    using UP = std::unique_ptr<ctf_fs_file, ctf_fs_file_deleter>;

    explicit ctf_fs_file(const bt2_common::LogCfg& logCfgParam) noexcept : logCfg {logCfgParam}
    {
    }

    const bt2_common::LogCfg logCfg;

    std::string path;

    bt2_common::FileUP fp;

    off_t size = 0;
};

void ctf_fs_file_destroy(struct ctf_fs_file *file);

ctf_fs_file::UP ctf_fs_file_create(const bt2_common::LogCfg& logCfg);

int ctf_fs_file_open(struct ctf_fs_file *file, const char *mode);

#endif /* CTF_FS_FILE_H */
