/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2016 Philippe Proulx <pproulx@efficios.com>
 */

#define BT_COMP_LOG_SELF_COMP (file->logCfg.selfComp())
#define BT_LOG_OUTPUT_LEVEL   (file->logCfg.logLevel())
#define BT_LOG_TAG            "PLUGIN/SRC.CTF.FS/FILE"
#include "logging/comp-logging.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <glib.h>
#include "file.hpp"

BT_HIDDEN
void ctf_fs_file_destroy(struct ctf_fs_file *file)
{
    if (!file) {
        return;
    }

    delete file;
}

void ctf_fs_file_deleter::operator()(struct ctf_fs_file *file)
{
    ctf_fs_file_destroy(file);
}

BT_HIDDEN
ctf_fs_file::UP ctf_fs_file_create(const bt2_common::LogCfg& logCfg)
{
    return ctf_fs_file::UP {new ctf_fs_file {logCfg}};
}

BT_HIDDEN
int ctf_fs_file_open(struct ctf_fs_file *file, const char *mode)
{
    int ret = 0;
    struct stat stat;

    BT_COMP_LOGI("Opening file \"%s\" with mode \"%s\"", file->path.c_str(), mode);
    file->fp.reset(fopen(file->path.c_str(), mode));
    if (!file->fp) {
        BT_COMP_LOGE_APPEND_CAUSE_ERRNO(file->logCfg.selfComp(), "Cannot open file",
                                        ": path=%s, mode=%s", file->path.c_str(), mode);
        goto error;
    }

    BT_COMP_LOGI("Opened file: %p", file->fp.get());

    if (fstat(fileno(file->fp.get()), &stat)) {
        BT_COMP_LOGE_APPEND_CAUSE_ERRNO(file->logCfg.selfComp(), "Cannot get file information",
                                        ": path=%s", file->path.c_str());
        goto error;
    }

    file->size = stat.st_size;
    BT_COMP_LOGI("File is %jd bytes", (intmax_t) file->size);
    goto end;

error:
    ret = -1;

end:
    return ret;
}
