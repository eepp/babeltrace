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

    if (file->fp) {
        BT_COMP_LOGD("Closing file \"%s\" (%p)", file->path ? file->path->str : NULL, file->fp);

        if (fclose(file->fp)) {
            BT_COMP_LOGE("Cannot close file \"%s\": %s", file->path ? file->path->str : "NULL",
                         strerror(errno));
        }
    }

    if (file->path) {
        g_string_free(file->path, TRUE);
    }

    delete file;
}

BT_HIDDEN
struct ctf_fs_file *ctf_fs_file_create(const bt2_common::LogCfg& logCfg)
{
    ctf_fs_file *file = new ctf_fs_file {logCfg};
    file->path = g_string_new(NULL);
    if (!file->path) {
        goto error;
    }

    goto end;

error:
    ctf_fs_file_destroy(file);
    file = NULL;

end:
    return file;
}

BT_HIDDEN
int ctf_fs_file_open(struct ctf_fs_file *file, const char *mode)
{
    int ret = 0;
    struct stat stat;

    BT_COMP_LOGI("Opening file \"%s\" with mode \"%s\"", file->path->str, mode);
    file->fp = fopen(file->path->str, mode);
    if (!file->fp) {
        BT_COMP_LOGE_APPEND_CAUSE_ERRNO(file->logCfg.selfComp(), "Cannot open file",
                                        ": path=%s, mode=%s", file->path->str, mode);
        goto error;
    }

    BT_COMP_LOGI("Opened file: %p", file->fp);

    if (fstat(fileno(file->fp), &stat)) {
        BT_COMP_LOGE_APPEND_CAUSE_ERRNO(file->logCfg.selfComp(), "Cannot get file information",
                                        ": path=%s", file->path->str);
        goto error;
    }

    file->size = stat.st_size;
    BT_COMP_LOGI("File is %jd bytes", (intmax_t) file->size);
    goto end;

error:
    ret = -1;

    if (file->fp) {
        if (fclose(file->fp)) {
            BT_COMP_LOGE("Cannot close file \"%s\": %s", file->path->str, strerror(errno));
        }
    }

end:
    return ret;
}
