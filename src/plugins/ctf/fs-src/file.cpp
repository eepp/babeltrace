/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2016 Philippe Proulx <pproulx@efficios.com>
 */

#define BT_CLOG_CFG (logCfg)
#define BT_LOG_TAG  "PLUGIN/SRC.CTF.FS/FILE"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <glib.h>
#include "file.hpp"
#include "cpp-common/cfg-logging.hpp"
#include "cpp-common/cfg-logging-error-reporting.hpp"

void ctf_fs_file_destroy(struct ctf_fs_file *file)
{
    if (!file) {
        return;
    }

    if (file->fp) {
        const bt2_common::LogCfg& logCfg = file->logCfg;

        BT_CLOGD("Closing file \"%s\" (%p)", file->path ? file->path->str : NULL, file->fp);

        if (fclose(file->fp)) {
            BT_CLOGE("Cannot close file \"%s\": %s", file->path ? file->path->str : "NULL",
                     strerror(errno));
        }
    }

    if (file->path) {
        g_string_free(file->path, TRUE);
    }

    delete file;
}

void ctf_fs_file_deleter::operator()(struct ctf_fs_file *file)
{
    ctf_fs_file_destroy(file);
}

ctf_fs_file::UP ctf_fs_file_create(const bt2_common::LogCfg& logCfg)
{
    ctf_fs_file::UP file {new ctf_fs_file {logCfg}};

    file->path = g_string_new(NULL);
    if (!file->path) {
        goto error;
    }

    goto end;

error:
    file.reset();

end:
    return file;
}

int ctf_fs_file_open(struct ctf_fs_file *file, const char *mode)
{
    int ret = 0;
    struct stat stat;
    const bt2_common::LogCfg& logCfg = file->logCfg;

    BT_CLOGI("Opening file \"%s\" with mode \"%s\"", file->path->str, mode);
    file->fp = fopen(file->path->str, mode);
    if (!file->fp) {
        BT_CLOGE_ERRNO_APPEND_CAUSE("Cannot open file", ": path=%s, mode=%s", file->path->str,
                                    mode);
        goto error;
    }

    BT_CLOGI("Opened file: %p", file->fp);

    if (fstat(fileno(file->fp), &stat)) {
        BT_CLOGE_ERRNO_APPEND_CAUSE("Cannot get file information", ": path=%s", file->path->str);
        goto error;
    }

    file->size = stat.st_size;
    BT_CLOGI("File is %jd bytes", (intmax_t) file->size);
    goto end;

error:
    ret = -1;

    if (file->fp) {
        if (fclose(file->fp)) {
            BT_CLOGE("Cannot close file \"%s\": %s", file->path->str, strerror(errno));
        }
    }

end:
    return ret;
}
