/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2016 Philippe Proulx <pproulx@efficios.com>
 * Copyright 2010-2011 EfficiOS Inc. and Linux Foundation
 */

#define BT_COMP_LOG_SELF_COMP logCfg.selfComp()
#define BT_LOG_OUTPUT_LEVEL   logCfg.logLevel()
#define BT_LOG_TAG            "PLUGIN/SRC.CTF.FS/META"
#include "logging/comp-logging.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "common/assert.h"
#include <glib.h>
#include "common/uuid.h"
#include "compat/memstream.h"
#include <babeltrace2/babeltrace.h>

#include "fs.hpp"
#include "file.hpp"
#include "metadata.hpp"
#include "../common/src/metadata/tsdl/decoder.hpp"

BT_HIDDEN
FILE *ctf_fs_metadata_open_file(const char *trace_path)
{
    GString *metadata_path;
    FILE *fp = NULL;

    metadata_path = g_string_new(trace_path);
    if (!metadata_path) {
        goto end;
    }

    g_string_append(metadata_path, G_DIR_SEPARATOR_S CTF_FS_METADATA_FILENAME);
    fp = fopen(metadata_path->str, "rb");
    g_string_free(metadata_path, TRUE);
end:
    return fp;
}

static ctf_fs_file::UP get_file(const char *trace_path, const bt2_common::LogCfg& logCfg)
{
    ctf_fs_file::UP file = ctf_fs_file_create(logCfg);

    if (!file) {
        goto error;
    }

    file->path = trace_path;
    file->path += G_DIR_SEPARATOR_S CTF_FS_METADATA_FILENAME;

    if (ctf_fs_file_open(file.get(), "rb")) {
        goto error;
    }

    goto end;

error:
    file.reset();

end:
    return file;
}

BT_HIDDEN
int ctf_fs_metadata_set_trace_class(struct ctf_fs_trace *ctf_fs_trace,
                                    ctf::src::ClkClsCfg clkClsCfg, bt_self_component *selfComp,
                                    const bt2_common::LogCfg& logCfg)
{
    int ret = 0;

    ctf_metadata_decoder_config decoder_config(logCfg);
    decoder_config.clkClsCfg = clkClsCfg;
    decoder_config.create_trace_class = true;
    decoder_config.self_comp = selfComp;

    ctf_fs_file::UP file = get_file(ctf_fs_trace->path.c_str(), logCfg);
    if (!file) {
        BT_COMP_LOGE("Cannot create metadata file object.");
        ret = -1;
        goto end;
    }

    ctf_fs_trace->metadata->decoder = ctf_metadata_decoder_create(&decoder_config);
    if (!ctf_fs_trace->metadata->decoder) {
        BT_COMP_LOGE("Cannot create metadata decoder object.");
        ret = -1;
        goto end;
    }

    ret =
        ctf_metadata_decoder_append_content(ctf_fs_trace->metadata->decoder.get(), file->fp.get());
    if (ret) {
        BT_COMP_LOGE("Cannot update metadata decoder's content.");
        goto end;
    }

    ctf_fs_trace->metadata->trace_class =
        ctf_metadata_decoder_get_ir_trace_class(ctf_fs_trace->metadata->decoder.get());
    ctf_fs_trace->metadata->tc =
        ctf_metadata_decoder_borrow_ctf_trace_class(ctf_fs_trace->metadata->decoder.get());
    BT_ASSERT(ctf_fs_trace->metadata->tc);

end:
    return ret;
}

BT_HIDDEN
int ctf_fs_metadata_init(struct ctf_fs_metadata *metadata)
{
    /* Nothing to initialize for the moment. */
    return 0;
}

BT_HIDDEN
void ctf_fs_metadata_fini(struct ctf_fs_metadata *metadata)
{
    free(metadata->text);

    if (metadata->trace_class) {
        BT_TRACE_CLASS_PUT_REF_AND_RESET(metadata->trace_class);
    }

    metadata->decoder.reset();
}
