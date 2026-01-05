/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2015 EfficiOS Inc. and Linux Foundation
 * Copyright (C) 2015 Antoine Busque <abusque@efficios.com>
 * Copyright (C) 2019 Michael Jeanson <mjeanson@efficios.com>
 *
 * Babeltrace SO info tests
 */

#define BT_LOG_OUTPUT_LEVEL ((bt_logging_level) BT_LOG_WARNING)
#define BT_LOG_TAG          "TEST/BIN-INFO"
#include <lttng-utils/debug-info/bin-info.hpp>

#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "logging/log.h"

#include "common/assert.h"
#include "common/macros.h"

#define CATCH_CONFIG_MAIN

#include "catch.hpp"

#define SO_NAME                  "libhello-so"
#define DEBUG_NAME               "libhello-so.debug"
#define FUNC_FOO_FILENAME        "./libhello.c"
#define FUNC_FOO_PRINTF_NAME_FMT "foo+0x%" PRIx64
#define FUNC_FOO_NAME_LEN        64

#define DWARF_DIR_NAME     "dwarf-full"
#define ELF_DIR_NAME       "elf-only"
#define BUILDID_DIR_NAME   "build-id"
#define DEBUGLINK_DIR_NAME "debug-link"

/* Lower bound of PIC address mapping */
#define SO_LOW_ADDR 0x400000
/* Size of PIC address mapping */
#define SO_MEMSZ 0x800000
/* An address outside the PIC mapping */
#define SO_INV_ADDR 0x200000

#define BUILD_ID_HEX_LEN 20

namespace {

struct TestConfig
{
    uint64_t func_foo_addr;
    uint64_t func_foo_printf_offset;
    uint64_t func_foo_printf_line_no;
    uint64_t func_foo_tp_offset;
    uint64_t func_foo_tp_line_no;
    uint64_t debug_link_crc;
    gchar *debug_info_dir;
    uint8_t build_id[BUILD_ID_HEX_LEN];
    uint64_t func_foo_printf_addr;
    uint64_t func_foo_tp_addr;
    char func_foo_printf_name[FUNC_FOO_NAME_LEN];
};

int build_id_to_bin(const char *build_id_str, uint8_t *build_id_bin)
{
    int ret, len, i;

    if (!build_id_str) {
        goto error;
    }

    len = strnlen(build_id_str, BUILD_ID_HEX_LEN * 2);
    if (len != (BUILD_ID_HEX_LEN * 2)) {
        goto error;
    }

    for (i = 0; i < (len / 2); i++) {
        ret = sscanf(build_id_str + 2 * i, "%02hhx", &build_id_bin[i]);
        if (ret != 1) {
            goto error;
        }
    }

    if (i != BUILD_ID_HEX_LEN) {
        goto error;
    }

    return 0;
error:
    return -1;
}

uint64_t env_to_uint64(const char *name)
{
    const char *val = getenv(name);

    REQUIRE(val != nullptr);
    return strtoull(val, nullptr, 0);
}

TestConfig load_config()
{
    TestConfig cfg {};

    cfg.debug_info_dir = g_strdup(getenv("BIN_INFO_DATA_DIR"));
    REQUIRE(cfg.debug_info_dir != nullptr);

    cfg.func_foo_addr = env_to_uint64("BIN_INFO_FOO_ADDR");
    cfg.func_foo_printf_offset = env_to_uint64("BIN_INFO_PRINTF_OFFSET");
    cfg.func_foo_printf_line_no = env_to_uint64("BIN_INFO_PRINTF_LINENO");
    cfg.func_foo_tp_offset = env_to_uint64("BIN_INFO_TP_OFFSET");
    cfg.func_foo_tp_line_no = env_to_uint64("BIN_INFO_TP_LINENO");
    cfg.debug_link_crc = env_to_uint64("BIN_INFO_DEBUG_LINK_CRC");

    const char *build_id_str = getenv("BIN_INFO_BUILD_ID");
    REQUIRE(build_id_str != nullptr);
    REQUIRE(build_id_to_bin(build_id_str, cfg.build_id) == 0);

    g_snprintf(cfg.func_foo_printf_name, FUNC_FOO_NAME_LEN, FUNC_FOO_PRINTF_NAME_FMT,
               cfg.func_foo_printf_offset);
    cfg.func_foo_printf_addr = SO_LOW_ADDR + cfg.func_foo_addr + cfg.func_foo_printf_offset;
    cfg.func_foo_tp_addr = SO_LOW_ADDR + cfg.func_foo_addr + cfg.func_foo_tp_offset;

    return cfg;
}

void subtest_has_address(struct bin_info *bin, uint64_t addr)
{
    int ret;

    ret = bin_info_has_address(bin, SO_LOW_ADDR - 1);
    CHECK(ret == 0);

    ret = bin_info_has_address(bin, SO_LOW_ADDR);
    CHECK(ret == 1);

    ret = bin_info_has_address(bin, addr);
    CHECK(ret == 1);

    ret = bin_info_has_address(bin, SO_LOW_ADDR + SO_MEMSZ - 1);
    CHECK(ret == 1);

    ret = bin_info_has_address(bin, SO_LOW_ADDR + SO_MEMSZ);
    CHECK(ret == 0);
}

void subtest_lookup_function_name(struct bin_info *bin, uint64_t addr, char *func_name)
{
    int ret;
    char *_func_name = NULL;

    ret = bin_info_lookup_function_name(bin, addr, &_func_name);
    CHECK(ret == 0);
    if (_func_name) {
        CHECK(strcmp(_func_name, func_name) == 0);
        free(_func_name);
        _func_name = NULL;
    }

    /* Test function name lookup - erroneous address */
    ret = bin_info_lookup_function_name(bin, SO_INV_ADDR, &_func_name);
    CHECK((ret == -1 && !_func_name));
    free(_func_name);
}

void subtest_lookup_source_location(struct bin_info *bin, uint64_t addr, uint64_t line_no,
                                    const char *filename)
{
    int ret;
    struct source_location *src_loc = NULL;

    ret = bin_info_lookup_source_location(bin, addr, &src_loc);
    CHECK(ret == 0);
    if (src_loc) {
        CHECK(src_loc->line_no == line_no);
        CHECK(strcmp(src_loc->filename, filename) == 0);
        source_location_destroy(src_loc);
        src_loc = NULL;
    }

    /* Test source location lookup - erroneous address */
    ret = bin_info_lookup_source_location(bin, SO_INV_ADDR, &src_loc);
    CHECK((ret == -1 && !src_loc));
    if (src_loc) {
        source_location_destroy(src_loc);
    }
}

} /* namespace */

TEST_CASE("ELF only")
{
    TestConfig cfg = load_config();
    int ret;
    char *data_dir, *bin_path;
    struct bin_info *bin = NULL;
    struct source_location *src_loc = NULL;
    struct bt_fd_cache fdc;

    ret = bin_info_init(BT_LOG_OUTPUT_LEVEL, NULL);
    REQUIRE(ret == 0);

    data_dir = g_build_filename(cfg.debug_info_dir, ELF_DIR_NAME, NULL);
    bin_path = g_build_filename(cfg.debug_info_dir, ELF_DIR_NAME, SO_NAME, NULL);
    REQUIRE(data_dir);
    REQUIRE(bin_path);

    ret = bt_fd_cache_init(&fdc, BT_LOG_OUTPUT_LEVEL);
    REQUIRE(ret == 0);

    bin = bin_info_create(&fdc, bin_path, SO_LOW_ADDR, SO_MEMSZ, true, data_dir, NULL,
                          BT_LOG_OUTPUT_LEVEL, NULL);
    REQUIRE(bin);

    /* Test bin_info_has_address */
    subtest_has_address(bin, cfg.func_foo_printf_addr);

    /* Test function name lookup (with ELF) */
    subtest_lookup_function_name(bin, cfg.func_foo_printf_addr, cfg.func_foo_printf_name);

    /* Test source location location - should fail on ELF only file  */
    ret = bin_info_lookup_source_location(bin, cfg.func_foo_printf_addr, &src_loc);
    CHECK(ret == -1);

    source_location_destroy(src_loc);
    bin_info_destroy(bin);
    bt_fd_cache_fini(&fdc);
    g_free(data_dir);
    g_free(bin_path);
    g_free(cfg.debug_info_dir);
}

TEST_CASE("DWARF bundled in SO file")
{
    TestConfig cfg = load_config();
    int ret;
    char *data_dir, *bin_path;
    struct bin_info *bin = NULL;
    struct bt_fd_cache fdc;

    ret = bin_info_init(BT_LOG_OUTPUT_LEVEL, NULL);
    REQUIRE(ret == 0);

    data_dir = g_build_filename(cfg.debug_info_dir, DWARF_DIR_NAME, NULL);
    bin_path = g_build_filename(cfg.debug_info_dir, DWARF_DIR_NAME, SO_NAME, NULL);
    REQUIRE(data_dir);
    REQUIRE(bin_path);

    ret = bt_fd_cache_init(&fdc, BT_LOG_OUTPUT_LEVEL);
    REQUIRE(ret == 0);

    bin = bin_info_create(&fdc, bin_path, SO_LOW_ADDR, SO_MEMSZ, true, data_dir, NULL,
                          BT_LOG_OUTPUT_LEVEL, NULL);
    REQUIRE(bin);

    /* Test bin_info_has_address */
    subtest_has_address(bin, cfg.func_foo_printf_addr);

    /* Test function name lookup (with DWARF) */
    subtest_lookup_function_name(bin, cfg.func_foo_printf_addr, cfg.func_foo_printf_name);

    /* Test source location lookup */
    subtest_lookup_source_location(bin, cfg.func_foo_printf_addr, cfg.func_foo_printf_line_no,
                                   FUNC_FOO_FILENAME);

    /* Test source location lookup - inlined function */
    subtest_lookup_source_location(bin, cfg.func_foo_tp_addr, cfg.func_foo_tp_line_no,
                                   FUNC_FOO_FILENAME);

    bin_info_destroy(bin);
    bt_fd_cache_fini(&fdc);
    g_free(data_dir);
    g_free(bin_path);
    g_free(cfg.debug_info_dir);
}

TEST_CASE("Separate DWARF via build ID")
{
    TestConfig cfg = load_config();
    int ret;
    char *data_dir, *bin_path;
    struct bin_info *bin = NULL;
    struct bt_fd_cache fdc;
    uint8_t invalid_build_id[BUILD_ID_HEX_LEN] = {0xa3, 0xfd, 0x8b, 0xff, 0x45, 0xe1, 0xa9,
                                                  0x32, 0x15, 0xdd, 0x6d, 0xaa, 0xd5, 0x53,
                                                  0x98, 0x7e, 0xaf, 0xd4, 0x0c, 0xbb};

    ret = bin_info_init(BT_LOG_OUTPUT_LEVEL, NULL);
    REQUIRE(ret == 0);

    data_dir = g_build_filename(cfg.debug_info_dir, BUILDID_DIR_NAME, NULL);
    bin_path = g_build_filename(cfg.debug_info_dir, BUILDID_DIR_NAME, SO_NAME, NULL);
    REQUIRE(data_dir);
    REQUIRE(bin_path);

    ret = bt_fd_cache_init(&fdc, BT_LOG_OUTPUT_LEVEL);
    REQUIRE(ret == 0);

    bin = bin_info_create(&fdc, bin_path, SO_LOW_ADDR, SO_MEMSZ, true, data_dir, NULL,
                          BT_LOG_OUTPUT_LEVEL, NULL);
    REQUIRE(bin);

    /* Test setting invalid build_id */
    ret = bin_info_set_build_id(bin, invalid_build_id, BUILD_ID_HEX_LEN);
    CHECK(ret == -1);

    /* Test setting correct build_id */
    ret = bin_info_set_build_id(bin, cfg.build_id, BUILD_ID_HEX_LEN);
    CHECK(ret == 0);

    /* Test bin_info_has_address */
    subtest_has_address(bin, cfg.func_foo_printf_addr);

    /* Test function name lookup (with DWARF) */
    subtest_lookup_function_name(bin, cfg.func_foo_printf_addr, cfg.func_foo_printf_name);

    /* Test source location lookup */
    subtest_lookup_source_location(bin, cfg.func_foo_printf_addr, cfg.func_foo_printf_line_no,
                                   FUNC_FOO_FILENAME);

    bin_info_destroy(bin);
    bt_fd_cache_fini(&fdc);
    g_free(data_dir);
    g_free(bin_path);
    g_free(cfg.debug_info_dir);
}

TEST_CASE("Separate DWARF via debug link")
{
    TestConfig cfg = load_config();
    int ret;
    char *data_dir, *bin_path;
    struct bin_info *bin = NULL;
    struct bt_fd_cache fdc;

    ret = bin_info_init(BT_LOG_OUTPUT_LEVEL, NULL);
    REQUIRE(ret == 0);

    data_dir = g_build_filename(cfg.debug_info_dir, DEBUGLINK_DIR_NAME, NULL);
    bin_path = g_build_filename(cfg.debug_info_dir, DEBUGLINK_DIR_NAME, SO_NAME, NULL);
    REQUIRE(data_dir);
    REQUIRE(bin_path);

    ret = bt_fd_cache_init(&fdc, BT_LOG_OUTPUT_LEVEL);
    REQUIRE(ret == 0);

    bin = bin_info_create(&fdc, bin_path, SO_LOW_ADDR, SO_MEMSZ, true, data_dir, NULL,
                          BT_LOG_OUTPUT_LEVEL, NULL);
    REQUIRE(bin);

    /* Test setting debug link */
    ret = bin_info_set_debug_link(bin, DEBUG_NAME, cfg.debug_link_crc);
    CHECK(ret == 0);

    /* Test bin_info_has_address */
    subtest_has_address(bin, cfg.func_foo_printf_addr);

    /* Test function name lookup (with DWARF) */
    subtest_lookup_function_name(bin, cfg.func_foo_printf_addr, cfg.func_foo_printf_name);

    /* Test source location lookup */
    subtest_lookup_source_location(bin, cfg.func_foo_printf_addr, cfg.func_foo_printf_line_no,
                                   FUNC_FOO_FILENAME);

    bin_info_destroy(bin);
    bt_fd_cache_fini(&fdc);
    g_free(data_dir);
    g_free(bin_path);
    g_free(cfg.debug_info_dir);
}
