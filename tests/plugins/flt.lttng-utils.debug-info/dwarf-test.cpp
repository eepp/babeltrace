/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2015 EfficiOS Inc. and Linux Foundation
 * Copyright (C) 2015 Antoine Busque <abusque@efficios.com>
 *
 * Babeltrace bt_dwarf (DWARF utilities) tests
 */

#include <lttng-utils/debug-info/dwarf.hpp>

#include <fcntl.h>
#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CATCH_CONFIG_MAIN

#include "catch.hpp"

#define SO_NAME        "libhello-so"
#define DWARF_DIR_NAME "dwarf-full"
#define ELF_DIR_NAME   "elf-only"

namespace {

const char *data_dir()
{
    const char *dir = getenv("DWARF_DATA_DIR");

    REQUIRE(dir != nullptr);
    return dir;
}

} /* namespace */

/*
 * Test that we fail on an ELF file without DWARF.
 */
TEST_CASE("ELF file without DWARF")
{
    int fd;
    char *path;
    Dwarf *dwarf_info = NULL;

    path = g_build_filename(data_dir(), ELF_DIR_NAME, SO_NAME, NULL);
    REQUIRE(path);

    fd = open(path, O_RDONLY);
    INFO("Open ELF file " << path);
    REQUIRE(fd >= 0);

    dwarf_info = dwarf_begin(fd, DWARF_C_READ);
    CHECK(!dwarf_info);

    if (dwarf_info) {
        dwarf_end(dwarf_info);
    }

    close(fd);
    g_free(path);
}

/*
 * Test with a proper ELF file with DWARF.
 */
TEST_CASE("ELF file with DWARF")
{
    int fd, ret, tag = -1;
    char *path;
    char *die_name = NULL;
    struct bt_dwarf_cu *cu = NULL;
    struct bt_dwarf_die *die = NULL;
    Dwarf *dwarf_info = NULL;

    path = g_build_filename(data_dir(), DWARF_DIR_NAME, SO_NAME, NULL);
    REQUIRE(path);

    fd = open(path, O_RDONLY);
    INFO("Open DWARF file " << path);
    REQUIRE(fd >= 0);

    dwarf_info = dwarf_begin(fd, DWARF_C_READ);
    REQUIRE(dwarf_info);

    cu = bt_dwarf_cu_create(dwarf_info);
    REQUIRE(cu);

    ret = bt_dwarf_cu_next(cu);
    CHECK(ret == 0);

    die = bt_dwarf_die_create(cu);
    REQUIRE(die);

    /*
     * Test bt_dwarf_die_next twice, as the code path is different
     * for DIEs at depth 0 (just created) and other depths.
     */
    ret = bt_dwarf_die_next(die);
    CHECK(ret == 0);
    CHECK(die->depth == 1);

    ret = bt_dwarf_die_next(die);
    CHECK(ret == 0);
    CHECK(die->depth == 1);

    /* Reset DIE to test dwarf_child */
    bt_dwarf_die_destroy(die);
    die = bt_dwarf_die_create(cu);
    REQUIRE(die);

    ret = bt_dwarf_die_child(die);
    CHECK(ret == 0);
    CHECK(die->depth == 1);

    ret = bt_dwarf_die_get_tag(die, &tag);
    CHECK(ret == 0);
    CHECK(tag == DW_TAG_typedef);

    ret = bt_dwarf_die_get_name(die, &die_name);
    CHECK(ret == 0);
    CHECK(strcmp(die_name, "size_t") == 0);

    bt_dwarf_die_destroy(die);
    bt_dwarf_cu_destroy(cu);
    dwarf_end(dwarf_info);
    free(die_name);
    close(fd);
    g_free(path);
}
