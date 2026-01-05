# SPDX-FileCopyrightText: 2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import pytest
import bt_tests_utils as btu


def _run_dwarf_test(data_dir, build_root_dir, arch, test_name):
    binary = btu.exe_path(
        btu.build_dir_of_source_file(build_root_dir, __file__) / "dwarf-test"
    )

    if not binary.exists():
        pytest.skip("`dwarf-test` Catch2 binary doesn't exist")

    dwarf_data_dir = data_dir / "plugins/flt.lttng-utils.debug-info" / arch
    btu.run(
        build_root_dir,
        binary,
        [test_name],
        extra_env={"DWARF_DATA_DIR": str(dwarf_data_dir)},
        check=True,
    )


_ARCHS = [
    "i386-linux-gnu",
    "powerpc-linux-gnu",
    "powerpc64le-linux-gnu",
    "x86-64-linux-gnu",
]


@pytest.mark.parametrize("arch", _ARCHS)
def test_dwarf_elf_without_dwarf(data_dir, build_root_dir, arch):
    _run_dwarf_test(
        data_dir,
        build_root_dir,
        arch,
        "ELF file without DWARF",
    )


@pytest.mark.parametrize("arch", _ARCHS)
def test_dwarf_elf_with_dwarf(data_dir, build_root_dir, arch):
    _run_dwarf_test(
        data_dir,
        build_root_dir,
        arch,
        "ELF file with DWARF",
    )
