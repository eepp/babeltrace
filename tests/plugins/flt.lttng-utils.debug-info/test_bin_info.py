# SPDX-FileCopyrightText: 2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import pytest
import bt_tests_utils as btu

_ARCH_PARAMS = {
    "i386-linux-gnu": {
        "foo_addr": "0x1c8d",
        "printf_offset": "0xda",
        "tp_offset": "0x12",
        "debug_link_crc": "0xdeead493",
    },
    "powerpc-linux-gnu": {
        "foo_addr": "0x23bc",
        "printf_offset": "0x114",
        "tp_offset": "0x28",
        "debug_link_crc": "0xd7b98958",
    },
    "powerpc64le-linux-gnu": {
        "foo_addr": "0x2e7c",
        "printf_offset": "0x190",
        "tp_offset": "0x1c",
        "debug_link_crc": "0x9b8eb2ff",
    },
    "x86-64-linux-gnu": {
        "foo_addr": "0x2277",
        "printf_offset": "0xf0",
        "tp_offset": "0x89",
        "debug_link_crc": "0x289a8fdc",
    },
}


def _run_bin_info_test(data_dir, build_root_dir, arch, test_name):
    binary = btu.exe_path(
        btu.build_dir_of_source_file(build_root_dir, __file__) / "bin-info-test"
    )

    if not binary.exists():
        pytest.skip("`bin-info-test` Catch2 binary doesn't exist")

    params = _ARCH_PARAMS[arch]
    btu.run(
        build_root_dir,
        binary,
        [test_name],
        extra_env={
            "BIN_INFO_DATA_DIR": str(
                data_dir / "plugins/flt.lttng-utils.debug-info" / arch
            ),
            "BIN_INFO_FOO_ADDR": params["foo_addr"],
            "BIN_INFO_PRINTF_OFFSET": params["printf_offset"],
            "BIN_INFO_PRINTF_LINENO": "36",
            "BIN_INFO_TP_OFFSET": params["tp_offset"],
            "BIN_INFO_TP_LINENO": "35",
            "BIN_INFO_DEBUG_LINK_CRC": params["debug_link_crc"],
            "BIN_INFO_BUILD_ID": "cdd98cdd87f7fe64c13b6daad553987eafd40cbb",
        },
        check=True,
    )


_ARCHS = list(_ARCH_PARAMS.keys())


@pytest.mark.parametrize("arch", _ARCHS)
def test_bin_info_elf_only(data_dir, build_root_dir, arch):
    _run_bin_info_test(data_dir, build_root_dir, arch, "ELF only")


@pytest.mark.parametrize("arch", _ARCHS)
def test_bin_info_dwarf_bundled(data_dir, build_root_dir, arch):
    _run_bin_info_test(data_dir, build_root_dir, arch, "DWARF bundled in SO file")


@pytest.mark.parametrize("arch", _ARCHS)
def test_bin_info_build_id(data_dir, build_root_dir, arch):
    _run_bin_info_test(data_dir, build_root_dir, arch, "Separate DWARF via build ID")


@pytest.mark.parametrize("arch", _ARCHS)
def test_bin_info_debug_link(data_dir, build_root_dir, arch):
    _run_bin_info_test(data_dir, build_root_dir, arch, "Separate DWARF via debug link")
