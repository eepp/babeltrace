# SPDX-FileCopyrightText: 2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import pathlib
import tempfile

import bt2
import pytest
import bt_tests_utils as btu

pytestmark = pytest.mark.needs_lttng_utils_plugin


@pytest.fixture(scope="module")
def debug_info_comp_cls():
    return bt2.find_plugin("lttng-utils").filter_component_classes["debug-info"]


def _run_convert_with_details(
    source_component_specs,
    mip_version,
    details_comp_cls,
    filter_component_specs=None,
):
    with tempfile.TemporaryDirectory(prefix="bt-test-debug-info-") as temp_dir:
        temp_path = pathlib.Path(temp_dir) / "output.txt"

        btu.convert(
            source_component_specs,
            btu.SinkComponentSpec(
                details_comp_cls,
                {
                    "with-trace-name": False,
                    "with-stream-name": False,
                    "with-uuid": False,
                    "with-uid": False,
                    "path": str(temp_path),
                },
            ),
            filter_component_specs,
            mip_version=mip_version,
        )

        return temp_path.read_text()


_MIP_VERSIONS = [pytest.param(0, id="mip-0"), pytest.param(1, id="mip-1")]


# Test that the `flt.lttng-utils.debug-info` filter component produces
# expected output on a trace containing LTTng debug info fields.
@pytest.mark.parametrize("mip_version", _MIP_VERSIONS)
def test_debug_info_trace(data_dir, ctf_traces_dir, mip_version, debug_info_comp_cls):
    btu.convert_sink_text_details_test(
        ctf_traces_dir / "1/succeed/debug-info",
        (
            data_dir
            / "plugins/flt.lttng-utils.debug-info"
            / "trace-debug-info-mip{}.expect".format(mip_version)
        ),
        bt2.ComponentSpec(
            debug_info_comp_cls,
            params={
                "target-prefix": str(
                    data_dir
                    / "plugins/flt.lttng-utils.debug-info/x86-64-linux-gnu/dwarf-full"
                )
            },
        ),
        details_params={"with-trace-name": False, "with-stream-name": False},
        mip_version=mip_version,
    )


def _compare_with_without_debug_info(
    source_component_specs, mip_version, details_comp_cls, debug_info_comp_cls
):
    result_without = _run_convert_with_details(
        source_component_specs,
        mip_version,
        details_comp_cls,
    )

    result_with = _run_convert_with_details(
        source_component_specs,
        mip_version,
        details_comp_cls,
        bt2.ComponentSpec(debug_info_comp_cls),
    )

    assert result_with.strip() == result_without.strip()


# Compare output with and without `flt.lttng-utils.debug-info` filter on
# CTF traces.
#
# Both are expected to be identical for traces without LTTng
# debugging fields.
@pytest.mark.parametrize("mip_version", _MIP_VERSIONS)
@pytest.mark.parametrize(
    "trace_name",
    [
        "smalltrace",
        "2packets",
        "session-rotation",
    ],
)
def test_compare_ctf_src_trace(
    ctf_traces_dir, mip_version, trace_name, details_comp_cls, debug_info_comp_cls
):
    _compare_with_without_debug_info(
        str(ctf_traces_dir / "1/succeed" / trace_name),
        mip_version,
        details_comp_cls,
        debug_info_comp_cls,
    )


# Compare output with and without `flt.lttng-utils.debug-info` filter
# component on `src.trace-ir-test.AllFields`.
#
# Both are expected to be identical.
@pytest.mark.parametrize("mip_version", _MIP_VERSIONS)
def test_compare_complete_src_trace(mip_version, details_comp_cls, debug_info_comp_cls):
    _compare_with_without_debug_info(
        bt2.ComponentSpec(
            bt2.find_plugin("trace-ir-test").source_component_classes["AllFields"]
        ),
        mip_version,
        details_comp_cls,
        debug_info_comp_cls,
    )
