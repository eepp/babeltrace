# SPDX-FileCopyrightText: 2019 Francis Deslauriers <francis.deslauriers@efficios.com>
# SPDX-FileCopyrightText: 2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import bt2
import pytest
import bt_tests_utils as btu


@pytest.fixture(scope="module")
def src_comp_cls(data_dir):
    return btu.find_comp_cls_in_path(
        data_dir / "plugins/flt.utils.muxer",
        "test-muxer",
        btu.CompClsType.SOURCE,
        "TheSourceOfConfusion",
    )


@pytest.mark.parametrize(
    "test_name",
    [
        "basic-timestamp-ordering",
        "diff-event-class-id",
        "diff-event-class-name",
        "diff-inactivity-msg-cs",
        "diff-stream-class-id",
        "diff-stream-class-name",
        "diff-stream-class-no-name",
        "diff-stream-id",
        "diff-stream-name",
        "diff-stream-no-name",
        "diff-trace-name",
        "multi-iter-ordering",
    ],
)
def test_muxer_succeed(data_dir, test_name, src_comp_cls):
    btu.convert_sink_text_details_test(
        bt2.ComponentSpec(
            src_comp_cls,
            params={"test-name": test_name},
        ),
        data_dir / "plugins/flt.utils.muxer/succeed" / "{}.expect".format(test_name),
        details_params={"compact": False, "with-metadata": False},
    )
