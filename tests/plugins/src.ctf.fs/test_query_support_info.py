# SPDX-FileCopyrightText: 2019-2025 Efficios, Inc.
# SPDX-License-Identifier: GPL-2.0-only

import bt2
import pytest


@pytest.fixture(scope="module")
def ctf_fs_comp_cls():
    return bt2.find_plugin("ctf").source_component_classes["fs"]


_CTF_VERSIONS = [pytest.param(1, id="ctf-1.8"), pytest.param(2, id="ctf-2")]


@pytest.mark.parametrize("ctf_version", _CTF_VERSIONS)
def test_non_map_params(ctf_fs_comp_cls, ctf_version):
    with pytest.raises(bt2._Error) as exc_info:
        bt2.QueryExecutor(ctf_fs_comp_cls, "babeltrace.support-info").query()

    assert "top-level is not a map value" in exc_info.value[0].message


@pytest.mark.parametrize("ctf_version", _CTF_VERSIONS)
@pytest.mark.parametrize(
    ["trace_subpath", "expected_group"],
    [
        pytest.param(
            "a/1/ust/pid/10352",
            "namespace: lttng.org,2009, name: , uid: 21cdfa5e-9a64-490a-832c-53aca6c101ba",
            id="10352-1",
        ),
        pytest.param(
            "a/2/ust/pid/10352",
            "namespace: lttng.org,2009, name: , uid: 21cdfa5e-9a64-490a-832c-53aca6c101ba",
            id="10352-2",
        ),
        pytest.param(
            "3/ust/pid/10352",
            "namespace: lttng.org,2009, name: , uid: 21cdfa5e-9a64-490a-832c-53aca6c101ba",
            id="10352-3",
        ),
        pytest.param(
            "a/1/ust/pid/10353",
            "namespace: lttng.org,2009, name: , uid: 83656eb1-b131-40e7-9666-c04ae279b58c",
            id="10353-1",
        ),
        pytest.param(
            "a/2/ust/pid/10353",
            "namespace: lttng.org,2009, name: , uid: 83656eb1-b131-40e7-9666-c04ae279b58c",
            id="10353-2",
        ),
        pytest.param(
            "3/ust/pid/10353",
            "namespace: lttng.org,2009, name: , uid: 83656eb1-b131-40e7-9666-c04ae279b58c",
            id="10353-3",
        ),
    ],
)
def test_support_info_with_uuid(
    ctf_fs_comp_cls, ctf_traces_dir, ctf_version, trace_subpath, expected_group
):
    # Test that the right group is reported for each trace
    result = bt2.QueryExecutor(
        ctf_fs_comp_cls,
        "babeltrace.support-info",
        {
            "input": str(
                ctf_traces_dir
                / str(ctf_version)
                / "succeed/session-rotation"
                / trace_subpath
            ),
            "type": "directory",
        },
    ).query()
    assert result["group"] == expected_group
