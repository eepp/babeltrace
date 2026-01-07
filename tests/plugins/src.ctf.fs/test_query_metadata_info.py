# SPDX-FileCopyrightText: 2019-2025 Efficios, Inc.
# SPDX-License-Identifier: GPL-2.0-only

import tempfile

import bt2
import pytest


@pytest.fixture(scope="module")
def ctf_fs_comp_cls():
    return bt2.find_plugin("ctf").source_component_classes["fs"]


def test_non_map_params(ctf_fs_comp_cls):
    with pytest.raises(bt2._Error) as exc_info:
        bt2.QueryExecutor(ctf_fs_comp_cls, "metadata-info").query()

    assert "top-level is not a map value" in exc_info.value[0].message


@pytest.mark.parametrize("trace_name", ["succeed1", "lf-metadata", "crlf-metadata"])
def test_query_metadata_info(ctf_fs_comp_cls, ctf_traces_dir, data_dir, trace_name):
    result = bt2.QueryExecutor(
        ctf_fs_comp_cls,
        "metadata-info",
        {"path": str(ctf_traces_dir / "1/succeed" / trace_name)},
    ).query()

    assert not result["is-packetized"]

    expect_file = (
        data_dir
        / "plugins/src.ctf.fs/query"
        / "metadata-info-{}.expect".format(trace_name)
    )

    assert (
        str(result["text"]).replace("\r\n", "\n").strip()
        == expect_file.read_text().strip()
    )


def test_non_existent_trace_dir(ctf_fs_comp_cls):
    with tempfile.TemporaryDirectory() as empty_dir:
        with pytest.raises(bt2._Error) as exc_info:
            bt2.QueryExecutor(
                ctf_fs_comp_cls, "metadata-info", {"path": empty_dir}
            ).query()

        assert "No such file or directory" in exc_info.value[0].message
