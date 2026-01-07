# SPDX-FileCopyrightText: 2025 EfficiOS, Inc.
# SPDX-License-Identifier: GPL-2.0-only

import bt2
import pytest


@pytest.mark.parametrize(
    "query_name",
    [
        "sessions",
        "babeltrace.support-info",
    ],
)
def test_no_params(live_comp_cls, query_name):
    with pytest.raises(bt2._Error) as exc_info:
        bt2.QueryExecutor(live_comp_cls, query_name).query()

    assert "top-level is not a map value" in exc_info.value[0].message
