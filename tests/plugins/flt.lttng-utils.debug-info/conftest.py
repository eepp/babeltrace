# SPDX-FileCopyrightText: 2025 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: MIT

# pyright: strict

from typing import List

import pytest


def pytest_collection_modifyitems(
    config: "pytest.Config", items: List[pytest.Item]
) -> None:
    for item in items:
        item.add_marker(pytest.mark.needs_lttng_utils_plugin)
