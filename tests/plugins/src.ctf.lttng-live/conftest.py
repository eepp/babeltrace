# SPDX-FileCopyrightText: 2025 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: MIT

# pyright: strict, reportMissingTypeStubs=false

import typing

if typing.TYPE_CHECKING:
    import bt2

import pytest


@pytest.fixture(scope="module")
def live_comp_cls() -> "bt2._SourceComponentClassConst":
    import bt2

    return bt2.find_plugin(
        "ctf"
    ).source_component_classes[  # pyright: ignore[reportOptionalMemberAccess]
        "lttng-live"
    ]
