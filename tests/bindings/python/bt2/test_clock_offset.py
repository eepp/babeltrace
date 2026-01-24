# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019-2026 EfficiOS Inc.

import bt2
import pytest


def test_create_def():
    clk_offset = bt2.ClockOffset()
    assert clk_offset.seconds == 0
    assert clk_offset.cycles == 0


def test_create():
    clk_offset = bt2.ClockOffset(23, 4871232)
    assert clk_offset.seconds == 23
    assert clk_offset.cycles == 4871232


def test_create_kwargs():
    clk_offset = bt2.ClockOffset(seconds=23, cycles=4871232)
    assert clk_offset.seconds == 23
    assert clk_offset.cycles == 4871232


def test_create_invalid_seconds():
    with pytest.raises(TypeError):
        bt2.ClockOffset("hello", 4871232)


def test_create_invalid_cycles():
    with pytest.raises(TypeError):
        bt2.ClockOffset(23, "hello")


def test_eq():
    clk_offset_1 = bt2.ClockOffset(23, 42)
    clk_offset_2 = bt2.ClockOffset(23, 42)
    assert clk_offset_1 == clk_offset_2


def test_ne_seconds():
    clk_offset_1 = bt2.ClockOffset(23, 42)
    clk_offset_2 = bt2.ClockOffset(24, 42)
    assert clk_offset_1 != clk_offset_2


def test_ne_cycles():
    clk_offset_1 = bt2.ClockOffset(23, 42)
    clk_offset_2 = bt2.ClockOffset(23, 43)
    assert clk_offset_1 != clk_offset_2


def test_eq_invalid():
    assert not (bt2.ClockOffset() == 23)
