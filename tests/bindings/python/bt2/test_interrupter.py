# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019-2026 EfficiOS Inc.

import bt2
import pytest


@pytest.fixture
def interrupter():
    return bt2.Interrupter()


def test_create(interrupter):
    assert not interrupter.is_set


def test_is_set(interrupter):
    assert not interrupter.is_set


def test_bool(interrupter):
    assert not interrupter
    interrupter.set()
    assert interrupter


def test_set(interrupter):
    assert not interrupter
    interrupter.set()
    assert interrupter


def test_reset(interrupter):
    interrupter.set()
    assert interrupter
    interrupter.reset()
    assert not interrupter
