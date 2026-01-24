# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019-2026 EfficiOS Inc.

import bt2
import pytest


class _DummySink(bt2._UserSinkComponent):
    def _user_consume(self):
        pass


def test_init_invalid_cls_type():
    with pytest.raises(TypeError):
        bt2.ComponentDescriptor(int)


def test_init_invalid_params_type():
    with pytest.raises(TypeError):
        bt2.ComponentDescriptor(_DummySink, object())


def test_init_invalid_obj_non_python_comp_cls(dmesg_comp_cls):
    with pytest.raises(ValueError):
        bt2.ComponentDescriptor(dmesg_comp_cls, obj=57)


def test_init_with_user_comp_cls():
    bt2.ComponentDescriptor(_DummySink)


def test_init_with_gen_comp_cls(dmesg_comp_cls):
    bt2.ComponentDescriptor(dmesg_comp_cls)


@pytest.fixture
def comp_descr():
    obj = object()
    descr = bt2.ComponentDescriptor(_DummySink, {"zoom": -23}, obj)
    return obj, descr


def test_attr_component_class(comp_descr):
    _, descr = comp_descr
    assert descr.component_class is _DummySink


def test_attr_params(comp_descr):
    _, descr = comp_descr
    assert descr.params == {"zoom": -23}


def test_attr_obj(comp_descr):
    obj, descr = comp_descr
    assert descr.obj is obj
