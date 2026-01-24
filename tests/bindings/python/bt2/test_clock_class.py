# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019-2026 EfficiOS Inc.

import uuid

import bt2
import utils
import pytest
from bt2 import value as bt2_value


# Runs `user_func` within a component initialization context for the
# given MIP version `mip_version`.
#
# Expects `user_func` to raise an exception of type `expected_exc_type`,
# its string optionally containing `expected_str`.
def _raises_in_comp_init(mip_version, expected_exc_type, user_func, expected_str=None):
    def f(comp_self):
        try:
            user_func(comp_self)
        except Exception as exc:
            return exc

    exc = utils.run_in_component_init(mip_version, f)
    assert exc is not None
    assert type(exc) is expected_exc_type

    if expected_str is not None:
        assert expected_str in str(exc)


@pytest.mark.parametrize(
    "mip_version",
    [pytest.param(0, id="mip-0"), pytest.param(1, id="mip-1")],
)
class TestClkClsAllMips:
    @pytest.fixture
    def run_in_comp_init(self, mip_version):
        return lambda f: utils.run_in_component_init(mip_version, f)

    @pytest.fixture
    def raises_in_comp_init(self, mip_version):
        return lambda expected_exc_type, user_func, expected_str=None: _raises_in_comp_init(
            mip_version, expected_exc_type, user_func, expected_str
        )

    def test_create_def(self, run_in_comp_init):
        clk_cls = run_in_comp_init(lambda comp_self: comp_self._create_clock_class())

        # Common MIP 0 and MIP 1 attributes
        assert clk_cls.name is None
        assert clk_cls.frequency == 1000000000
        assert clk_cls.description is None
        assert clk_cls.offset == bt2.ClockOffset()
        assert clk_cls.origin is bt2.unix_epoch_clock_origin
        assert len(clk_cls.user_attributes) == 0

    def test_create_name(self, run_in_comp_init):
        assert (
            run_in_comp_init(
                lambda comp_self: comp_self._create_clock_class(name="the_clock")
            ).name
            == "the_clock"
        )

    def test_create_invalid_name(self, raises_in_comp_init):
        raises_in_comp_init(
            TypeError, lambda comp_self: comp_self._create_clock_class(name=23)
        )

    def test_create_description(self, run_in_comp_init):
        assert (
            run_in_comp_init(
                lambda comp_self: comp_self._create_clock_class(description="hi people")
            ).description
            == "hi people"
        )

    def test_create_invalid_description(self, raises_in_comp_init):
        raises_in_comp_init(
            TypeError, lambda comp_self: comp_self._create_clock_class(description=23)
        )

    def test_create_frequency(self, run_in_comp_init):
        assert (
            run_in_comp_init(
                lambda comp_self: comp_self._create_clock_class(frequency=987654321)
            ).frequency
            == 987654321
        )

    def test_create_invalid_frequency(self, raises_in_comp_init):
        raises_in_comp_init(
            TypeError, lambda comp_self: comp_self._create_clock_class(frequency="lel")
        )

    def test_create_precision(self, run_in_comp_init):
        assert (
            run_in_comp_init(
                lambda comp_self: comp_self._create_clock_class(precision=12)
            ).precision
            == 12
        )

    def test_create_invalid_precision(self, raises_in_comp_init):
        raises_in_comp_init(
            TypeError, lambda comp_self: comp_self._create_clock_class(precision="lel")
        )

    def test_create_offset(self, run_in_comp_init):
        assert run_in_comp_init(
            lambda comp_self: comp_self._create_clock_class(
                offset=bt2.ClockOffset(12, 56)
            )
        ).offset == bt2.ClockOffset(12, 56)

    def test_create_invalid_offset(self, raises_in_comp_init):
        raises_in_comp_init(
            TypeError, lambda comp_self: comp_self._create_clock_class(offset=object())
        )

    def test_create_orig_is_unix_epoch_true(self, run_in_comp_init):
        assert (
            run_in_comp_init(
                lambda comp_self: comp_self._create_clock_class(
                    origin_is_unix_epoch=True
                )
            ).origin
            is bt2.unix_epoch_clock_origin
        )

    def test_create_orig_is_unix_epoch_false(self, run_in_comp_init):
        assert (
            run_in_comp_init(
                lambda comp_self: comp_self._create_clock_class(
                    origin_is_unix_epoch=False
                )
            ).origin
            is bt2.unknown_clock_origin
        )

    def test_create_invalid_orig_is_unix_epoch(self, raises_in_comp_init):
        raises_in_comp_init(
            TypeError,
            lambda comp_self: comp_self._create_clock_class(origin_is_unix_epoch=23),
        )

    def test_create_unix_epoch_orig(self, run_in_comp_init):
        assert (
            run_in_comp_init(
                lambda comp_self: comp_self._create_clock_class(
                    origin=bt2.unix_epoch_clock_origin
                )
            ).origin
            is bt2.unix_epoch_clock_origin
        )

    def test_create_unknown_orig(self, run_in_comp_init):
        assert (
            run_in_comp_init(
                lambda comp_self: comp_self._create_clock_class(
                    origin=bt2.unknown_clock_origin
                )
            ).origin
            is bt2.unknown_clock_origin
        )

    def test_create_invalid_orig(self, raises_in_comp_init):
        raises_in_comp_init(
            TypeError,
            lambda comp_self: comp_self._create_clock_class(origin=23),
            "'int' is not a '<class 'bt2.clock_class.ClockOrigin'>' object",
        )

    @pytest.mark.parametrize(
        "orig_is_unix_epoch",
        [pytest.param(True, id="unix-epoch"), pytest.param(False, id="not-unix-epoch")],
    )
    def test_create_multiple_orig(self, orig_is_unix_epoch, raises_in_comp_init):
        def f(comp_self):
            return comp_self._create_clock_class(
                origin_is_unix_epoch=orig_is_unix_epoch,
                origin=bt2.ClockOrigin("ns", "name", "uid"),
            )

        raises_in_comp_init(
            ValueError,
            f,
            "only one of `origin_is_unix_epoch` and `origin` can be set",
        )

    def test_cycles_to_ns_from_orig(self, run_in_comp_init):
        def f(comp_self):
            return comp_self._create_clock_class(
                frequency=10**8, origin_is_unix_epoch=True
            )

        assert run_in_comp_init(f).cycles_to_ns_from_origin(112) == 1120

    def test_cycles_to_ns_from_orig_overflow(self, run_in_comp_init):
        clk_cls = run_in_comp_init(
            lambda comp_self: comp_self._create_clock_class(frequency=1000)
        )

        with pytest.raises(bt2._OverflowError):
            clk_cls.cycles_to_ns_from_origin(2**63)

    def test_create_user_attrs(self, run_in_comp_init):
        clk_cls = run_in_comp_init(
            lambda comp_self: comp_self._create_clock_class(
                user_attributes={"salut": 23}
            )
        )

        assert clk_cls.user_attributes == {"salut": 23}
        assert type(clk_cls.user_attributes) is bt2_value.MapValue

    def test_create_invalid_user_attrs(self, raises_in_comp_init):
        raises_in_comp_init(
            TypeError,
            lambda comp_self: comp_self._create_clock_class(user_attributes=object()),
        )

    def test_create_invalid_user_attrs_value_type(self, raises_in_comp_init):
        raises_in_comp_init(
            TypeError,
            lambda comp_self: comp_self._create_clock_class(user_attributes=23),
        )


def test_create_def_mip_0():
    clk_cls = utils.run_in_component_init(
        0, lambda comp_self: comp_self._create_clock_class()
    )

    assert clk_cls.precision == 0
    assert clk_cls.uuid is None


def test_create_namespace_mip_0():
    _raises_in_comp_init(
        0,
        ValueError,
        lambda comp_self: comp_self._create_clock_class(namespace="the_clock"),
        "Clock class namespace is only available with MIP version ≥ 1 (currently 0)",
    )


def test_create_uid_mip_0():
    _raises_in_comp_init(
        0,
        ValueError,
        lambda comp_self: comp_self._create_clock_class(uid="the_clock"),
        "Clock class UID is only available with MIP version ≥ 1 (currently 0)",
    )


def test_create_accuracy_mip_0():
    _raises_in_comp_init(
        0,
        ValueError,
        lambda comp_self: comp_self._create_clock_class(accuracy=12),
        "Clock class accuracy is only available with MIP version ≥ 1 (currently 0)",
    )


def test_create_custom_orig_mip_0():
    _raises_in_comp_init(
        0,
        ValueError,
        lambda comp_self: comp_self._create_clock_class(
            origin=bt2.ClockOrigin("ns", "name", "uid")
        ),
        "Custom clock class origin is only available with MIP version ≥ 1 (currently 0)",
    )


def test_create_uuid_mip_0():
    clk_cls = utils.run_in_component_init(
        0,
        lambda comp_self: comp_self._create_clock_class(
            uuid=uuid.UUID("b43372c32ef0be28444dfc1c5cdafd33")
        ),
    )

    assert clk_cls.uuid == uuid.UUID("b43372c32ef0be28444dfc1c5cdafd33")


def test_create_invalid_uuid_mip_0():
    _raises_in_comp_init(
        0, TypeError, lambda comp_self: comp_self._create_clock_class(uuid=23)
    )


def test_create_def_mip_1():
    clk_cls = utils.run_in_component_init(
        1, lambda comp_self: comp_self._create_clock_class()
    )

    assert clk_cls.precision is None
    assert clk_cls.accuracy is None
    assert clk_cls.namespace is None
    assert clk_cls.name is None
    assert clk_cls.uid is None


def test_create_namespace_mip_1():
    clk_cls = utils.run_in_component_init(
        1, lambda comp_self: comp_self._create_clock_class(namespace="the_clock")
    )

    assert clk_cls.namespace == "the_clock"


def test_create_invalid_namespace_mip_1():
    _raises_in_comp_init(
        1,
        TypeError,
        lambda comp_self: comp_self._create_clock_class(namespace=23),
        "'int' is not a 'str' object",
    )


def test_create_uid_mip_1():
    clk_cls = utils.run_in_component_init(
        1, lambda comp_self: comp_self._create_clock_class(uid="the_clock")
    )

    assert clk_cls.uid == "the_clock"


def test_create_invalid_uid_mip_1():
    _raises_in_comp_init(
        1,
        TypeError,
        lambda comp_self: comp_self._create_clock_class(uid=23),
        "'int' is not a 'str' object",
    )


def test_create_accuracy_mip_1():
    clk_cls = utils.run_in_component_init(
        1, lambda comp_self: comp_self._create_clock_class(accuracy=12)
    )

    assert clk_cls.accuracy == 12


def test_create_custom_orig_mip_1():
    clk_cls = utils.run_in_component_init(
        1,
        lambda comp_self: comp_self._create_clock_class(
            origin=bt2.ClockOrigin("ns", "name", "uid")
        ),
    )

    orig = clk_cls.origin
    assert type(orig) is bt2.ClockOrigin
    assert orig.namespace == "ns"
    assert orig.name == "name"
    assert orig.uid == "uid"


def test_create_uuid_mip_1():
    _raises_in_comp_init(
        1,
        ValueError,
        lambda comp_self: comp_self._create_clock_class(
            uuid=uuid.UUID("b43372c32ef0be28444dfc1c5cdafd33")
        ),
        "Clock class UUID is only available with MIP version 0 (currently 1)",
    )


def test_const_user_attrs(const_ev_msg):
    clk_cls = const_ev_msg.default_clock_snapshot.clock_class
    assert clk_cls.user_attributes == {"a-clock-class-attribute": 1}
    assert type(clk_cls.user_attributes) is bt2._MapValueConst
