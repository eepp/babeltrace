# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019-2026 EfficiOS Inc.

import bt2
import utils
import pytest


# Returns a const signed integer range set containing `int_ranges`
# (list of (lower, upper) tuples).
def _const_sint_range(int_ranges):
    def range_setter(field):
        field.value = 12

    tc = utils.get_default_trace_class()

    return (
        utils.create_const_field(
            tc,
            tc.create_signed_enumeration_field_class(
                32,
                mappings=(("something", bt2.SignedIntegerRangeSet(int_ranges)),),
            ),
            range_setter,
        )
        .cls["something"]
        .ranges
    )


# Returns a const unsigned integer range set containing `int_ranges`
# (list of (lower, upper) tuples).
def _const_uint_range(int_ranges):
    def range_setter(field):
        field.value = 12

    tc = utils.get_default_trace_class()

    return (
        utils.create_const_field(
            tc,
            tc.create_unsigned_enumeration_field_class(
                32,
                mappings=(("something", bt2.UnsignedIntegerRangeSet(int_ranges)),),
            ),
            range_setter,
        )
        .cls["something"]
        .ranges
    )


class _IntRangeInfo:
    def __init__(
        self,
        range_cls,
        range_const_cls,
        range_set_cls,
        range_set_const_cls,
        get_const_range_set,
        def_lower,
        def_upper,
        oob_lower,
        oob_upper,
        range_1_vals,
        range_2_vals,
        range_3_vals,
        range_same_vals,
    ):
        self.range_cls = range_cls
        self.range_const_cls = range_const_cls
        self.range_set_cls = range_set_cls
        self.range_set_const_cls = range_set_const_cls
        self.get_const_range_set = get_const_range_set
        self.def_lower = def_lower
        self.def_upper = def_upper
        self.oob_lower = oob_lower
        self.oob_upper = oob_upper
        self.range_1_vals = range_1_vals
        self.range_2_vals = range_2_vals
        self.range_3_vals = range_3_vals
        self.range_same_vals = range_same_vals

    @property
    def range_1(self):
        return self.range_cls(*self.range_1_vals)

    @property
    def range_2(self):
        return self.range_cls(*self.range_2_vals)

    @property
    def range_3(self):
        return self.range_cls(*self.range_3_vals)

    @property
    def rs(self):
        return self.range_set_cls((self.range_1, self.range_2, self.range_3))


_PARAMS = [
    pytest.param(
        _IntRangeInfo(
            range_cls=bt2.UnsignedIntegerRange,
            range_const_cls=bt2._UnsignedIntegerRangeConst,
            range_set_cls=bt2.UnsignedIntegerRangeSet,
            range_set_const_cls=bt2._UnsignedIntegerRangeSetConst,
            get_const_range_set=_const_uint_range,
            def_lower=23,
            def_upper=18293,
            oob_lower=-1,
            oob_upper=1 << 64,
            range_1_vals=(4, 192),
            range_2_vals=(17, 228),
            range_3_vals=(1000, 2000),
            range_same_vals=(1300, 1300),
        ),
        id="unsigned",
    ),
    pytest.param(
        _IntRangeInfo(
            range_cls=bt2.SignedIntegerRange,
            range_const_cls=bt2._SignedIntegerRangeConst,
            range_set_cls=bt2.SignedIntegerRangeSet,
            range_set_const_cls=bt2._SignedIntegerRangeSetConst,
            get_const_range_set=_const_sint_range,
            def_lower=-184,
            def_upper=11547,
            oob_lower=-(1 << 63) - 1,
            oob_upper=1 << 63,
            range_1_vals=(-1484, -17),
            range_2_vals=(-101, 1500),
            range_3_vals=(1948, 2019),
            range_same_vals=(-1300, -1300),
        ),
        id="signed",
    ),
]


@pytest.mark.parametrize("info", _PARAMS)
class TestIntRange:
    def test_create(self, info):
        rg = info.range_cls(info.def_lower, info.def_upper)
        assert rg.lower == info.def_lower
        assert rg.upper == info.def_upper
        assert type(rg) is info.range_cls

    def test_const_create(self, info):
        const_rg = list(info.get_const_range_set([(info.def_lower, info.def_upper)]))[0]
        assert const_rg.lower == info.def_lower
        assert const_rg.upper == info.def_upper
        assert type(const_rg) is info.range_const_cls

    def test_create_same(self, info):
        rg = info.range_cls(info.def_lower, info.def_lower)
        assert rg.lower == info.def_lower
        assert rg.upper == info.def_lower

    def test_create_single(self, info):
        rg = info.range_cls(info.def_lower)
        assert rg.lower == info.def_lower
        assert rg.upper == info.def_lower

    def test_create_wrong_type_lower(self, info):
        with pytest.raises(TypeError):
            info.range_cls(19.3, info.def_upper)

    def test_create_wrong_type_upper(self, info):
        with pytest.raises(TypeError):
            info.range_cls(info.def_lower, 19.3)

    def test_create_out_of_bound_lower(self, info):
        with pytest.raises(ValueError):
            info.range_cls(info.oob_lower, info.def_upper)

    def test_create_out_of_bound_upper(self, info):
        with pytest.raises(ValueError):
            info.range_cls(info.def_lower, info.oob_upper)

    def test_create_lower_gt_upper(self, info):
        with pytest.raises(ValueError):
            info.range_cls(info.def_lower, info.def_lower - 1)

    def test_contains_lower(self, info):
        assert info.range_cls(info.def_lower, info.def_upper).contains(info.def_lower)

    def test_contains_upper(self, info):
        assert info.range_cls(info.def_lower, info.def_upper).contains(info.def_upper)

    def test_contains_avg(self, info):
        assert info.range_cls(info.def_lower, info.def_upper).contains(
            (info.def_lower + info.def_upper) // 2
        )

    def test_contains_wrong_type(self, info):
        rg = info.range_cls(info.def_lower, info.def_upper)

        with pytest.raises(TypeError):
            rg.contains("allo")

    def test_contains_out_of_bound(self, info):
        rg = info.range_cls(info.def_lower, info.def_upper)

        with pytest.raises(ValueError):
            rg.contains(info.oob_upper)

    def test_eq(self, info):
        rg1 = info.range_cls(info.def_lower, info.def_upper)
        rg2 = info.range_cls(info.def_lower, info.def_upper)
        assert rg1 == rg2

    def test_const_eq(self, info):
        const_rg1 = list(info.get_const_range_set([(info.def_lower, info.def_upper)]))[
            0
        ]
        const_rg2 = list(info.get_const_range_set([(info.def_lower, info.def_upper)]))[
            0
        ]
        assert const_rg1 == const_rg2

    def test_const_nonconst_eq(self, info):
        rg = info.range_cls(info.def_lower, info.def_upper)
        const_rg = list(info.get_const_range_set([(info.def_lower, info.def_upper)]))[0]
        assert rg == const_rg

    def test_ne(self, info):
        rg1 = info.range_cls(info.def_lower, info.def_upper)
        rg2 = info.range_cls(info.def_lower, info.def_upper - 1)
        assert rg1 != rg2

    def test_const_ne(self, info):
        const_rg1 = list(info.get_const_range_set([(info.def_lower, info.def_upper)]))[
            0
        ]
        const_rg2 = list(
            info.get_const_range_set([(info.def_lower, info.def_upper - 1)])
        )[0]
        assert const_rg1 != const_rg2

    def test_ne_other_type(self, info):
        assert info.range_cls(info.def_lower, info.def_upper) != 48


@pytest.mark.parametrize("info", _PARAMS)
class TestIntRangeSet:
    def test_create(self, info):
        rs = info.rs
        assert len(rs) == 3
        assert info.range_1 in rs
        assert info.range_2 in rs
        assert info.range_3 in rs
        assert type(info.range_1) is info.range_cls

    def test_const_create(self, info):
        const_rs = info.get_const_range_set(
            [info.range_1_vals, info.range_2_vals, info.range_3_vals]
        )
        assert len(const_rs) == 3
        assert info.range_1 in const_rs
        assert info.range_2 in const_rs
        assert info.range_3 in const_rs
        assert type(info.range_1) is info.range_cls

    def test_create_tuples(self, info):
        rs = info.range_set_cls(
            (info.range_1_vals, info.range_2_vals, info.range_3_vals)
        )
        assert len(rs) == 3
        assert info.range_1 in rs
        assert info.range_2 in rs
        assert info.range_3 in rs

    def test_create_single(self, info):
        rs = info.range_set_cls((info.range_same_vals[0],))
        assert len(rs) == 1
        assert info.range_cls(*info.range_same_vals) in rs

    def test_create_non_iter(self, info):
        with pytest.raises(TypeError):
            info.range_set_cls(23)

    def test_create_wrong_elem_type(self, info):
        with pytest.raises(TypeError):
            info.range_set_cls((info.range_1, info.range_2, "lel"))

    def test_len(self, info):
        assert len(info.rs) == 3

    def test_contains(self, info):
        rs = info.range_set_cls((info.range_1, info.range_2))
        assert info.range_1 in rs
        assert info.range_2 in rs
        assert info.range_3 not in rs

    def test_contains_value(self, info):
        rs = info.range_set_cls((info.range_1, info.range_2))
        assert rs.contains_value(info.range_1.upper)
        assert rs.contains_value(info.range_2.lower)
        assert not rs.contains_value(info.range_3.upper)

    def test_contains_value_wrong_type(self, info):
        with pytest.raises(TypeError):
            info.rs.contains_value("meow")

    def test_iter(self, info):
        range_list = list(info.rs)
        assert info.range_1 in range_list
        assert info.range_2 in range_list
        assert info.range_3 in range_list

        for rg in range_list:
            assert type(rg) is info.range_cls

    def test_const_iter(self, info):
        const_rs = info.get_const_range_set(
            [info.range_1_vals, info.range_2_vals, info.range_3_vals]
        )
        range_list = list(const_rs)
        assert info.range_1 in range_list
        assert info.range_2 in range_list
        assert info.range_3 in range_list

        for rg in range_list:
            assert type(rg) is info.range_const_cls

    def test_empty(self, info):
        rs = info.range_set_cls()
        assert len(rs) == 0
        assert len(list(rs)) == 0

    def test_add_range_obj(self, info):
        rs = info.range_set_cls((info.range_1,))
        assert len(rs) == 1
        rs.add(info.range_2)
        assert len(rs) == 2
        assert info.range_2 in rs

    def test_const_add_range_obj(self, info):
        const_rs = info.get_const_range_set(
            [info.range_1_vals, info.range_2_vals, info.range_3_vals]
        )
        with pytest.raises(AttributeError):
            const_rs.add((12, 4434))

    def test_discard_not_implemented(self, info):
        with pytest.raises(NotImplementedError):
            info.rs.discard(info.range_2)

    def test_eq_same_order(self, info):
        assert info.rs == info.rs

    def test_eq_diff_order(self, info):
        assert info.rs == info.range_set_cls((info.range_1, info.range_3, info.range_2))

    def test_eq_same_addr(self, info):
        assert info.rs == info.rs

    def test_ne_diff_len(self, info):
        rs1 = info.rs
        rs2 = info.range_set_cls((info.range_1, info.range_2))
        assert rs1 != rs2

    def test_ne_diff_values(self, info):
        rs1 = info.range_set_cls((info.range_1, info.range_2))
        rs2 = info.range_set_cls((info.range_1, info.range_3))
        assert rs1 != rs2

    def test_ne_incompatible_type(self, info):
        assert info.rs != object()
