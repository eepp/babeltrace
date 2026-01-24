# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019-2026 EfficiOS Inc.

import copy
import math
import operator
import functools
import itertools
import collections

import bt2
import utils
import pytest


# Creates and returns a stream with the structure field class members
# `members` part of its packet context field class.
#
# The stream is part of a dummy trace created from trace class `tc`.
def _create_stream(tc, members):
    return tc().create_stream(
        tc.create_stream_class(
            packet_context_field_class=tc.create_structure_field_class(members=members),
            supports_packets=True,
        )
    )


# Creates a field of the field class `fc`.
#
# The field is part of a dummy stream, itself part of a dummy trace
# created from trace class `tc`.
def _create_field(tc, fc):
    field_name = "field"

    return (
        _create_stream(tc, [(field_name, fc)]).create_packet().context_field[field_name]
    )


# Binary operators for numeric field tests.
_BIN_OPS = [
    pytest.param(operator.lt, id="lt"),
    pytest.param(operator.le, id="le"),
    pytest.param(operator.eq, id="eq"),
    pytest.param(operator.ne, id="ne"),
    pytest.param(operator.ge, id="ge"),
    pytest.param(operator.gt, id="gt"),
    pytest.param(operator.add, id="add"),
    pytest.param(lambda a, b: operator.add(b, a), id="radd"),
    pytest.param(operator.and_, id="and"),
    pytest.param(lambda a, b: operator.and_(b, a), id="rand"),
    pytest.param(operator.floordiv, id="floordiv"),
    pytest.param(lambda a, b: operator.floordiv(b, a), id="rfloordiv"),
    pytest.param(operator.lshift, id="lshift"),
    pytest.param(lambda a, b: operator.lshift(b, a), id="rlshift"),
    pytest.param(operator.mod, id="mod"),
    pytest.param(lambda a, b: operator.mod(b, a), id="rmod"),
    pytest.param(operator.mul, id="mul"),
    pytest.param(lambda a, b: operator.mul(b, a), id="rmul"),
    pytest.param(operator.or_, id="or"),
    pytest.param(lambda a, b: operator.or_(b, a), id="ror"),
    pytest.param(operator.pow, id="pow"),
    pytest.param(lambda a, b: operator.pow(b, a), id="rpow"),
    pytest.param(operator.rshift, id="rshift"),
    pytest.param(lambda a, b: operator.rshift(b, a), id="rrshift"),
    pytest.param(operator.sub, id="sub"),
    pytest.param(lambda a, b: operator.sub(b, a), id="rsub"),
    pytest.param(operator.truediv, id="truediv"),
    pytest.param(lambda a, b: operator.truediv(b, a), id="rtruediv"),
    pytest.param(operator.xor, id="xor"),
    pytest.param(lambda a, b: operator.xor(b, a), id="rxor"),
]


# Unary operators for numeric field tests.
_UNARY_OPS = [
    pytest.param(operator.neg, id="neg"),
    pytest.param(operator.pos, id="pos"),
    pytest.param(operator.abs, id="abs"),
    pytest.param(operator.invert, id="invert"),
    pytest.param(round, id="round"),
    pytest.param(functools.partial(round, ndigits=0), id="round-0"),
    pytest.param(functools.partial(round, ndigits=1), id="round-1"),
    pytest.param(functools.partial(round, ndigits=2), id="round-2"),
    pytest.param(functools.partial(round, ndigits=3), id="round-3"),
    pytest.param(math.ceil, id="ceil"),
    pytest.param(math.floor, id="floor"),
    pytest.param(math.trunc, id="trunc"),
]


# Right-hand side operands for binary operator tests.
_RHS_OPERANDS = [
    pytest.param(False, id="false"),
    pytest.param(True, id="true"),
    pytest.param(2, id="pos-int"),
    pytest.param(-23, id="neg-int"),
    pytest.param(0, id="zero-int"),
    pytest.param(bt2.create_value(2), id="pos-int-val"),
    pytest.param(bt2.create_value(-23), id="neg-int-val"),
    pytest.param(bt2.create_value(0), id="zero-int-val"),
    pytest.param(2.2, id="pos-real"),
    pytest.param(-23.4, id="neg-real"),
    pytest.param(0.0, id="zero-real"),
    pytest.param(bt2.create_value(2.2), id="pos-real-val"),
    pytest.param(bt2.create_value(-23.4), id="neg-real-val"),
    pytest.param(bt2.create_value(0.0), id="zero-real-val"),
    pytest.param(-23 + 19j, id="complex"),
    pytest.param(0j, id="zero-complex"),
]


class TestBitArray:
    @pytest.fixture
    def field(self, def_tc):
        f = _create_field(def_tc, def_tc.create_bit_array_field_class(24))
        f.value_as_integer = 15497
        return f

    @pytest.fixture(scope="class")
    def raw_val(self):
        return 15497

    def test_assign_invalid_type(self, field):
        with pytest.raises(TypeError):
            field.value_as_integer = "onze"

    def test_assign(self, field):
        field.value_as_integer = 199
        assert field.value_as_integer == 199

    def test_assign_masked(self, field):
        field.value_as_integer = 0xE1549BB
        assert field.value_as_integer == 0xE1549BB & ((1 << 24) - 1)

    def test_eq(self, def_tc, raw_val):
        field1 = _create_field(def_tc, def_tc.create_bit_array_field_class(24))
        field1.value_as_integer = raw_val
        field2 = _create_field(def_tc, def_tc.create_bit_array_field_class(24))
        field2.value_as_integer = raw_val
        assert field1 == field2

    def test_ne_same_type(self, def_tc, field, raw_val):
        other = _create_field(def_tc, def_tc.create_bit_array_field_class(24))
        other.value_as_integer = raw_val - 1
        assert field != other

    def test_ne_diff_type(self, field, raw_val):
        assert field != raw_val

    def test_len(self, field):
        assert len(field) == 24

    def test_str(self, field, raw_val):
        assert str(field) == str(raw_val)

    def test_repr(self, field, raw_val):
        assert repr(field) == repr(raw_val)


# Base class for numeric field test cases.
#
# Subclass must define:
#
# field() fixture:
#     Returns a field object with an arbitrary value.
#
# raw_val() fixture:
#     Returns the equivalent raw value of field().
#
# const_field() fixture:
#     Returns a const field object with an arbitrary value.
class _TestNumeric:
    # Tries the binary operation `op(field, rhs)` and `op(raw_val,
    # rhs)`, returning both results.
    #
    # If either operation raises an exception, asserts that both raised
    # the same exception type and returns a (`None`, `None`) tuple.
    @staticmethod
    def _bin_op(field, raw_val, op, rhs):
        field_exc_type = None
        raw_val_exc_type = None

        try:
            field_res = op(field, rhs)
        except Exception as e:
            field_exc_type = type(e)

        try:
            raw_val_res = op(raw_val, rhs)
        except Exception as e:
            raw_val_exc_type = type(e)

        if field_exc_type is not None or raw_val_exc_type is not None:
            assert field_exc_type is raw_val_exc_type
            return None, None

        return field_res, raw_val_res

    # Tries the unary operation `op(field)` and `op(raw_val)`, returning
    # both results.
    @staticmethod
    def _unary_op(field, raw_val, op):
        if (
            isinstance(field, bt2._BoolFieldConst) or isinstance(raw_val, bool)
        ) and op is operator.invert:
            pytest.skip("Invalid bitwise inversion on `bool`")

        field_exc_type = None
        raw_val_exc_type = None

        try:
            field_res = op(field)
        except Exception as e:
            field_exc_type = type(e)

        try:
            raw_val_res = op(raw_val)
        except Exception as e:
            raw_val_exc_type = type(e)

        if field_exc_type is not None or raw_val_exc_type is not None:
            assert field_exc_type is raw_val_exc_type
            return None, None

        return field_res, raw_val_res

    @pytest.mark.parametrize("op", [bool, int, float, complex])
    def test_type_op(self, field, raw_val, op):
        assert op(field) == op(raw_val)

    def test_type_str(self, field, raw_val):
        assert str(field) == str(raw_val)

    def test_hash_op(self, field):
        with pytest.raises(TypeError):
            hash(field)

    def test_const_hash_op(self, const_field, raw_val):
        assert hash(const_field) == hash(raw_val)

    def test_const_hash_dict(self, const_field, raw_val):
        my_dict = {}
        my_dict[const_field] = "my_val"
        assert my_dict[raw_val] == "my_val"

    def test_eq_none(self, field):
        # Disable the "comparison to None" warning, as this is precisely
        # what we want to test here!
        assert not (field == None)  # noqa: E711

    def test_ne_none(self, field):
        # Disable the "comparison to None" warning, as this is precisely
        # what we want to test here!
        assert field != None  # noqa: E711

    # Tests that `==` returns `False`, `!=` returns `True`, and other
    # binary operators raise `TypeError` when the right-hand side
    # operand is an unknown type.
    @pytest.mark.parametrize("op", _BIN_OPS)
    def test_bin_op_unknown(self, field, op):
        if op is operator.eq:
            assert op(field, object()) is False
        elif op is operator.ne:
            assert op(field, object()) is True
        else:
            with pytest.raises(TypeError):
                op(field, object())

    # Tests that `==` returns `False`, `!=` returns `True`, and other
    # binary operators raise `TypeError` when the right-hand side
    # operand is `None`.
    @pytest.mark.parametrize("op", _BIN_OPS)
    def test_bin_op_none(self, field, op):
        if op is operator.eq:
            assert op(field, None) is False
        elif op is operator.ne:
            assert op(field, None) is True
        else:
            with pytest.raises(TypeError):
                op(field, None)

    # Tests that binary operators return the same type as the equivalent
    # operation on raw values (comparisons return `bool`).
    @pytest.mark.parametrize("op", _BIN_OPS)
    @pytest.mark.parametrize("rhs", _RHS_OPERANDS)
    def test_bin_op_type(self, field, raw_val, op, rhs):
        field_res, raw_val_res = self._bin_op(field, raw_val, op, rhs)

        if field_res is not None:
            if op in (operator.eq, operator.ne):
                assert isinstance(field_res, bool)
            else:
                assert isinstance(field_res, type(raw_val_res))

    # Tests that binary operators return the same value as the
    # equivalent operation on raw values.
    @pytest.mark.parametrize("op", _BIN_OPS)
    @pytest.mark.parametrize("rhs", _RHS_OPERANDS)
    def test_bin_op_val(self, field, raw_val, op, rhs):
        field_res, raw_val_res = self._bin_op(field, raw_val, op, rhs)

        if field_res is not None:
            assert field_res == raw_val_res

    # Tests that binary operators don't change the address of the
    # left-hand side field object.
    @pytest.mark.parametrize("op", _BIN_OPS)
    @pytest.mark.parametrize("rhs", _RHS_OPERANDS)
    def test_bin_op_lhs_addr_same(self, field, raw_val, op, rhs):
        addr_before = field.addr
        self._bin_op(field, raw_val, op, rhs)
        assert field.addr == addr_before

    # Tests that binary operators don't modify the left-hand side
    # field object.
    @pytest.mark.parametrize("op", _BIN_OPS)
    @pytest.mark.parametrize("rhs", _RHS_OPERANDS)
    def test_bin_op_lhs_val_same(self, field, raw_val, op, rhs):
        val_before = copy.copy(raw_val)
        self._bin_op(field, raw_val, op, rhs)
        assert field == val_before

    # Tests that unary operators return the same type as the equivalent
    # operation on raw values.
    @pytest.mark.parametrize("op", _UNARY_OPS)
    def test_unary_op_type(self, field, raw_val, op):
        field_res, raw_val_res = self._unary_op(field, raw_val, op)

        if field_res is not None:
            assert isinstance(field_res, type(raw_val_res))

    # Tests that unary operators return the same value as the equivalent
    # operation on raw values.
    @pytest.mark.parametrize("op", _UNARY_OPS)
    def test_unary_op_val(self, field, raw_val, op):
        field_res, raw_val_res = self._unary_op(field, raw_val, op)

        if field_res is not None:
            assert field_res == raw_val_res

    # Tests that unary operators don't change the address of the operand
    # field object.
    @pytest.mark.parametrize("op", _UNARY_OPS)
    def test_unary_op_addr_same(self, field, raw_val, op):
        addr_before = field.addr
        self._unary_op(field, raw_val, op)
        assert field.addr == addr_before

    # Tests that unary operators don't modify the operand field object.
    @pytest.mark.parametrize("op", _UNARY_OPS)
    def test_unary_op_val_same(self, field, raw_val, op):
        val_before = copy.copy(raw_val)
        self._unary_op(field, raw_val, op)
        assert field == val_before


class TestBool(_TestNumeric):
    @pytest.fixture
    def fc(self, def_tc):
        return def_tc.create_bool_field_class()

    @pytest.fixture
    def field(self, def_tc, fc):
        f = _create_field(def_tc, fc)
        f.value = True
        return f

    @pytest.fixture(scope="class")
    def raw_val(self):
        return True

    @pytest.fixture
    def const_field(self, def_tc):
        def value_setter(f):
            f.value = True

        return utils.create_const_field(
            def_tc, def_tc.create_bool_field_class(), value_setter
        )

    def test_classes(self, field, const_field):
        assert type(field) is bt2._BoolField
        assert type(const_field) is bt2._BoolFieldConst

    @pytest.mark.parametrize("raw_val", [True, False])
    def test_assign_bool(self, field, raw_val):
        field.value = raw_val
        assert field == raw_val  # noqa: E712

    @pytest.mark.parametrize("raw_val", [True, False])
    def test_assign_bool_field(self, def_tc, raw_val):
        field1 = _create_field(def_tc, def_tc.create_bool_field_class())
        field1.value = raw_val
        field2 = _create_field(def_tc, def_tc.create_bool_field_class())
        field2.value = field1
        assert field2 == raw_val  # noqa: E712

    def test_assign_invalid_type(self, field):
        with pytest.raises(TypeError):
            field.value = 17


# Base class for integer field test cases.
#
# Subclass must satisfy the requirements of `_TestNumeric` and define
# the fc() fixture which returns the field class to use.
#
# Provides:
#
# • raw_val() fixture.
# • field() fixture.
# • const_field() fixture.
# • Common numeric field tests.
class _TestInt(_TestNumeric):
    @pytest.fixture(scope="class")
    def raw_val(self):
        return 17

    @pytest.fixture
    def field(self, def_tc, fc, raw_val):
        f = _create_field(def_tc, fc)
        f.value = raw_val
        return f

    @pytest.fixture
    def const_field(self, def_tc, fc, raw_val):
        def value_setter(f):
            f.value = raw_val

        return utils.create_const_field(def_tc, fc, value_setter)

    @pytest.mark.parametrize("raw_val", [True, False])
    def test_assign_bool(self, field, raw_val):
        field.value = raw_val
        assert field == raw_val  # noqa: E712

    def test_assign_int(self, field):
        field.value = 477
        assert field == 477

    def test_assign_int_field(self, def_tc, field):
        other = _create_field(def_tc, def_tc.create_signed_integer_field_class(25))
        other.value = 999
        field.value = other
        assert field == 999

    def test_assign_invalid_type(self, field):
        with pytest.raises(TypeError):
            field.value = "yes"

    def test_assign_uint(self, def_tc):
        uint_fc = def_tc.create_unsigned_integer_field_class(32)
        field = _create_field(def_tc, uint_fc)
        field.value = 1777
        assert field == 1777

    def test_assign_big_uint(self, def_tc):
        field = _create_field(def_tc, def_tc.create_unsigned_integer_field_class(64))

        # Larger than the IEEE 754 double-precision exact representation
        # of integers.
        raw_val = (2**53) + 1
        field.value = raw_val
        assert field == raw_val

    def test_assign_uint_out_of_range(self, def_tc):
        uint_fc = def_tc.create_unsigned_integer_field_class(8)
        field = _create_field(def_tc, uint_fc)

        with pytest.raises(ValueError, match=r"Value 256 is outside valid range"):
            field.value = 256

        with pytest.raises(ValueError, match=r"Value -1 is outside valid range"):
            field.value = -1

    def test_assign_int_out_of_range(self, def_tc):
        int_fc = def_tc.create_signed_integer_field_class(8)
        field = _create_field(def_tc, int_fc)

        with pytest.raises(ValueError, match=r"Value 128 is outside valid range"):
            field.value = 128

        with pytest.raises(ValueError, match=r"Value -129 is outside valid range"):
            field.value = -129


class TestSInt(_TestInt):
    @pytest.fixture
    def fc(self, def_tc):
        return def_tc.create_signed_integer_field_class(25)

    def test_assign_neg_int(self, field):
        field.value = -13
        assert field == -13


class TestUInt(_TestInt):
    @pytest.fixture
    def fc(self, def_tc):
        return def_tc.create_unsigned_integer_field_class(25)


class TestSignedEnum(TestSInt):
    @pytest.fixture
    def fc(self, def_tc):
        return def_tc.create_signed_enumeration_field_class(
            32,
            mappings=(
                ("something", bt2.SignedIntegerRangeSet([(17, 17)])),
                ("speaker", bt2.SignedIntegerRangeSet([(12, 16)])),
                ("can", bt2.SignedIntegerRangeSet([(18, 2540)])),
                (
                    "whole range",
                    bt2.SignedIntegerRangeSet([(-(2**31), (2**31) - 1)]),
                ),
                ("zip", bt2.SignedIntegerRangeSet([(-45, 1001)])),
            ),
        )

    def test_type_str(self, field, raw_val):
        expected_str_found = False

        # Establish all permutations of the three expected matches since
        # the order in which mappings are enumerated is not explicitly
        # part of the API.
        for p in itertools.permutations(["whole range", "something", "zip"]):
            candidate = "{} ({})".format(raw_val, ", ".join(p))

            if candidate == str(field):
                expected_str_found = True
                break

        assert expected_str_found

    def test_labels(self, def_tc, fc):
        field = _create_field(def_tc, fc)
        field.value = 17
        assert sorted(field.labels) == ["something", "whole range", "zip"]

    def test_assign_neg_int(self, field):
        field.value = -13
        assert field == -13


class TestUnsignedEnum(TestUInt):
    @pytest.fixture
    def fc(self, def_tc):
        return def_tc.create_unsigned_enumeration_field_class(
            32,
            mappings=(
                ("something", bt2.UnsignedIntegerRangeSet([(17, 17)])),
                ("speaker", bt2.UnsignedIntegerRangeSet([(12, 16)])),
                ("can", bt2.UnsignedIntegerRangeSet([(18, 2540)])),
                ("whole range", bt2.UnsignedIntegerRangeSet([(0, (2**32) - 1)])),
                ("zip", bt2.UnsignedIntegerRangeSet([(0, 1001)])),
            ),
        )

    def test_type_str(self, field, raw_val):
        expected_str_found = False

        # Establish all permutations of the three expected matches since
        # the order in which mappings are enumerated is not explicitly
        # part of the API.
        for p in itertools.permutations(["whole range", "something", "zip"]):
            candidate = "{} ({})".format(raw_val, ", ".join(p))

            if candidate == str(field):
                expected_str_found = True
                break

        assert expected_str_found

    def test_labels(self, def_tc, fc):
        field = _create_field(def_tc, fc)
        field.value = 17
        assert sorted(field.labels) == ["something", "whole range", "zip"]


# Base class for real field test cases.
#
# Subclass must satisfy the requirements of `_TestNumeric` and define:
#
# fc() fixture:
#     Returns the field class to use.
#
# Provides:
#
# • raw_val() fixture.
# • field() fixture.
# • const_field() fixture.
# • Common real field tests.
class _TestReal(_TestNumeric):
    @pytest.fixture
    def raw_val(self):
        return 52.0

    @pytest.fixture
    def field(self, def_tc, fc, raw_val):
        f = _create_field(def_tc, fc)
        f.value = raw_val
        return f

    @pytest.fixture
    def const_field(self, def_tc, fc, raw_val):
        def value_setter(f):
            f.value = raw_val

        return utils.create_const_field(def_tc, fc, value_setter)

    @pytest.mark.parametrize(
        "raw_val",
        [True, False],
    )
    def test_assign_bool(self, field, raw_val):
        field.value = raw_val
        assert bool(field) == raw_val

    @pytest.mark.parametrize(
        ["raw_val", "expected"],
        [
            pytest.param(477, float(477), id="pos"),
            pytest.param(-13, float(-13), id="neg"),
        ],
    )
    def test_assign_int(self, field, raw_val, expected):
        field.value = raw_val
        assert field == expected

    def test_assign_int_field(self, def_tc, field):
        int_field = _create_field(def_tc, def_tc.create_signed_integer_field_class(32))
        int_field.value = 999
        field.value = int_field
        assert field == float(999)

    def test_assign_invalid_type(self, field):
        with pytest.raises(TypeError):
            field.value = "yes"

    @pytest.mark.parametrize(
        "op",
        [
            pytest.param(operator.lshift, id="lshift"),
            pytest.param(operator.rshift, id="rshift"),
            pytest.param(operator.and_, id="and"),
            pytest.param(operator.or_, id="or"),
            pytest.param(operator.xor, id="xor"),
        ],
    )
    def test_invalid_bitwise_bin_op(self, field, op):
        with pytest.raises(TypeError):
            op(field, 23)

    def test_invalid_invert(self, field):
        with pytest.raises(TypeError):
            ~field


class TestRealSingle(_TestReal):
    @pytest.fixture
    def fc(self, def_tc):
        return def_tc.create_single_precision_real_field_class()

    def test_assign_real(self, field):
        raw_val = -19.23
        field.value = raw_val

        # It's expected to have some loss of precision because of the
        # field that is in single precision.
        assert round(field, 5) == raw_val

    def test_assign_real_field(self, def_tc, field):
        other_field = _create_field(
            def_tc, def_tc.create_single_precision_real_field_class()
        )
        raw_val = 101.32
        other_field.value = raw_val
        field.value = other_field

        # It's expected to have some loss of precision because of the
        # field that is in single precision.
        assert round(field, 5) == raw_val

    def test_str_op(self, field, raw_val):
        assert str(round(field, 5)) == str(raw_val)


class TestRealDouble(_TestReal):
    @pytest.fixture
    def fc(self, def_tc):
        return def_tc.create_double_precision_real_field_class()

    def test_assign_real(self, field):
        raw_val = -19.23
        field.value = raw_val
        assert field == raw_val

    def test_assign_real_field(self, def_tc, field):
        other_field = _create_field(
            def_tc, def_tc.create_double_precision_real_field_class()
        )
        raw_val = 101.32
        other_field.value = raw_val
        field.value = other_field
        assert field == raw_val


class TestStr:
    @staticmethod
    def _create_str_field(tc):
        field_name = "str_field"

        return (
            _create_stream(tc, [(field_name, tc.create_string_field_class())])
            .create_packet()
            .context_field[field_name]
        )

    @pytest.fixture
    def raw_val(self):
        return "Hello, World!"

    @pytest.fixture
    def field(self, def_tc, raw_val):
        f = self._create_str_field(def_tc)
        f.value = raw_val
        return f

    @pytest.fixture
    def const_field(self, def_tc, raw_val):
        def value_setter(f):
            f.value = raw_val

        return utils.create_const_field(
            def_tc, def_tc.create_string_field_class(), value_setter
        )

    def test_assign_int(self, field):
        with pytest.raises(TypeError):
            field.value = 283

    def test_assign_str_field(self, def_tc):
        field = self._create_str_field(def_tc)
        field.value = "zorg"
        assert field == "zorg"

    def test_eq(self, field, raw_val):
        assert field == raw_val

    def test_const_eq(self, const_field, raw_val):
        assert const_field == raw_val

    def test_not_eq(self, field):
        assert field != 23

    def test_lt_vstr(self, def_tc):
        s1 = self._create_str_field(def_tc)
        s1.value = "allo"
        s2 = self._create_str_field(def_tc)
        s2.value = "bateau"
        assert s1 < s2

    def test_lt_str(self, def_tc):
        s1 = self._create_str_field(def_tc)
        s1.value = "allo"
        assert s1 < "bateau"

    def test_le_vstr(self, def_tc):
        s1 = self._create_str_field(def_tc)
        s1.value = "allo"
        s2 = self._create_str_field(def_tc)
        s2.value = "bateau"
        assert s1 <= s2

    def test_le_str(self, def_tc):
        s1 = self._create_str_field(def_tc)
        s1.value = "allo"
        assert s1 <= "bateau"

    def test_gt_vstr(self, def_tc):
        s1 = self._create_str_field(def_tc)
        s1.value = "allo"
        s2 = self._create_str_field(def_tc)
        s2.value = "bateau"
        assert s2 > s1

    def test_gt_str(self, def_tc):
        s1 = self._create_str_field(def_tc)
        s1.value = "allo"
        assert "bateau" > s1

    def test_ge_vstr(self, def_tc):
        s1 = self._create_str_field(def_tc)
        s1.value = "allo"
        s2 = self._create_str_field(def_tc)
        s2.value = "bateau"
        assert s2 >= s1

    def test_ge_str(self, def_tc):
        s1 = self._create_str_field(def_tc)
        s1.value = "allo"
        assert "bateau" >= s1

    def test_bool_op(self, field, raw_val):
        assert bool(field) == bool(raw_val)

    def test_str_op(self, field, raw_val):
        assert str(field) == str(raw_val)

    def test_len(self, field, raw_val):
        assert len(field) == len(raw_val)

    def test_getitem(self, field, raw_val):
        assert field[5] == raw_val[5]

    def test_const_getitem(self, const_field, raw_val):
        assert const_field[5] == raw_val[5]

    def test_append_str(self, field, raw_val):
        to_append = "meow meow meow"
        field += to_append
        assert field == raw_val + to_append

    def test_const_append_str(self, const_field, raw_val):
        with pytest.raises(TypeError):
            const_field += "meow meow meow"

        assert const_field == raw_val

    def test_append_str_field(self, def_tc, field, raw_val):
        other = self._create_str_field(def_tc)
        to_append = "meow meow meow"
        other.value = to_append
        field += other
        assert field == raw_val + to_append

    def test_hash_op(self, field):
        with pytest.raises(TypeError):
            hash(field)

    def test_const_hash_op(self, const_field, raw_val):
        assert hash(const_field) == hash(raw_val)

    def test_const_hash_dict(self, const_field, raw_val):
        my_dict = {}
        my_dict[const_field] = "my_val"
        assert my_dict[raw_val] == "my_val"


# Base class for array field test cases.
#
# Subclass must define:
#
# field() fixture:
#     Returns an array field object.
#
# const_field() fixture:
#     Returns a const array field object.
#
# raw_val() fixture:
#     Returns a list matching the contents of field.
class _TestArrayField:
    @staticmethod
    def _create_int_array_field(tc, len):
        field_name = "int_array"

        return (
            _create_stream(
                tc,
                [
                    (
                        field_name,
                        tc.create_static_array_field_class(
                            tc.create_signed_integer_field_class(32), len
                        ),
                    )
                ],
            )
            .create_packet()
            .context_field[field_name]
        )

    @staticmethod
    def _create_struct_array_field(tc, len):
        field_name = "struct_array"

        return (
            _create_stream(
                tc,
                [
                    (
                        field_name,
                        tc.create_static_array_field_class(
                            tc.create_structure_field_class(), len
                        ),
                    )
                ],
            )
            .create_packet()
            .context_field[field_name]
        )

    def test_bool_op_true(self, field):
        assert field

    def test_len(self, field):
        assert len(field) == 3

    def test_length(self, field):
        assert field.length == 3

    def test_getitem(self, field):
        elem = field[1]
        assert type(elem) is bt2._SignedIntegerField
        assert elem == 1847

    def test_const_getitem(self, const_field):
        elem = const_field[1]
        assert type(elem) is bt2._SignedIntegerFieldConst
        assert elem == 1847

    def test_eq(self, def_tc, field):
        other = self._create_int_array_field(def_tc, 3)
        other[0] = 45
        other[1] = 1847
        other[2] = 1948754
        assert field == other

    def test_eq_invalid_type(self, field):
        assert field != 23

    def test_eq_diff_len(self, def_tc, field):
        other = self._create_int_array_field(def_tc, 2)
        other[0] = 45
        other[1] = 1847
        assert field != other

    def test_eq_diff_content_same_len(self, def_tc, field):
        other = self._create_int_array_field(def_tc, 3)
        other[0] = 45
        other[1] = 1846
        other[2] = 1948754
        assert field != other

    def test_eq_non_sequence_iterable(self, def_tc):
        dct = collections.OrderedDict([(1, 2), (3, 4), (5, 6)])
        field = self._create_int_array_field(def_tc, 3)
        field[0] = 1
        field[1] = 3
        field[2] = 5
        assert field == list(dct.keys())
        assert field != dct

    def test_setitem(self, field):
        field[2] = 24
        assert field[2] == 24

    def test_setitem_int_field(self, def_tc, field):
        int_field = _create_field(def_tc, def_tc.create_signed_integer_field_class(32))
        int_field.value = 19487
        field[1] = int_field
        assert field[1] == 19487

    def test_setitem_non_basic_field(self, def_tc):
        field = self._create_struct_array_field(def_tc, 2)

        with pytest.raises(TypeError):
            field[1] = 23

    def test_setitem_none(self, field):
        with pytest.raises(TypeError):
            field[1] = None

    def test_setitem_index_wrong_type(self, field):
        with pytest.raises(TypeError):
            field["yes"] = 23

    def test_setitem_index_neg(self, field):
        with pytest.raises(IndexError):
            field[-2] = 23

    def test_setitem_index_out_of_range(self, field):
        with pytest.raises(IndexError):
            field[len(field)] = 134679

    def test_const_setitem(self, const_field):
        with pytest.raises(TypeError):
            const_field[0] = 134679

    def test_iter(self, field, raw_val):
        for elem, val in zip(field, raw_val):
            assert elem == val

    def test_const_iter(self, const_field, raw_val):
        for elem, val in zip(const_field, raw_val):
            assert elem == val

    def test_val_int_field(self, field):
        vals = [45646, 145, 12145]
        field.value = vals
        assert vals == field

    def test_val_check_sequence(self, field):
        with pytest.raises(TypeError):
            field.value = 42

    def test_val_wrong_type_in_sequence(self, field):
        with pytest.raises(TypeError):
            field.value = [32, "hello", 11]

    def test_val_complex_type(self, def_tc):
        vals = [
            {"an_int": 42, "a_str": "hello", "another_int": 66},
            {"an_int": 1, "a_str": "goodbye", "another_int": 488},
            {"an_int": 156, "a_str": "or not", "another_int": 4648},
        ]

        field = (
            _create_stream(
                def_tc,
                [
                    (
                        "array_field",
                        def_tc.create_static_array_field_class(
                            def_tc.create_structure_field_class(
                                members=(
                                    (
                                        "an_int",
                                        def_tc.create_signed_integer_field_class(32),
                                    ),
                                    ("a_str", def_tc.create_string_field_class()),
                                    (
                                        "another_int",
                                        def_tc.create_signed_integer_field_class(32),
                                    ),
                                )
                            ),
                            3,
                        ),
                    )
                ],
            )
            .create_packet()
            .context_field["array_field"]
        )

        field.value = vals
        assert vals == field
        vals[0]["an_int"] = "a string"

        with pytest.raises(TypeError):
            field.value = vals

    def test_str_op(self, field, raw_val):
        s = str(field)
        expected_str = "[{}]".format(", ".join([repr(v) for v in raw_val]))
        assert expected_str == s


class TestStaticArray(_TestArrayField):
    @pytest.fixture
    def raw_val(self):
        return [45, 1847, 1948754]

    @pytest.fixture
    def field(self, def_tc, raw_val):
        field = self._create_int_array_field(def_tc, 3)
        field[0] = raw_val[0]
        field[1] = raw_val[1]
        field[2] = raw_val[2]
        return field

    @pytest.fixture
    def const_field(self, def_tc, raw_val):
        def value_setter(f):
            f.value = raw_val

        return utils.create_const_field(
            def_tc,
            def_tc.create_static_array_field_class(
                def_tc.create_signed_integer_field_class(32), 3
            ),
            value_setter,
        )

    def test_val_wrong_len(self, field):
        with pytest.raises(ValueError):
            field.value = [45, 1847]


class TestDynArray(_TestArrayField):
    @pytest.fixture
    def raw_val(self):
        return copy.copy([45, 1847, 1948754])

    @pytest.fixture
    def field(self, def_tc, raw_val):
        field_name = "int_dyn_array"

        pkt = _create_stream(
            def_tc,
            [
                ("thelength", def_tc.create_signed_integer_field_class(32)),
                (
                    field_name,
                    def_tc.create_dynamic_array_field_class(
                        def_tc.create_signed_integer_field_class(32)
                    ),
                ),
            ],
        ).create_packet()

        pkt.context_field[field_name].length = 3
        field = pkt.context_field[field_name]
        field[0] = raw_val[0]
        field[1] = raw_val[1]
        field[2] = raw_val[2]
        return field

    @pytest.fixture
    def const_field(self, def_tc, raw_val):
        def value_setter(f):
            f.value = raw_val

        return utils.create_const_field(
            def_tc,
            def_tc.create_dynamic_array_field_class(
                def_tc.create_signed_integer_field_class(32)
            ),
            value_setter,
        )

    def test_val_resize(self, field):
        new_vals = [1, 2, 3, 4]
        field.value = new_vals
        assert list(field) == new_vals

    def test_set_length(self, field):
        field.length = 4
        field[3] = 0
        assert len(field) == 4

    def test_const_set_length(self, const_field, field):
        with pytest.raises(AttributeError):
            const_field.length = 4

        assert len(field) == 3

    def test_set_invalid_length(self, field):
        with pytest.raises(TypeError):
            field.length = "cheval"


class TestStruct:
    # Static method instead of fixture because some tests need to create
    # multiple independent field classes (a field class may only be used
    # at one location within a trace class).
    @staticmethod
    def _create_fc(tc):
        return tc.create_structure_field_class(
            members=(
                ("A", tc.create_signed_integer_field_class()),
                ("B", tc.create_string_field_class()),
                ("C", tc.create_double_precision_real_field_class()),
                ("D", tc.create_signed_integer_field_class()),
                ("E", tc.create_structure_field_class()),
                (
                    "F",
                    tc.create_structure_field_class(
                        members=(("F_1", tc.create_signed_integer_field_class()),),
                    ),
                ),
            )
        )

    @pytest.fixture
    def fc(self, def_tc):
        return self._create_fc(def_tc)

    @pytest.fixture
    def raw_val(self):
        return copy.deepcopy(
            {
                "A": -1872,
                "B": "salut",
                "C": 17.5,
                "D": 16497,
                "E": {},
                "F": {"F_1": 52},
            }
        )

    @pytest.fixture
    def field(self, def_tc, fc, raw_val):
        field = _create_field(def_tc, fc)
        field["A"] = raw_val["A"]
        field["B"] = raw_val["B"]
        field["C"] = raw_val["C"]
        field["D"] = raw_val["D"]
        field["E"] = raw_val["E"]
        field["F"] = raw_val["F"]
        return field

    @pytest.fixture
    def const_field(self, def_tc, fc, raw_val):
        def value_setter(f):
            f.value = raw_val

        return utils.create_const_field(def_tc, fc, value_setter)

    def test_bool_op_true(self, field):
        assert field

    def test_bool_op_false(self, field):
        assert not field["E"]

    def test_len(self, field, raw_val):
        assert len(field) == len(raw_val)

    def test_getitem(self, field):
        assert type(field["A"]) is bt2._SignedIntegerField
        assert field["A"] == -1872
        assert type(field["B"]) is bt2._StringField
        assert field["B"] == "salut"
        assert type(field["C"]) is bt2._DoublePrecisionRealField
        assert field["C"] == 17.5
        assert type(field["D"]) is bt2._SignedIntegerField
        assert field["D"] == 16497
        assert type(field["E"]) is bt2._StructureField
        assert field["E"] == {}
        assert type(field["F"]) is bt2._StructureField
        assert field["F"] == {"F_1": 52}

    def test_const_getitem(self, const_field):
        assert type(const_field["A"]) is bt2._SignedIntegerFieldConst
        assert const_field["A"] == -1872
        assert type(const_field["B"]) is bt2._StringFieldConst
        assert const_field["B"] == "salut"
        assert type(const_field["C"]) is bt2._DoublePrecisionRealFieldConst
        assert const_field["C"] == 17.5
        assert type(const_field["D"]) is bt2._SignedIntegerFieldConst
        assert const_field["D"] == 16497
        assert type(const_field["E"]) is bt2._StructureFieldConst
        assert const_field["E"] == {}
        assert type(const_field["F"]) is bt2._StructureFieldConst
        assert const_field["F"] == {"F_1": 52}

    def test_member_at_index_out_of_bounds_after(self, field, raw_val):
        with pytest.raises(IndexError):
            field.member_at_index(len(raw_val))

    def test_eq(self, def_tc, field):
        other_field = _create_field(def_tc, self._create_fc(def_tc))
        other_field["A"] = -1872
        other_field["B"] = "salut"
        other_field["C"] = 17.5
        other_field["D"] = 16497
        other_field["E"] = {}
        other_field["F"] = {"F_1": 52}
        assert field == other_field

    def test_const_eq(self, def_tc, const_field):
        other_field = _create_field(def_tc, self._create_fc(def_tc))
        other_field["A"] = -1872
        other_field["B"] = "salut"
        other_field["C"] = 17.5
        other_field["D"] = 16497
        other_field["E"] = {}
        other_field["F"] = {"F_1": 52}
        assert const_field == other_field

    def test_eq_invalid_type(self, field):
        assert field != 23

    def test_eq_diff_len(self, def_tc, field):
        other_field = _create_field(
            def_tc,
            def_tc.create_structure_field_class(
                members=(
                    ("A", def_tc.create_signed_integer_field_class()),
                    ("B", def_tc.create_string_field_class()),
                    ("C", def_tc.create_double_precision_real_field_class()),
                )
            ),
        )

        other_field["A"] = -1872
        other_field["B"] = "salut"
        other_field["C"] = 17.5
        assert field != other_field

    def test_eq_diff_keys(self, def_tc, field):
        other_field = _create_field(
            def_tc,
            def_tc.create_structure_field_class(
                members=(
                    ("U", def_tc.create_signed_integer_field_class()),
                    ("V", def_tc.create_string_field_class()),
                    ("W", def_tc.create_double_precision_real_field_class()),
                    ("X", def_tc.create_signed_integer_field_class()),
                    ("Y", def_tc.create_structure_field_class()),
                    ("Z", def_tc.create_structure_field_class()),
                )
            ),
        )

        other_field["U"] = -1871
        other_field["V"] = "gerry"
        other_field["W"] = 18.19
        other_field["X"] = 16497
        other_field["Y"] = {}
        other_field["Z"] = {}
        assert field != other_field

    def test_eq_diff_content_same_len(self, def_tc, field):
        other_field = _create_field(def_tc, self._create_fc(def_tc))
        other_field["A"] = -1872
        other_field["B"] = "salut"
        other_field["C"] = 17.4
        other_field["D"] = 16497
        other_field["E"] = {}
        other_field["F"] = {"F_1": 0}
        assert field != other_field

    def test_eq_same_content_diff_keys(self, def_tc, field):
        other_field = _create_field(
            def_tc,
            def_tc.create_structure_field_class(
                members=(
                    ("A", def_tc.create_signed_integer_field_class()),
                    ("B", def_tc.create_string_field_class()),
                    ("E", def_tc.create_double_precision_real_field_class()),
                    ("D", def_tc.create_signed_integer_field_class()),
                    ("C", def_tc.create_structure_field_class()),
                    ("F", def_tc.create_structure_field_class()),
                )
            ),
        )

        other_field["A"] = -1872
        other_field["B"] = "salut"
        other_field["E"] = 17.5
        other_field["D"] = 16497
        other_field["C"] = {}
        other_field["F"] = {}
        assert field != other_field

    def test_setitem(self, field):
        field["C"] = -18.47
        assert field["C"] == -18.47

    def test_const_setitem(self, const_field):
        with pytest.raises(TypeError):
            const_field["A"] = 134679

    def test_setitem_int_field(self, def_tc, field):
        int_field = _create_field(def_tc, def_tc.create_signed_integer_field_class(32))
        int_field.value = 19487
        field["D"] = int_field
        assert field["D"] == 19487

    def test_setitem_non_basic_field(self, def_tc):
        field = _create_field(
            def_tc,
            def_tc.create_structure_field_class(
                members=(("A", def_tc.create_structure_field_class()),)
            ),
        )

        # Will fail on access to items() of the value
        with pytest.raises(AttributeError):
            field["A"] = 23

    def test_setitem_none(self, field):
        with pytest.raises(TypeError):
            field["C"] = None

    def test_setitem_key_wrong_type(self, field):
        with pytest.raises(TypeError):
            field[3] = 23

    def test_setitem_wrong_key(self, field):
        with pytest.raises(KeyError):
            field["hi"] = 134679

    def test_member_at_index(self, field):
        assert field.member_at_index(1) == "salut"

    def test_const_member_at_index(self, const_field):
        assert const_field.member_at_index(1) == "salut"

    def test_iter(self, field, raw_val):
        for vkey, vval in field.items():
            assert vval == raw_val[vkey]

    def test_eq_raw_val(self, field, raw_val):
        assert field == raw_val

    def test_set_val(self, def_tc):
        vals = {"an_int": 42, "a_str": "hello", "another_int": 66}

        field = _create_field(
            def_tc,
            def_tc.create_structure_field_class(
                members=(
                    ("an_int", def_tc.create_signed_integer_field_class(32)),
                    ("a_str", def_tc.create_string_field_class()),
                    ("another_int", def_tc.create_signed_integer_field_class(32)),
                )
            ),
        )

        field.value = vals
        assert vals == field

        bad_type_vals = copy.deepcopy(vals)
        bad_type_vals["an_int"] = "a string"

        with pytest.raises(TypeError):
            field.value = bad_type_vals

        unknown_key_vals = copy.deepcopy(vals)
        unknown_key_vals["unknown_key"] = 16546

        with pytest.raises(KeyError):
            field.value = unknown_key_vals

    def test_str_op(self, field):
        expected_str_found = False

        # Establish all permutations of the three expected matches since
        # the order in which mappings are enumerated is not explicitly
        # part of the API.
        for p in itertools.permutations([(k, v) for k, v in field.items()]):
            items = ["{}: {}".format(repr(k), repr(v)) for k, v in p]
            candidate = "{{{}}}".format(", ".join(items))

            if candidate == str(field):
                expected_str_found = True
                break

        assert expected_str_found


@pytest.mark.filterwarnings(
    r"ignore:.*create_option_without_selector_field_class.*:DeprecationWarning"
)
class TestOpt:
    # Static method instead of fixture because some tests need to create
    # multiple independent field classes (a field class may only be used
    # at one location within a trace class).
    @staticmethod
    def _create_fc(tc):
        return tc.create_option_without_selector_field_class(
            tc.create_string_field_class()
        )

    @pytest.fixture
    def fc(self, def_tc):
        return self._create_fc(def_tc)

    @pytest.fixture
    def raw_val(self):
        return "hiboux"

    @pytest.fixture
    def field(self, def_tc, fc):
        return _create_field(def_tc, fc)

    @pytest.fixture
    def const_field(self, def_tc, fc, raw_val):
        def value_setter(f):
            f.value = raw_val

        return utils.create_const_field(def_tc, fc, value_setter)

    def test_val_prop(self, field, raw_val):
        field.value = raw_val
        assert field.field == raw_val
        assert type(field) is bt2._OptionField
        assert type(field.field) is bt2._StringField
        assert field.has_field

    def test_const_val_prop(self, const_field, raw_val):
        assert const_field.field == raw_val
        assert type(const_field) is bt2._OptionFieldConst
        assert type(const_field.field) is bt2._StringFieldConst
        assert const_field.has_field

    @pytest.mark.parametrize("has_field", [True, False])
    def test_has_field_prop(self, field, has_field):
        field.has_field = has_field
        assert field.has_field == has_field

    def test_bool_op_true(self, field):
        field.value = "allo"
        assert field

    def test_bool_op_false(self, field):
        field.has_field = False
        assert not field

    def test_field_prop_existing(self, field):
        field.value = "meow"
        assert field.field == "meow"

    def test_field_prop_none(self, field):
        field.has_field = False
        assert field.field is None

    def test_const_field_prop(self, const_field, raw_val):
        with pytest.raises(AttributeError):
            const_field.has_field = False

        assert const_field == raw_val
        assert const_field.has_field

    def test_field_prop_existing_then_none(self, field):
        field.value = "meow"
        assert field.field == "meow"
        field.has_field = False
        assert field.field is None

    def test_eq(self, def_tc, field):
        other_field = _create_field(def_tc, self._create_fc(def_tc))
        other_field.value = "walk"
        field.value = "walk"
        assert field == other_field

    def test_const_eq(self, def_tc, const_field, raw_val):
        other_field = _create_field(def_tc, self._create_fc(def_tc))
        other_field.value = raw_val
        assert const_field == other_field
        assert const_field == raw_val

    def test_eq_invalid_type(self, field):
        field.value = "gerry"
        assert field != 23

    def test_str_op(self, field):
        field.value = "marcel"
        assert str(field) == str(field.field)

    def test_repr_op(self, field):
        field.value = "mireille"
        assert repr(field) == repr(field.field)


class TestVar:
    # Static method instead of fixture because some tests need to create
    # multiple independent field classes (a field class may only be used
    # at one location within a trace class).
    @staticmethod
    def _create_fc(tc):
        return tc.create_variant_field_class(
            options=(
                ("corner", tc.create_signed_integer_field_class(32)),
                ("zoom", tc.create_string_field_class()),
                ("mellotron", tc.create_double_precision_real_field_class()),
                ("giorgio", tc.create_signed_integer_field_class(17)),
            )
        )

    @pytest.fixture
    def fc(self, def_tc):
        return self._create_fc(def_tc)

    @pytest.fixture
    def raw_val(self):
        return 1334

    @pytest.fixture
    def field(self, def_tc, fc):
        return _create_field(def_tc, fc)

    @pytest.fixture
    def const_field(self, def_tc, fc, raw_val):
        def value_setter(f):
            f.selected_option_index = 3
            f.value = raw_val

        return utils.create_const_field(def_tc, fc, value_setter)

    def test_bool_op(self, field):
        field.selected_option_index = 2
        field.value = -17.34

        with pytest.raises(NotImplementedError):
            bool(field)

    def test_selected_opt_index(self, field):
        field.selected_option_index = 2
        assert field.selected_option_index == 2

    def test_selected_opt_index_above_range(self, field):
        with pytest.raises(IndexError):
            field.selected_option_index = 4

    def test_selected_opt_index_below_range(self, field):
        with pytest.raises(IndexError):
            field.selected_option_index = -1

    def test_const_selected_opt_index(self, const_field):
        with pytest.raises(AttributeError):
            const_field.selected_option_index = 2

        assert const_field.selected_option_index == 3

    def test_selected_opt(self, field):
        field.selected_option_index = 2
        field.value = -17.34
        assert field.selected_option == -17.34
        assert type(field.selected_option) is bt2._DoublePrecisionRealField
        field.selected_option_index = 3
        field.value = 1921
        assert field.selected_option == 1921
        assert type(field.selected_option) is bt2._SignedIntegerField

    def test_const_selected_opt(self, const_field, raw_val):
        assert const_field.selected_option == raw_val
        assert type(const_field.selected_option) is bt2._SignedIntegerFieldConst

    def test_eq(self, def_tc, field):
        other_field = _create_field(def_tc, self._create_fc(def_tc))
        other_field.selected_option_index = 0
        other_field.value = 1774
        field.selected_option_index = 0
        field.value = 1774
        assert field == other_field

    def test_const_eq(self, def_tc, const_field):
        other_field = _create_field(def_tc, self._create_fc(def_tc))
        other_field.selected_option_index = 3
        other_field.value = 1334
        assert const_field == other_field

    def test_len(self, field):
        assert len(field) == 4

    def test_eq_invalid_type(self, field):
        field.selected_option_index = 1
        field.value = "gerry"
        assert field != 23

    def test_str_op_int(self, def_tc):
        field = _create_field(def_tc, self._create_fc(def_tc))
        field.selected_option_index = 0
        field.value = 1774
        other = _create_field(def_tc, self._create_fc(def_tc))
        other.selected_option_index = 0
        other.value = 1774
        assert str(field) == str(other)

    def test_str_op_str(self, def_tc):
        field = _create_field(def_tc, self._create_fc(def_tc))
        field.selected_option_index = 1
        field.value = "un beau grand bateau"
        other = _create_field(def_tc, self._create_fc(def_tc))
        other.selected_option_index = 1
        other.value = "un beau grand bateau"
        assert str(field) == str(other)

    def test_str_op_float(self, def_tc):
        field = _create_field(def_tc, self._create_fc(def_tc))
        field.selected_option_index = 2
        field.value = 14.4245
        other = _create_field(def_tc, self._create_fc(def_tc))
        other.selected_option_index = 2
        other.value = 14.4245
        assert str(field) == str(other)
