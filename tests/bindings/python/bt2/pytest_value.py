# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019-2026 EfficiOS Inc.

import copy
import math
import operator
import collections
from functools import partial

import bt2
import utils
import pytest


# Returns a const value object wrapping `raw_val`.
def _create_const_val(raw_val):
    class MySink(bt2._UserSinkComponent):
        def _user_consume(self):
            pass

        @classmethod
        def _user_query(cls, priv_query_exec, obj, params, method_obj):
            return {"my_value": raw_val}

    return bt2.QueryExecutor(MySink, "obj", None).query()["my_value"]


# Binary operators for numeric value tests.
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


# Unary operators for numeric value tests.
_UNARY_OPS = [
    pytest.param(operator.neg, id="neg"),
    pytest.param(operator.pos, id="pos"),
    pytest.param(operator.abs, id="abs"),
    pytest.param(operator.invert, id="invert"),
    pytest.param(round, id="round"),
    pytest.param(partial(round, ndigits=0), id="round-0"),
    pytest.param(partial(round, ndigits=1), id="round-1"),
    pytest.param(partial(round, ndigits=2), id="round-2"),
    pytest.param(partial(round, ndigits=3), id="round-3"),
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


class TestCreate:
    def test_none(self):
        assert bt2.create_value(None) is None

    @pytest.mark.parametrize(
        ["raw_val", "expected_type"],
        [
            pytest.param(False, bt2.BoolValue, id="bool-false"),
            pytest.param(True, bt2.BoolValue, id="bool-true"),
            pytest.param(23, bt2.SignedIntegerValue, id="sint-pos"),
            pytest.param(-23, bt2.SignedIntegerValue, id="sint-neg"),
            pytest.param(17.5, bt2.RealValue, id="real-pos"),
            pytest.param(-17.5, bt2.RealValue, id="real-neg"),
            pytest.param("salut", bt2.StringValue, id="str"),
            pytest.param("", bt2.StringValue, id="str-empty"),
            pytest.param([1, 2, 3], bt2.ArrayValue, id="array-from-list"),
            pytest.param((4, 5, 6), bt2.ArrayValue, id="array-from-tuple"),
            pytest.param([], bt2.ArrayValue, id="array-from-empty-list"),
            pytest.param((), bt2.ArrayValue, id="array-from-empty-tuple"),
            pytest.param({"salut": 23}, bt2.MapValue, id="map"),
            pytest.param({}, bt2.MapValue, id="map-empty"),
        ],
    )
    def test_from_raw_val(self, raw_val, expected_type):
        val = bt2.create_value(raw_val)
        assert isinstance(val, expected_type)
        assert val == raw_val

    @pytest.mark.parametrize(
        ["raw_val", "expected_type"],
        [
            pytest.param(False, bt2.BoolValue, id="bool-false"),
            pytest.param(True, bt2.BoolValue, id="bool-true"),
            pytest.param(-23, bt2.SignedIntegerValue, id="sint"),
            pytest.param(17.5, bt2.RealValue, id="real"),
            pytest.param("salut", bt2.StringValue, id="str"),
            pytest.param([1, 2, 3], bt2.ArrayValue, id="array"),
            pytest.param({"a": 1}, bt2.MapValue, id="map"),
        ],
    )
    def test_from_val(self, raw_val, expected_type):
        val = bt2.create_value(bt2.create_value(raw_val))
        assert isinstance(val, expected_type)
        assert val == raw_val

    def test_invalid(self):
        with pytest.raises(
            TypeError, match="cannot create value object from 'object' object"
        ):
            bt2.create_value(object())


class TestNull:
    def test_create_from_none(self):
        assert bt2.create_value(None) is None


# The value object classes explicitly do not implement the copy methods,
# raising `NotImplementedError`, just in case we decide to implement
# them someday.
#
# Subclass must define val() fixture which returns a value object.
class _TestCopy:
    def test_copy(self, val):
        with pytest.raises(NotImplementedError, match="^$"):
            copy.copy(val)

    def test_deepcopy(self, val):
        with pytest.raises(NotImplementedError, match="^$"):
            copy.deepcopy(val)


# Base class for numeric value test cases.
#
# Subclass must define:
#
# val() fixture:
#     Returns a value object with an arbitrary raw value.
#
# raw_val() fixture:
#     Returns the equivalent raw value of val().
class _TestNumeric(_TestCopy):
    # Tries the binary operation `op(val, rhs)` and `op(raw_val, rhs)`,
    # returning both results.
    #
    # If either operation raises an exception, asserts that both raised
    # the same exception type and returns a (`None`, `None`) tuple to
    # signal that there's no result to compare (the exception behavior
    # was validated).
    @staticmethod
    def _bin_op(val, raw_val, op, rhs):
        val_exc_type = None
        raw_val_exc_type = None

        try:
            val_res = op(val, rhs)
        except Exception as e:
            val_exc_type = type(e)

        try:
            raw_val_res = op(raw_val, rhs)
        except Exception as e:
            raw_val_exc_type = type(e)

        if val_exc_type is not None or raw_val_exc_type is not None:
            assert val_exc_type is raw_val_exc_type
            return None, None

        return val_res, raw_val_res

    # Tries the unary operation `op(val)` and `op(raw_val)`, returning
    # both results.
    #
    # If either operation raises an exception, asserts that both raised
    # the same exception type and returns a (`None`, `None`) tuple to
    # signal that there's no result to compare (the exception behavior
    # was validated).
    @staticmethod
    def _unary_op(val, raw_val, op):
        if (
            isinstance(val, bt2._BoolValueConst) or isinstance(raw_val, bool)
        ) and op is operator.invert:
            pytest.skip("Invalid bitwise inversion on `bool`")

        val_exc_type = None
        raw_val_exc_type = None

        try:
            val_res = op(val)
        except Exception as e:
            val_exc_type = type(e)

        try:
            raw_val_res = op(raw_val)
        except Exception as e:
            raw_val_exc_type = type(e)

        if val_exc_type is not None or raw_val_exc_type is not None:
            assert val_exc_type is raw_val_exc_type
            return None, None

        return val_res, raw_val_res

    @pytest.mark.parametrize("type_conv", [bool, int, float, complex, str])
    def test_type_conv_op(self, val, raw_val, type_conv):
        assert type_conv(val) == type_conv(raw_val)

    def test_eq_none(self, val):
        # Disable the "comparison to None" warning, as this is precisely
        # what we want to test here!
        assert not (val == None)  # noqa: E711

    def test_ne_none(self, val):
        # Disable the "comparison to None" warning, as this is precisely
        # what we want to test here!
        assert val != None  # noqa: E711

    # Tests that `==` returns `False`, `!=` returns `True`, and other
    # binary operators raise `TypeError` when the right-hand side
    # operand is an unknown type.
    @pytest.mark.parametrize("op", _BIN_OPS)
    def test_bin_op_unknown(self, val, op):
        if op is operator.eq:
            assert op(val, object()) is False
        elif op is operator.ne:
            assert op(val, object()) is True
        else:
            with pytest.raises(TypeError):
                op(val, object())

    # Tests that `==` returns `False`, `!=` returns `True`, and other
    # binary operators raise `TypeError` when the right-hand side
    # operand is `None`.
    @pytest.mark.parametrize("op", _BIN_OPS)
    def test_bin_op_none(self, val, op):
        if op is operator.eq:
            assert op(val, None) is False
        elif op is operator.ne:
            assert op(val, None) is True
        else:
            with pytest.raises(TypeError):
                op(val, None)

    # Tests that binary operators return the same type as the equivalent
    # operation on raw values (comparisons return `bool`).
    @pytest.mark.parametrize("op", _BIN_OPS)
    @pytest.mark.parametrize("rhs", _RHS_OPERANDS)
    def test_bin_op_type(self, val, raw_val, op, rhs):
        val_res, raw_val_res = self._bin_op(val, raw_val, op, rhs)

        if val_res is not None:
            if op in (operator.eq, operator.ne):
                assert isinstance(val_res, bool)
            else:
                assert isinstance(val_res, type(raw_val_res))

    # Tests that binary operators return the same value as the
    # equivalent operation on raw values.
    @pytest.mark.parametrize("op", _BIN_OPS)
    @pytest.mark.parametrize("rhs", _RHS_OPERANDS)
    def test_bin_op_val(self, val, raw_val, op, rhs):
        val_res, raw_val_res = self._bin_op(val, raw_val, op, rhs)

        if val_res is not None:
            assert val_res == raw_val_res

    # Tests that binary operators don't change the address of the
    # left-hand side value object.
    @pytest.mark.parametrize("op", _BIN_OPS)
    @pytest.mark.parametrize("rhs", _RHS_OPERANDS)
    def test_bin_op_lhs_addr_same(self, val, raw_val, op, rhs):
        addr_before = val.addr
        self._bin_op(val, raw_val, op, rhs)
        assert val.addr == addr_before

    # Tests that binary operators don't modify the left-hand side
    # value object.
    @pytest.mark.parametrize("op", _BIN_OPS)
    @pytest.mark.parametrize("rhs", _RHS_OPERANDS)
    def test_bin_op_lhs_val_same(self, val, raw_val, op, rhs):
        val_before = val.__class__(val)
        self._bin_op(val, raw_val, op, rhs)
        assert val == val_before

    # Tests that unary operators return the same type as the equivalent
    # operation on raw values.
    @pytest.mark.parametrize("op", _UNARY_OPS)
    def test_unary_op_type(self, val, raw_val, op):
        val_res, raw_val_res = self._unary_op(val, raw_val, op)

        if val_res is not None:
            assert isinstance(val_res, type(raw_val_res))

    # Tests that unary operators return the same value as the equivalent
    # operation on raw values.
    @pytest.mark.parametrize("op", _UNARY_OPS)
    def test_unary_op_val(self, val, raw_val, op):
        val_res, raw_val_res = self._unary_op(val, raw_val, op)

        if val_res is not None:
            assert val_res == raw_val_res

    # Tests that unary operators don't change the address of the operand
    # value object.
    @pytest.mark.parametrize("op", _UNARY_OPS)
    def test_unary_op_addr_same(self, val, raw_val, op):
        addr_before = val.addr
        self._unary_op(val, raw_val, op)
        assert val.addr == addr_before

    # Tests that unary operators don't modify the operand value object.
    @pytest.mark.parametrize("op", _UNARY_OPS)
    def test_unary_op_val_same(self, val, raw_val, op):
        val_before = val.__class__(val)
        self._unary_op(val, raw_val, op)
        assert val == val_before


class TestBool(_TestNumeric):
    @pytest.fixture
    def val(self):
        return bt2.BoolValue(False)

    @pytest.fixture(scope="class")
    def raw_val(self):
        return False

    @pytest.fixture
    def true_val(self):
        return bt2.BoolValue(True)

    def test_create_def(self):
        assert not bt2.BoolValue()

    def test_create_false(self, val):
        assert not val

    def test_create_true(self, true_val):
        assert true_val

    def test_create_from_false_val(self, val):
        assert not bt2.BoolValue(val)

    def test_create_from_true_val(self, true_val):
        assert bt2.BoolValue(true_val)

    def test_create_from_int_non_zero(self):
        with pytest.raises(
            TypeError,
            match="'<class 'int'>' object is not a 'bool', 'BoolValue', or '_BoolValueConst' object",
        ):
            bt2.BoolValue(23)

    def test_create_from_int_zero(self):
        with pytest.raises(
            TypeError,
            match="'<class 'int'>' object is not a 'bool', 'BoolValue', or '_BoolValueConst' object",
        ):
            bt2.BoolValue(0)

    @pytest.mark.parametrize(
        ["assign_val", "expected_truthy"],
        [
            pytest.param(True, True, id="true"),
            pytest.param(False, False, id="false"),
            pytest.param(bt2.BoolValue(True), True, id="true-val"),
            pytest.param(bt2.BoolValue(False), False, id="false-val"),
        ],
    )
    def test_assign(self, assign_val, expected_truthy):
        val = bt2.BoolValue()
        val.value = assign_val
        assert bool(val) == expected_truthy

    def test_assign_int(self):
        with pytest.raises(
            TypeError,
            match="'<class 'int'>' object is not a 'bool', 'BoolValue', or '_BoolValueConst' object",
        ):
            bt2.BoolValue().value = 23

    def test_false_val_eq_false(self, val):
        assert val == False  # noqa: E712

    def test_false_val_ne_true(self, val):
        assert val != True  # noqa: E712

    def test_true_val_eq_true(self, true_val):
        assert true_val == True  # noqa: E712

    def test_true_val_ne_false(self, true_val):
        assert true_val != False  # noqa: E712


# Base class for integer value test cases.
#
# Subclass must satisfy the requirements of `_TestNumeric` define the
# val_cls() fixture which returns the integer value class to test
# (`bt2.UnsignedIntegerValue` or `bt2.SignedIntegerValue`).
class _TestInt(_TestNumeric):
    @pytest.fixture(scope="class")
    def raw_val(self):
        return 23

    @pytest.fixture
    def val(self, val_cls, raw_val):
        return val_cls(raw_val)

    def test_create_def(self, val_cls):
        assert val_cls() == 0

    def test_create_pos(self, val, raw_val):
        assert val == raw_val

    def test_create_from_int_val(self, val_cls, val, raw_val):
        assert val_cls(val) == raw_val

    def test_create_from_false(self, val_cls):
        assert not val_cls(False)

    def test_create_from_true(self, val_cls):
        assert val_cls(True)

    def test_create_from_unknown(self, val_cls):
        with pytest.raises(TypeError, match="expecting an integral number object"):
            val_cls(object())

    def test_create_from_array_val(self, val_cls):
        with pytest.raises(TypeError, match="expecting an integral number object"):
            val_cls(bt2.ArrayValue())

    @pytest.mark.parametrize(
        ["assign_val", "expected"],
        [
            pytest.param(True, True, id="true"),
            pytest.param(False, False, id="false"),
            pytest.param(477, 477, id="pos-int"),
            pytest.param(bt2.create_value(999), 999, id="int-val"),
        ],
    )
    def test_assign(self, val, assign_val, expected):
        val.value = assign_val
        assert val == expected  # noqa: E712


class TestUInt(_TestInt):
    @pytest.fixture(scope="class")
    def val_cls(self):
        return bt2.UnsignedIntegerValue

    def test_create_pos_too_big(self, val_cls):
        with pytest.raises(
            ValueError, match="expecting an unsigned 64-bit integral value"
        ):
            val_cls(2**64)

    def test_create_neg(self, val_cls):
        with pytest.raises(
            ValueError, match="expecting an unsigned 64-bit integral value"
        ):
            val_cls(-1)


class TestSInt(_TestInt):
    @pytest.fixture(scope="class")
    def val_cls(self):
        return bt2.SignedIntegerValue

    @pytest.fixture
    def neg_raw_val(self):
        return -52

    @pytest.fixture
    def neg_val(self, val_cls, neg_raw_val):
        return val_cls(neg_raw_val)

    def test_create_neg(self, neg_val, neg_raw_val):
        assert neg_val == neg_raw_val

    def test_create_pos_too_big(self, val_cls):
        with pytest.raises(
            ValueError, match="expecting a signed 64-bit integral value"
        ):
            val_cls(2**63)

    def test_create_neg_too_big(self, val_cls):
        with pytest.raises(
            ValueError, match="expecting a signed 64-bit integral value"
        ):
            val_cls(-(2**63) - 1)

    def test_assign_neg_int(self, val):
        val.value = -13
        assert val == -13

    def test_compare_big_int(self):
        # Larger than the IEEE 754 double-precision exact representation
        # of integers.
        raw_val = (2**53) + 1
        val = bt2.create_value(raw_val)
        assert val == raw_val


class TestReal(_TestNumeric):
    @pytest.fixture(scope="class")
    def raw_val(self):
        return 23.4

    @pytest.fixture
    def val(self, raw_val):
        return bt2.RealValue(raw_val)

    @pytest.fixture
    def neg_raw_val(self):
        return -52.7

    @pytest.fixture
    def neg_val(self, neg_raw_val):
        return bt2.RealValue(neg_raw_val)

    def test_create_def(self):
        assert bt2.RealValue() == 0.0

    def test_create_pos(self, val, raw_val):
        assert val == raw_val

    def test_create_neg(self, neg_val, neg_raw_val):
        assert neg_val == neg_raw_val

    def test_create_from_false(self):
        assert not bt2.RealValue(False)

    def test_create_from_true(self):
        assert bt2.RealValue(True)

    def test_create_from_int(self):
        assert bt2.RealValue(17) == float(17)

    def test_create_from_int_val(self):
        assert bt2.RealValue(bt2.create_value(17)) == float(17)

    def test_create_from_real_val(self):
        assert bt2.RealValue(bt2.create_value(17.17)) == 17.17

    def test_create_from_unknown(self):
        with pytest.raises(TypeError, match="expecting a real number object"):
            bt2.RealValue(object())

    def test_create_from_array_val(self):
        with pytest.raises(TypeError, match="expecting a real number object"):
            bt2.RealValue(bt2.ArrayValue())

    @pytest.mark.parametrize(
        ["assign_val", "expected"],
        [
            pytest.param(True, True, id="true"),
            pytest.param(False, False, id="false"),
            pytest.param(477, float(477), id="pos-int"),
            pytest.param(-13, float(-13), id="neg-int"),
            pytest.param(bt2.create_value(999), float(999), id="int-val"),
            pytest.param(-19.23, -19.23, id="real"),
            pytest.param(bt2.create_value(101.32), 101.32, id="real-val"),
        ],
    )
    def test_assign(self, val, assign_val, expected):
        val.value = assign_val
        assert val == expected

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
    def test_invalid_bitwise_bin_op(self, val, op):
        with pytest.raises(TypeError):
            op(val, 23)

    def test_invalid_invert(self, val):
        with pytest.raises(TypeError):
            ~val


class TestStr(_TestCopy):
    @pytest.fixture(scope="class")
    def raw_val(self):
        return "Hello, World!"

    @pytest.fixture
    def val(self, raw_val):
        return bt2.StringValue(raw_val)

    @pytest.fixture(scope="class")
    def const_val(self, raw_val):
        return _create_const_val(raw_val)

    def test_create_def(self):
        assert bt2.StringValue() == ""

    def test_create_from_str(self):
        assert bt2.StringValue("liberté") == "liberté"

    def test_create_from_str_val(self):
        assert bt2.StringValue(bt2.create_value("liberté")) == "liberté"

    def test_create_from_unknown(self):
        with pytest.raises(TypeError, match="'object' is not a 'str' object"):
            bt2.StringValue(object())

    def test_create_from_array_val(self):
        with pytest.raises(TypeError, match="'ArrayValue' is not a 'str' object"):
            bt2.StringValue(bt2.ArrayValue())

    def test_assign_int(self, val):
        with pytest.raises(TypeError, match="'int' is not a 'str' object"):
            val.value = 283

    def test_assign_str(self, val):
        val.value = "zorg"
        assert val == "zorg"

    def test_assign_str_val(self, val):
        val.value = bt2.create_value("zorg")
        assert val == "zorg"

    def test_eq(self, val, raw_val):
        assert val == raw_val

    def test_const_eq(self, const_val, raw_val):
        assert const_val == raw_val

    def test_eq_raw(self, val):
        assert val != 23

    def test_lt_str_val(self):
        assert bt2.StringValue("allo") < bt2.StringValue("bateau")

    def test_lt_str(self):
        assert bt2.StringValue("allo") < "bateau"

    def test_le_str_val(self):
        assert bt2.StringValue("allo") <= bt2.StringValue("bateau")

    def test_le_str(self):
        assert bt2.StringValue("allo") <= "bateau"

    def test_gt_str_val(self):
        assert bt2.StringValue("bateau") > bt2.StringValue("allo")

    def test_gt_str(self):
        assert "bateau" > bt2.StringValue("allo")

    def test_ge_str_val(self):
        assert bt2.StringValue("bateau") >= bt2.StringValue("allo")

    def test_ge_str(self):
        assert "bateau" >= bt2.StringValue("allo")

    def test_in_str(self):
        assert "bateau" in bt2.StringValue("beau grand bateau")

    def test_in_str_val(self):
        assert bt2.StringValue("bateau") in bt2.StringValue("beau grand bateau")

    def test_bool_op(self, val, raw_val):
        assert bool(val) == bool(raw_val)

    def test_str_op(self, val, raw_val):
        assert str(val) == str(raw_val)

    def test_len(self, val, raw_val):
        assert len(val) == len(raw_val)

    def test_getitem(self, val, raw_val):
        assert val[5] == raw_val[5]

    def test_const_getitem(self, const_val, raw_val):
        assert const_val[5] == raw_val[5]

    def test_iadd_str(self, val, raw_val):
        to_append = "meow meow meow"
        val += to_append
        assert val == raw_val + to_append

    def test_const_iadd_str(self, const_val, raw_val):
        with pytest.raises(
            TypeError,
            match=r"unsupported operand type\(s\) for \+=: '_StringValueConst' and 'str'",
        ):
            const_val += "meow meow meow"

        assert const_val == raw_val

    def test_append_str_val(self, val, raw_val):
        to_append = "meow meow meow"
        val += bt2.create_value(to_append)
        assert val == raw_val + to_append


class TestArray(_TestCopy):
    _RAW_VAL = [None, False, True, -23, 0, 42, -42.4, 23.17, "yes"]

    @pytest.fixture
    def raw_val(self):
        return copy.copy(self._RAW_VAL)

    @pytest.fixture
    def val(self, raw_val):
        return bt2.ArrayValue(copy.deepcopy(raw_val))

    @pytest.fixture(scope="class")
    def const_val(self):
        return _create_const_val(copy.deepcopy(self._RAW_VAL))

    def test_create_def(self):
        assert len(bt2.ArrayValue()) == 0

    def test_create_from_array(self, val, raw_val):
        assert val == raw_val

    def test_create_from_tuple(self):
        t = 1, 2, False, None
        assert bt2.ArrayValue(t) == t

    def test_create_from_array_val(self, raw_val):
        val = bt2.ArrayValue(copy.deepcopy(raw_val))
        assert bt2.ArrayValue(val) == val

    def test_create_from_unknown(self):
        with pytest.raises(TypeError, match="'object' object is not iterable"):
            bt2.ArrayValue(object())

    def test_bool_op_true(self, val):
        assert bool(val)

    def test_bool_op_false(self):
        assert not bool(bt2.ArrayValue())

    def test_len(self, val, raw_val):
        assert len(val) == len(raw_val)

    def test_eq_int(self, val):
        assert val != 23

    def test_const_eq(self):
        assert _create_const_val([1, 2, 3]) == [1, 2, 3]

    def test_eq_diff_len(self):
        assert bt2.create_value([1, 2, 3]) != bt2.create_value([1, 2])

    def test_eq_diff_content_same_len(self):
        assert bt2.create_value([1, 2, 3]) != bt2.create_value([4, 5, 6])

    def test_eq_same_content_same_len(self):
        raw = (3, True, [1, 2.5, None, {"a": 17.6, "b": None}])
        assert bt2.ArrayValue(raw) == bt2.ArrayValue(copy.deepcopy(raw))

    def test_eq_non_sequence_iterable(self):
        dct = collections.OrderedDict([(1, 2), (3, 4), (5, 6)])
        a = bt2.ArrayValue((1, 3, 5))
        assert a == list(dct.keys())
        assert a != dct

    def test_setitem_int(self, val):
        val[2] = 19
        assert val[2] == 19

    def test_setitem_int_val(self, val):
        val[2] = bt2.create_value(19)
        assert val[2] == 19

    def test_setitem_none(self, val):
        val[2] = None
        assert val[2] is None

    def test_setitem_index_wrong_type(self, val):
        with pytest.raises(
            TypeError,
            match="'str' object is not an integral number object: invalid index",
        ):
            val["yes"] = 23

    def test_setitem_index_neg(self, val):
        with pytest.raises(
            IndexError, match="array value object index is out of range"
        ):
            val[-2] = 23

    def test_setitem_index_out_of_range(self, val):
        with pytest.raises(
            IndexError, match="array value object index is out of range"
        ):
            val[len(val)] = 23

    def test_const_setitem(self, const_val):
        with pytest.raises(
            TypeError,
            match="'_ArrayValueConst' object does not support item assignment",
        ):
            const_val[2] = 19

    def test_append_none(self, val):
        val.append(None)
        assert val[len(val) - 1] is None

    def test_append_int(self, val):
        val.append(145)
        assert val[len(val) - 1] == 145

    def test_const_append(self, const_val):
        with pytest.raises(
            AttributeError, match="'_ArrayValueConst' object has no attribute 'append'"
        ):
            const_val.append(12194)

    def test_append_int_val(self, val):
        val.append(bt2.create_value(145))
        assert val[len(val) - 1] == 145

    def test_append_unknown(self, val):
        with pytest.raises(
            TypeError, match="cannot create value object from 'object' object"
        ):
            val.append(object())

    def test_iadd(self, val):
        raw = 4, 5, True
        val += raw
        assert val[len(val) - 3] == raw[0]
        assert val[len(val) - 2] == raw[1]
        assert val[len(val) - 1] == raw[2]

    def test_const_iadd(self, const_val):
        with pytest.raises(
            TypeError,
            match=r"unsupported operand type\(s\) for \+=: '_ArrayValueConst' and 'int'",
        ):
            const_val += 12194

    def test_iadd_unknown(self, val):
        with pytest.raises(TypeError, match="'object' object is not iterable"):
            val += object()

    def test_iadd_list_unknown(self, val):
        with pytest.raises(
            TypeError, match="cannot create value object from 'object' object"
        ):
            val += [object()]

    def test_iter(self, val, raw_val):
        for elem_val, elem in zip(val, raw_val):
            assert elem_val == elem

    def test_const_iter(self, const_val, raw_val):
        for elem_val, elem in zip(const_val, raw_val):
            assert elem_val == elem

    def test_const_get_item(self, const_val):
        assert const_val[0] is None
        assert type(const_val[2]) is bt2._BoolValueConst
        assert const_val[2] == True  # noqa: E712
        assert type(const_val[5]) is bt2._SignedIntegerValueConst
        assert const_val[5] == 42
        assert type(const_val[7]) is bt2._RealValueConst
        assert const_val[7] == 23.17
        assert type(const_val[8]) is bt2._StringValueConst
        assert const_val[8] == "yes"


class TestMap(_TestCopy):
    _RAW_VAL = {
        "none": None,
        "false": False,
        "true": True,
        "neg-int": -23,
        "zero": 0,
        "pos-int": 42,
        "neg-float": -42.4,
        "pos-float": 23.17,
        "str": "yes",
    }

    @pytest.fixture
    def raw_val(self):
        return copy.copy(self._RAW_VAL)

    @pytest.fixture
    def val(self, raw_val):
        return bt2.MapValue(copy.deepcopy(raw_val))

    @pytest.fixture(scope="class")
    def const_val(self):
        return _create_const_val(copy.deepcopy(self._RAW_VAL))

    def test_create_def(self):
        assert len(bt2.MapValue()) == 0

    def test_create_from_dict(self, val, raw_val):
        assert val == raw_val

    def test_create_from_map_val(self, raw_val):
        val = bt2.MapValue(copy.deepcopy(raw_val))
        assert bt2.MapValue(val) == val

    def test_create_from_unknown(self):
        with pytest.raises(
            AttributeError, match="'object' object has no attribute 'items'"
        ):
            bt2.MapValue(object())

    def test_bool_op_true(self, val):
        assert bool(val)

    def test_bool_op_false(self):
        assert not bool(bt2.MapValue())

    def test_len(self, val, raw_val):
        assert len(val) == len(raw_val)

    @pytest.fixture(scope="class")
    def short_dict(self):
        return {"a": 1, "b": 2, "c": 3}

    def test_const_eq(self, short_dict):
        assert _create_const_val(short_dict) == short_dict

    def test_eq_int(self, val):
        assert val != 23

    def test_eq_diff_len(self, short_dict):
        assert bt2.create_value(short_dict) != bt2.create_value({"a": 1, "b": 2})

    def test_const_eq_diff_len(self, short_dict):
        assert _create_const_val(short_dict) != _create_const_val({"a": 1, "b": 2})

    def test_eq_diff_content_same_len(self, short_dict):
        assert bt2.create_value(short_dict) != bt2.create_value(
            {"a": 4, "b": 2, "c": 3}
        )

    def test_const_eq_diff_content_same_len(self, short_dict):
        assert _create_const_val(short_dict) != _create_const_val(
            {"a": 4, "b": 2, "c": 3}
        )

    def test_eq_same_content_diff_keys(self, short_dict):
        assert bt2.create_value(short_dict) != bt2.create_value(
            {"a": 1, "k": 2, "c": 3}
        )

    def test_const_eq_same_content_diff_keys(self, short_dict):
        assert _create_const_val(short_dict) != _create_const_val(
            {"a": 1, "k": 2, "c": 3}
        )

    @pytest.fixture
    def some_dict(self):
        return {"3": 3, "True": True, "array": [1, 2.5, None, {"a": 17.6, "b": None}]}

    def test_eq_same_content_same_len(self, some_dict):
        a1 = bt2.MapValue(some_dict)
        a2 = bt2.MapValue(copy.deepcopy(some_dict))
        assert a1 == a2
        assert a1 == some_dict

    def test_const_eq_same_content_same_len(self, some_dict):
        assert _create_const_val(some_dict) == _create_const_val(
            copy.deepcopy(some_dict)
        )
        assert _create_const_val(some_dict) == some_dict

    def test_setitem_int(self, val):
        val["pos-int"] = 19
        assert val["pos-int"] == 19

    def test_const_setitem_int(self, const_val):
        with pytest.raises(
            TypeError, match="'_MapValueConst' object does not support item assignment"
        ):
            const_val["pos-int"] = 19

    def test_setitem_int_val(self, val):
        val["pos-int"] = bt2.create_value(19)
        assert val["pos-int"] == 19

    def test_setitem_none(self, val):
        val["none"] = None
        assert val["none"] is None

    def test_setitem_new_int(self, val):
        old_len = len(val)
        val["new-int"] = 23
        assert val["new-int"] == 23
        assert len(val) == old_len + 1

    def test_setitem_index_wrong_type(self, val):
        with pytest.raises(TypeError, match="'int' is not a 'str' object"):
            val[18] = 23

    def test_iter(self, val, raw_val):
        for vkey, vval in val.items():
            assert vval == raw_val[vkey]

    def test_const_iter(self, const_val, raw_val):
        for vkey, vval in const_val.items():
            assert vval == raw_val[vkey]

    def test_get_item(self, val):
        assert type(val["pos-float"]) is bt2.RealValue
        assert val["pos-float"] == 23.17

    def test_const_get_item(self, const_val):
        assert const_val["none"] is None
        assert type(const_val["true"]) is bt2._BoolValueConst
        assert const_val["true"] == True  # noqa: E712
        assert type(const_val["pos-int"]) is bt2._SignedIntegerValueConst
        assert const_val["pos-int"] == 42
        assert type(const_val["pos-float"]) is bt2._RealValueConst
        assert const_val["pos-float"] == 23.17
        assert type(const_val["str"]) is bt2._StringValueConst
        assert const_val["str"] == "yes"

    def test_getitem_wrong_key(self, val):
        with pytest.raises(KeyError, match="'kilojoule'"):
            val["kilojoule"]
