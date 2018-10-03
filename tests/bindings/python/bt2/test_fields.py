from functools import partial, partialmethod
import operator
import unittest
import numbers
import math
import copy
import itertools
import bt2


_COMP_BINOPS = (
    operator.eq,
    operator.ne,
)

def _create_stream(ctx_field_types):
    packet_context_ft = bt2.StructureFieldType()
    for name, ft in ctx_field_types:
        packet_context_ft.append_field(name, ft)

    trace = bt2.Trace()
    stream_class = trace.create_stream_class()
    stream_class.packet_context_field_type = packet_context_ft

    stream = stream_class()
    return stream

def _create_field(field_type):
    field_name = 'field'
    stream = _create_stream([(field_name, field_type)])
    packet = stream.create_packet()
    return packet.context_field[field_name]

def _create_string_field():
    field_name = 'string_field'
    stream = _create_stream([(field_name, bt2.StringFieldType())])
    packet = stream.create_packet()
    return packet.context_field[field_name]

def _create_int_array_field(length):
    elem_ft = bt2.SignedIntegerFieldType(32)
    ft = bt2.StaticArrayFieldType(elem_ft, length)
    field_name = 'int_array'
    stream = _create_stream([(field_name, ft)])
    packet = stream.create_packet()
    return packet.context_field[field_name]

def _create_dynamic_array():
    elem_ft = bt2.SignedIntegerFieldType(32)
    len_ft = bt2.SignedIntegerFieldType(32)
    ft = bt2.DynamicArrayFieldType(elem_ft)
    field_name = 'int_sequence'
    stream = _create_stream([('thelength', len_ft), (field_name, ft)])
    packet = stream.create_packet()
    packet.context_field[field_name].length = 3
    return packet.context_field[field_name]

def _create_struct_array_field(length):
    elem_ft = bt2.StructureFieldType()
    ft = bt2.StaticArrayFieldType(elem_ft, length)
    field_name = 'struct_array'
    stream = _create_stream([(field_name, ft)])
    packet = stream.create_packet()
    return packet.context_field[field_name]

class _TestNumericField:
    def _binop(self, op, rhs):
        rexc = None
        rvexc = None
        comp_value = rhs

        try:
            r = op(self._def, rhs)
        except Exception as e:
            rexc = e

        try:
            rv = op(self._def_value, comp_value)
        except Exception as e:
            rvexc = e

        if rexc is not None or rvexc is not None:
            # at least one of the operations raised an exception: in
            # this case both operations should have raised the same
            # type of exception (division by zero, bit shift with a
            # floating point number operand, etc.)
            self.assertIs(type(rexc), type(rvexc))
            return None, None

        return r, rv

    def _unaryop(self, op):
        rexc = None
        rvexc = None

        try:
            r = op(self._def)
        except Exception as e:
            rexc = e

        try:
            rv = op(self._def_value)
        except Exception as e:
            rvexc = e

        if rexc is not None or rvexc is not None:
            # at least one of the operations raised an exception: in
            # this case both operations should have raised the same
            # type of exception (division by zero, bit shift with a
            # floating point number operand, etc.)
            self.assertIs(type(rexc), type(rvexc))
            return None, None

        return r, rv

    def _test_unaryop_type(self, op):
        r, rv = self._unaryop(op)

        if r is None:
            return

        self.assertIsInstance(r, type(rv))

    def _test_unaryop_value(self, op):
        r, rv = self._unaryop(op)

        if r is None:
            return

        self.assertEqual(r, rv)

    def _test_unaryop_addr_same(self, op):
        addr_before = self._def.addr
        self._unaryop(op)
        self.assertEqual(self._def.addr, addr_before)

    def _test_unaryop_value_same(self, op):
        value_before = copy.copy(self._def_value)
        self._unaryop(op)
        self.assertEqual(self._def, value_before)

    def _test_binop_type(self, op, rhs):
        r, rv = self._binop(op, rhs)

        if r is None:
            return

        if op in _COMP_BINOPS:
            # __eq__() and __ne__() always return a 'bool' object
            self.assertIsInstance(r, bool)
        else:
            self.assertIsInstance(r, type(rv))

    def _test_binop_value(self, op, rhs):
        r, rv = self._binop(op, rhs)

        if r is None:
            return

        self.assertEqual(r, rv)

    def _test_binop_lhs_addr_same(self, op, rhs):
        addr_before = self._def.addr
        r, rv = self._binop(op, rhs)
        self.assertEqual(self._def.addr, addr_before)

    def _test_binop_lhs_value_same(self, op, rhs):
        pass
        #value_before = copy.copy(self._def.value)
        #r, rv = self._binop(op, rhs)
        #self.assertEqual(self._def.value, value_before)

    def _test_binop_invalid_unknown(self, op):
        if op in _COMP_BINOPS:
            self.skipTest('not testing')

        class A:
            pass

        with self.assertRaises(TypeError):
            op(self._def, A())

    def _test_binop_invalid_none(self, op):
        if op in _COMP_BINOPS:
            self.skipTest('not testing')

        with self.assertRaises(TypeError):
            op(self._def, None)

    def _test_ibinop_value(self, op, rhs):
        r, rv = self._binop(op, rhs)

        if r is None:
            return

        # The inplace operators are special for field objects because
        # they do not return a new, immutable object like it's the case
        # for Python numbers. In Python, `a += 2`, where `a` is a number
        # object, assigns a new number object reference to `a`, dropping
        # the old reference. Since BT's field objects are mutable, we
        # modify their internal value with the inplace operators. This
        # means however that we can lose data in the process, for
        # example:
        #
        #     int_value_obj += 3.3
        #
        # Here, if `int_value_obj` is a Python `int` with the value 2,
        # it would be a `float` object after this, holding the value
        # 5.3. In our case, if `int_value_obj` is an integer field
        # object, 3.3 is converted to an `int` object (3) and added to
        # the current value of `int_value_obj`, so after this the value
        # of the object is 5. This does not compare to 5.3, which is
        # why we also use the `int()` type here.
        if isinstance(self._def, bt2.fields._IntegerField):
            rv = int(rv)

        self.assertEqual(r, rv)

    def _test_ibinop_type(self, op, rhs):
        r, rv = self._binop(op, rhs)

        if r is None:
            return

        self.assertIs(r, self._def)

    def _test_ibinop_invalid_unknown(self, op):
        class A:
            pass

        with self.assertRaises(TypeError):
            op(self._def, A())

    def _test_ibinop_invalid_none(self, op):
        with self.assertRaises(TypeError):
            op(self._def, None)

    def _test_binop_rhs_false(self, test_cb, op):
        test_cb(op, False)

    def _test_binop_rhs_true(self, test_cb, op):
        test_cb(op, True)

    def _test_binop_rhs_pos_int(self, test_cb, op):
        test_cb(op, 2)

    def _test_binop_rhs_neg_int(self, test_cb, op):
        test_cb(op, -23)

    def _test_binop_rhs_zero_int(self, test_cb, op):
        test_cb(op, 0)

    def _test_binop_rhs_pos_vint(self, test_cb, op):
        test_cb(op, bt2.create_value(2))

    def _test_binop_rhs_neg_vint(self, test_cb, op):
        test_cb(op, bt2.create_value(-23))

    def _test_binop_rhs_zero_vint(self, test_cb, op):
        test_cb(op, bt2.create_value(0))

    def _test_binop_rhs_pos_float(self, test_cb, op):
        test_cb(op, 2.2)

    def _test_binop_rhs_neg_float(self, test_cb, op):
        test_cb(op, -23.4)

    def _test_binop_rhs_zero_float(self, test_cb, op):
        test_cb(op, 0.0)

    def _test_binop_rhs_pos_vfloat(self, test_cb, op):
        test_cb(op, bt2.create_value(2.2))

    def _test_binop_rhs_neg_vfloat(self, test_cb, op):
        test_cb(op, bt2.create_value(-23.4))

    def _test_binop_rhs_zero_vfloat(self, test_cb, op):
        test_cb(op, bt2.create_value(0.0))

    def _test_binop_type_false(self, op):
        self._test_binop_rhs_false(self._test_binop_type, op)

    def _test_binop_type_true(self, op):
        self._test_binop_rhs_true(self._test_binop_type, op)

    def _test_binop_type_pos_int(self, op):
        self._test_binop_rhs_pos_int(self._test_binop_type, op)

    def _test_binop_type_neg_int(self, op):
        self._test_binop_rhs_neg_int(self._test_binop_type, op)

    def _test_binop_type_zero_int(self, op):
        self._test_binop_rhs_zero_int(self._test_binop_type, op)

    def _test_binop_type_pos_vint(self, op):
        self._test_binop_rhs_pos_vint(self._test_binop_type, op)

    def _test_binop_type_neg_vint(self, op):
        self._test_binop_rhs_neg_vint(self._test_binop_type, op)

    def _test_binop_type_zero_vint(self, op):
        self._test_binop_rhs_zero_vint(self._test_binop_type, op)

    def _test_binop_type_pos_float(self, op):
        self._test_binop_rhs_pos_float(self._test_binop_type, op)

    def _test_binop_type_neg_float(self, op):
        self._test_binop_rhs_neg_float(self._test_binop_type, op)

    def _test_binop_type_zero_float(self, op):
        self._test_binop_rhs_zero_float(self._test_binop_type, op)

    def _test_binop_type_pos_vfloat(self, op):
        self._test_binop_rhs_pos_vfloat(self._test_binop_type, op)

    def _test_binop_type_neg_vfloat(self, op):
        self._test_binop_rhs_neg_vfloat(self._test_binop_type, op)

    def _test_binop_type_zero_vfloat(self, op):
        self._test_binop_rhs_zero_vfloat(self._test_binop_type, op)

    def _test_binop_value_false(self, op):
        self._test_binop_rhs_false(self._test_binop_value, op)

    def _test_binop_value_true(self, op):
        self._test_binop_rhs_true(self._test_binop_value, op)

    def _test_binop_value_pos_int(self, op):
        self._test_binop_rhs_pos_int(self._test_binop_value, op)

    def _test_binop_value_neg_int(self, op):
        self._test_binop_rhs_neg_int(self._test_binop_value, op)

    def _test_binop_value_zero_int(self, op):
        self._test_binop_rhs_zero_int(self._test_binop_value, op)

    def _test_binop_value_pos_vint(self, op):
        self._test_binop_rhs_pos_vint(self._test_binop_value, op)

    def _test_binop_value_neg_vint(self, op):
        self._test_binop_rhs_neg_vint(self._test_binop_value, op)

    def _test_binop_value_zero_vint(self, op):
        self._test_binop_rhs_zero_vint(self._test_binop_value, op)

    def _test_binop_value_pos_float(self, op):
        self._test_binop_rhs_pos_float(self._test_binop_value, op)

    def _test_binop_value_neg_float(self, op):
        self._test_binop_rhs_neg_float(self._test_binop_value, op)

    def _test_binop_value_zero_float(self, op):
        self._test_binop_rhs_zero_float(self._test_binop_value, op)

    def _test_binop_value_pos_vfloat(self, op):
        self._test_binop_rhs_pos_vfloat(self._test_binop_value, op)

    def _test_binop_value_neg_vfloat(self, op):
        self._test_binop_rhs_neg_vfloat(self._test_binop_value, op)

    def _test_binop_value_zero_vfloat(self, op):
        self._test_binop_rhs_zero_vfloat(self._test_binop_value, op)

    def _test_binop_lhs_addr_same_false(self, op):
        self._test_binop_rhs_false(self._test_binop_lhs_addr_same, op)

    def _test_binop_lhs_addr_same_true(self, op):
        self._test_binop_rhs_true(self._test_binop_lhs_addr_same, op)

    def _test_binop_lhs_addr_same_pos_int(self, op):
        self._test_binop_rhs_pos_int(self._test_binop_lhs_addr_same, op)

    def _test_binop_lhs_addr_same_neg_int(self, op):
        self._test_binop_rhs_neg_int(self._test_binop_lhs_addr_same, op)

    def _test_binop_lhs_addr_same_zero_int(self, op):
        self._test_binop_rhs_zero_int(self._test_binop_lhs_addr_same, op)

    def _test_binop_lhs_addr_same_pos_vint(self, op):
        self._test_binop_rhs_pos_vint(self._test_binop_lhs_addr_same, op)

    def _test_binop_lhs_addr_same_neg_vint(self, op):
        self._test_binop_rhs_neg_vint(self._test_binop_lhs_addr_same, op)

    def _test_binop_lhs_addr_same_zero_vint(self, op):
        self._test_binop_rhs_zero_vint(self._test_binop_lhs_addr_same, op)

    def _test_binop_lhs_addr_same_pos_float(self, op):
        self._test_binop_rhs_pos_float(self._test_binop_lhs_addr_same, op)

    def _test_binop_lhs_addr_same_neg_float(self, op):
        self._test_binop_rhs_neg_float(self._test_binop_lhs_addr_same, op)

    def _test_binop_lhs_addr_same_zero_float(self, op):
        self._test_binop_rhs_zero_float(self._test_binop_lhs_addr_same, op)

    def _test_binop_lhs_addr_same_pos_vfloat(self, op):
        self._test_binop_rhs_pos_vfloat(self._test_binop_lhs_addr_same, op)

    def _test_binop_lhs_addr_same_neg_vfloat(self, op):
        self._test_binop_rhs_neg_vfloat(self._test_binop_lhs_addr_same, op)

    def _test_binop_lhs_addr_same_zero_vfloat(self, op):
        self._test_binop_rhs_zero_vfloat(self._test_binop_lhs_addr_same, op)

    def _test_binop_lhs_value_same_false(self, op):
        self._test_binop_rhs_false(self._test_binop_lhs_value_same, op)

    def _test_binop_lhs_value_same_true(self, op):
        self._test_binop_rhs_true(self._test_binop_lhs_value_same, op)

    def _test_binop_lhs_value_same_pos_int(self, op):
        self._test_binop_rhs_pos_int(self._test_binop_lhs_value_same, op)

    def _test_binop_lhs_value_same_neg_int(self, op):
        self._test_binop_rhs_neg_int(self._test_binop_lhs_value_same, op)

    def _test_binop_lhs_value_same_zero_int(self, op):
        self._test_binop_rhs_zero_int(self._test_binop_lhs_value_same, op)

    def _test_binop_lhs_value_same_pos_vint(self, op):
        self._test_binop_rhs_pos_vint(self._test_binop_lhs_value_same, op)

    def _test_binop_lhs_value_same_neg_vint(self, op):
        self._test_binop_rhs_neg_vint(self._test_binop_lhs_value_same, op)

    def _test_binop_lhs_value_same_zero_vint(self, op):
        self._test_binop_rhs_zero_vint(self._test_binop_lhs_value_same, op)

    def _test_binop_lhs_value_same_pos_float(self, op):
        self._test_binop_rhs_pos_float(self._test_binop_lhs_value_same, op)

    def _test_binop_lhs_value_same_neg_float(self, op):
        self._test_binop_rhs_neg_float(self._test_binop_lhs_value_same, op)

    def _test_binop_lhs_value_same_zero_float(self, op):
        self._test_binop_rhs_zero_float(self._test_binop_lhs_value_same, op)

    def _test_binop_lhs_value_same_pos_vfloat(self, op):
        self._test_binop_rhs_pos_vfloat(self._test_binop_lhs_value_same, op)

    def _test_binop_lhs_value_same_neg_vfloat(self, op):
        self._test_binop_rhs_neg_vfloat(self._test_binop_lhs_value_same, op)

    def _test_binop_lhs_value_same_zero_vfloat(self, op):
        self._test_binop_rhs_zero_vfloat(self._test_binop_lhs_value_same, op)

    def _test_ibinop_type_false(self, op):
        self._test_binop_rhs_false(self._test_ibinop_type, op)

    def _test_ibinop_type_true(self, op):
        self._test_binop_rhs_true(self._test_ibinop_type, op)

    def _test_ibinop_type_pos_int(self, op):
        self._test_binop_rhs_pos_int(self._test_ibinop_type, op)

    def _test_ibinop_type_neg_int(self, op):
        self._test_binop_rhs_neg_int(self._test_ibinop_type, op)

    def _test_ibinop_type_zero_int(self, op):
        self._test_binop_rhs_zero_int(self._test_ibinop_type, op)

    def _test_ibinop_type_pos_vint(self, op):
        self._test_binop_rhs_pos_vint(self._test_ibinop_type, op)

    def _test_ibinop_type_neg_vint(self, op):
        self._test_binop_rhs_neg_vint(self._test_ibinop_type, op)

    def _test_ibinop_type_zero_vint(self, op):
        self._test_binop_rhs_zero_vint(self._test_ibinop_type, op)

    def _test_ibinop_type_pos_float(self, op):
        self._test_binop_rhs_pos_float(self._test_ibinop_type, op)

    def _test_ibinop_type_neg_float(self, op):
        self._test_binop_rhs_neg_float(self._test_ibinop_type, op)

    def _test_ibinop_type_zero_float(self, op):
        self._test_binop_rhs_zero_float(self._test_ibinop_type, op)

    def _test_ibinop_type_pos_vfloat(self, op):
        self._test_binop_rhs_pos_vfloat(self._test_ibinop_type, op)

    def _test_ibinop_type_neg_vfloat(self, op):
        self._test_binop_rhs_neg_vfloat(self._test_ibinop_type, op)

    def _test_ibinop_type_zero_vfloat(self, op):
        self._test_binop_rhs_zero_vfloat(self._test_ibinop_type, op)

    def _test_ibinop_value_false(self, op):
        self._test_binop_rhs_false(self._test_ibinop_value, op)

    def _test_ibinop_value_true(self, op):
        self._test_binop_rhs_true(self._test_ibinop_value, op)

    def _test_ibinop_value_pos_int(self, op):
        self._test_binop_rhs_pos_int(self._test_ibinop_value, op)

    def _test_ibinop_value_neg_int(self, op):
        self._test_binop_rhs_neg_int(self._test_ibinop_value, op)

    def _test_ibinop_value_zero_int(self, op):
        self._test_binop_rhs_zero_int(self._test_ibinop_value, op)

    def _test_ibinop_value_pos_vint(self, op):
        self._test_binop_rhs_pos_vint(self._test_ibinop_value, op)

    def _test_ibinop_value_neg_vint(self, op):
        self._test_binop_rhs_neg_vint(self._test_ibinop_value, op)

    def _test_ibinop_value_zero_vint(self, op):
        self._test_binop_rhs_zero_vint(self._test_ibinop_value, op)

    def _test_ibinop_value_pos_float(self, op):
        self._test_binop_rhs_pos_float(self._test_ibinop_value, op)

    def _test_ibinop_value_neg_float(self, op):
        self._test_binop_rhs_neg_float(self._test_ibinop_value, op)

    def _test_ibinop_value_zero_float(self, op):
        self._test_binop_rhs_zero_float(self._test_ibinop_value, op)

    def _test_ibinop_value_pos_vfloat(self, op):
        self._test_binop_rhs_pos_vfloat(self._test_ibinop_value, op)

    def _test_ibinop_value_neg_vfloat(self, op):
        self._test_binop_rhs_neg_vfloat(self._test_ibinop_value, op)

    def _test_ibinop_value_zero_vfloat(self, op):
        self._test_binop_rhs_zero_vfloat(self._test_ibinop_value, op)

    def test_bool_op(self):
        self.assertEqual(bool(self._def), bool(self._def_value))

    def test_int_op(self):
        self.assertEqual(int(self._def), int(self._def_value))

    def test_float_op(self):
        self.assertEqual(float(self._def), float(self._def_value))

    def test_complex_op(self):
        self.assertEqual(complex(self._def), complex(self._def_value))

    def test_str_op(self):
        self.assertEqual(str(self._def), str(self._def_value))

    def test_eq_none(self):
        self.assertFalse(self._def == None)

    def test_ne_none(self):
        self.assertTrue(self._def != None)


_BINOPS = (
    ('lt', operator.lt),
    ('le', operator.le),
    ('eq', operator.eq),
    ('ne', operator.ne),
    ('ge', operator.ge),
    ('gt', operator.gt),
    ('add', operator.add),
    ('radd', lambda a, b: operator.add(b, a)),
    ('and', operator.and_),
    ('rand', lambda a, b: operator.and_(b, a)),
    ('floordiv', operator.floordiv),
    ('rfloordiv', lambda a, b: operator.floordiv(b, a)),
    ('lshift', operator.lshift),
    ('rlshift', lambda a, b: operator.lshift(b, a)),
    ('mod', operator.mod),
    ('rmod', lambda a, b: operator.mod(b, a)),
    ('mul', operator.mul),
    ('rmul', lambda a, b: operator.mul(b, a)),
    ('or', operator.or_),
    ('ror', lambda a, b: operator.or_(b, a)),
    ('pow', operator.pow),
    ('rpow', lambda a, b: operator.pow(b, a)),
    ('rshift', operator.rshift),
    ('rrshift', lambda a, b: operator.rshift(b, a)),
    ('sub', operator.sub),
    ('rsub', lambda a, b: operator.sub(b, a)),
    ('truediv', operator.truediv),
    ('rtruediv', lambda a, b: operator.truediv(b, a)),
    ('xor', operator.xor),
    ('rxor', lambda a, b: operator.xor(b, a)),
)


_IBINOPS = (
    ('iadd', operator.iadd),
    ('iand', operator.iand),
    ('ifloordiv', operator.ifloordiv),
    ('ilshift', operator.ilshift),
    ('imod', operator.imod),
    ('imul', operator.imul),
    ('ior', operator.ior),
    ('ipow', operator.ipow),
    ('irshift', operator.irshift),
    ('isub', operator.isub),
    ('itruediv', operator.itruediv),
    ('ixor', operator.ixor),
)


_UNARYOPS = (
    ('neg', operator.neg),
    ('pos', operator.pos),
    ('abs', operator.abs),
    ('invert', operator.invert),
    ('round', round),
    ('round_0', partial(round, ndigits=0)),
    ('round_1', partial(round, ndigits=1)),
    ('round_2', partial(round, ndigits=2)),
    ('round_3', partial(round, ndigits=3)),
    ('ceil', math.ceil),
    ('floor', math.floor),
    ('trunc', math.trunc),
)


def _inject_numeric_testing_methods(cls):
    def test_binop_name(suffix):
        return 'test_binop_{}_{}'.format(name, suffix)

    def test_ibinop_name(suffix):
        return 'test_ibinop_{}_{}'.format(name, suffix)

    def test_unaryop_name(suffix):
        return 'test_unaryop_{}_{}'.format(name, suffix)

    # inject testing methods for each binary operation
    for name, binop in _BINOPS:
        setattr(cls, test_binop_name('invalid_unknown'), partialmethod(_TestNumericField._test_binop_invalid_unknown, op=binop))
        setattr(cls, test_binop_name('invalid_none'), partialmethod(_TestNumericField._test_binop_invalid_none, op=binop))
        setattr(cls, test_binop_name('type_true'), partialmethod(_TestNumericField._test_binop_type_true, op=binop))
        setattr(cls, test_binop_name('type_pos_int'), partialmethod(_TestNumericField._test_binop_type_pos_int, op=binop))
        setattr(cls, test_binop_name('type_pos_vint'), partialmethod(_TestNumericField._test_binop_type_pos_vint, op=binop))
        setattr(cls, test_binop_name('value_true'), partialmethod(_TestNumericField._test_binop_value_true, op=binop))
        setattr(cls, test_binop_name('value_pos_int'), partialmethod(_TestNumericField._test_binop_value_pos_int, op=binop))
        setattr(cls, test_binop_name('value_pos_vint'), partialmethod(_TestNumericField._test_binop_value_pos_vint, op=binop))
        setattr(cls, test_binop_name('lhs_addr_same_true'), partialmethod(_TestNumericField._test_binop_lhs_addr_same_true, op=binop))
        setattr(cls, test_binop_name('lhs_addr_same_pos_int'), partialmethod(_TestNumericField._test_binop_lhs_addr_same_pos_int, op=binop))
        setattr(cls, test_binop_name('lhs_addr_same_pos_vint'), partialmethod(_TestNumericField._test_binop_lhs_addr_same_pos_vint, op=binop))
        setattr(cls, test_binop_name('lhs_value_same_true'), partialmethod(_TestNumericField._test_binop_lhs_value_same_true, op=binop))
        setattr(cls, test_binop_name('lhs_value_same_pos_int'), partialmethod(_TestNumericField._test_binop_lhs_value_same_pos_int, op=binop))
        setattr(cls, test_binop_name('lhs_value_same_pos_vint'), partialmethod(_TestNumericField._test_binop_lhs_value_same_pos_vint, op=binop))
        setattr(cls, test_binop_name('type_neg_int'), partialmethod(_TestNumericField._test_binop_type_neg_int, op=binop))
        setattr(cls, test_binop_name('type_neg_vint'), partialmethod(_TestNumericField._test_binop_type_neg_vint, op=binop))
        setattr(cls, test_binop_name('value_neg_int'), partialmethod(_TestNumericField._test_binop_value_neg_int, op=binop))
        setattr(cls, test_binop_name('value_neg_vint'), partialmethod(_TestNumericField._test_binop_value_neg_vint, op=binop))
        setattr(cls, test_binop_name('lhs_addr_same_neg_int'), partialmethod(_TestNumericField._test_binop_lhs_addr_same_neg_int, op=binop))
        setattr(cls, test_binop_name('lhs_addr_same_neg_vint'), partialmethod(_TestNumericField._test_binop_lhs_addr_same_neg_vint, op=binop))
        setattr(cls, test_binop_name('lhs_value_same_neg_int'), partialmethod(_TestNumericField._test_binop_lhs_value_same_neg_int, op=binop))
        setattr(cls, test_binop_name('lhs_value_same_neg_vint'), partialmethod(_TestNumericField._test_binop_lhs_value_same_neg_vint, op=binop))
        setattr(cls, test_binop_name('type_false'), partialmethod(_TestNumericField._test_binop_type_false, op=binop))
        setattr(cls, test_binop_name('type_zero_int'), partialmethod(_TestNumericField._test_binop_type_zero_int, op=binop))
        setattr(cls, test_binop_name('type_zero_vint'), partialmethod(_TestNumericField._test_binop_type_zero_vint, op=binop))
        setattr(cls, test_binop_name('value_false'), partialmethod(_TestNumericField._test_binop_value_false, op=binop))
        setattr(cls, test_binop_name('value_zero_int'), partialmethod(_TestNumericField._test_binop_value_zero_int, op=binop))
        setattr(cls, test_binop_name('value_zero_vint'), partialmethod(_TestNumericField._test_binop_value_zero_vint, op=binop))
        setattr(cls, test_binop_name('lhs_addr_same_false'), partialmethod(_TestNumericField._test_binop_lhs_addr_same_false, op=binop))
        setattr(cls, test_binop_name('lhs_addr_same_zero_int'), partialmethod(_TestNumericField._test_binop_lhs_addr_same_zero_int, op=binop))
        setattr(cls, test_binop_name('lhs_addr_same_zero_vint'), partialmethod(_TestNumericField._test_binop_lhs_addr_same_zero_vint, op=binop))
        setattr(cls, test_binop_name('lhs_value_same_false'), partialmethod(_TestNumericField._test_binop_lhs_value_same_false, op=binop))
        setattr(cls, test_binop_name('lhs_value_same_zero_int'), partialmethod(_TestNumericField._test_binop_lhs_value_same_zero_int, op=binop))
        setattr(cls, test_binop_name('lhs_value_same_zero_vint'), partialmethod(_TestNumericField._test_binop_lhs_value_same_zero_vint, op=binop))
        setattr(cls, test_binop_name('type_pos_float'), partialmethod(_TestNumericField._test_binop_type_pos_float, op=binop))
        setattr(cls, test_binop_name('type_neg_float'), partialmethod(_TestNumericField._test_binop_type_neg_float, op=binop))
        setattr(cls, test_binop_name('type_pos_vfloat'), partialmethod(_TestNumericField._test_binop_type_pos_vfloat, op=binop))
        setattr(cls, test_binop_name('type_neg_vfloat'), partialmethod(_TestNumericField._test_binop_type_neg_vfloat, op=binop))
        setattr(cls, test_binop_name('value_pos_float'), partialmethod(_TestNumericField._test_binop_value_pos_float, op=binop))
        setattr(cls, test_binop_name('value_neg_float'), partialmethod(_TestNumericField._test_binop_value_neg_float, op=binop))
        setattr(cls, test_binop_name('value_pos_vfloat'), partialmethod(_TestNumericField._test_binop_value_pos_vfloat, op=binop))
        setattr(cls, test_binop_name('value_neg_vfloat'), partialmethod(_TestNumericField._test_binop_value_neg_vfloat, op=binop))
        setattr(cls, test_binop_name('lhs_addr_same_pos_float'), partialmethod(_TestNumericField._test_binop_lhs_addr_same_pos_float, op=binop))
        setattr(cls, test_binop_name('lhs_addr_same_neg_float'), partialmethod(_TestNumericField._test_binop_lhs_addr_same_neg_float, op=binop))
        setattr(cls, test_binop_name('lhs_addr_same_pos_vfloat'), partialmethod(_TestNumericField._test_binop_lhs_addr_same_pos_vfloat, op=binop))
        setattr(cls, test_binop_name('lhs_addr_same_neg_vfloat'), partialmethod(_TestNumericField._test_binop_lhs_addr_same_neg_vfloat, op=binop))
        setattr(cls, test_binop_name('lhs_value_same_pos_float'), partialmethod(_TestNumericField._test_binop_lhs_value_same_pos_float, op=binop))
        setattr(cls, test_binop_name('lhs_value_same_neg_float'), partialmethod(_TestNumericField._test_binop_lhs_value_same_neg_float, op=binop))
        setattr(cls, test_binop_name('lhs_value_same_pos_vfloat'), partialmethod(_TestNumericField._test_binop_lhs_value_same_pos_vfloat, op=binop))
        setattr(cls, test_binop_name('lhs_value_same_neg_vfloat'), partialmethod(_TestNumericField._test_binop_lhs_value_same_neg_vfloat, op=binop))
        setattr(cls, test_binop_name('type_zero_float'), partialmethod(_TestNumericField._test_binop_type_zero_float, op=binop))
        setattr(cls, test_binop_name('type_zero_vfloat'), partialmethod(_TestNumericField._test_binop_type_zero_vfloat, op=binop))
        setattr(cls, test_binop_name('value_zero_float'), partialmethod(_TestNumericField._test_binop_value_zero_float, op=binop))
        setattr(cls, test_binop_name('value_zero_vfloat'), partialmethod(_TestNumericField._test_binop_value_zero_vfloat, op=binop))
        setattr(cls, test_binop_name('lhs_addr_same_zero_float'), partialmethod(_TestNumericField._test_binop_lhs_addr_same_zero_float, op=binop))
        setattr(cls, test_binop_name('lhs_addr_same_zero_vfloat'), partialmethod(_TestNumericField._test_binop_lhs_addr_same_zero_vfloat, op=binop))
        setattr(cls, test_binop_name('lhs_value_same_zero_float'), partialmethod(_TestNumericField._test_binop_lhs_value_same_zero_float, op=binop))
        setattr(cls, test_binop_name('lhs_value_same_zero_vfloat'), partialmethod(_TestNumericField._test_binop_lhs_value_same_zero_vfloat, op=binop))

    # inject testing methods for each unary operation
    for name, unaryop in _UNARYOPS:
        setattr(cls, test_unaryop_name('type'), partialmethod(_TestNumericField._test_unaryop_type, op=unaryop))
        setattr(cls, test_unaryop_name('value'), partialmethod(_TestNumericField._test_unaryop_value, op=unaryop))
        setattr(cls, test_unaryop_name('addr_same'), partialmethod(_TestNumericField._test_unaryop_addr_same, op=unaryop))
        setattr(cls, test_unaryop_name('value_same'), partialmethod(_TestNumericField._test_unaryop_value_same, op=unaryop))

    # inject testing methods for each inplace binary operation
    for name, ibinop in _IBINOPS:
        setattr(cls, test_ibinop_name('invalid_unknown'), partialmethod(_TestNumericField._test_ibinop_invalid_unknown, op=ibinop))
        setattr(cls, test_ibinop_name('invalid_none'), partialmethod(_TestNumericField._test_ibinop_invalid_none, op=ibinop))
        setattr(cls, test_ibinop_name('type_true'), partialmethod(_TestNumericField._test_ibinop_type_true, op=ibinop))
        setattr(cls, test_ibinop_name('value_true'), partialmethod(_TestNumericField._test_ibinop_value_true, op=ibinop))
        setattr(cls, test_ibinop_name('type_pos_int'), partialmethod(_TestNumericField._test_ibinop_type_pos_int, op=ibinop))
        setattr(cls, test_ibinop_name('type_pos_vint'), partialmethod(_TestNumericField._test_ibinop_type_pos_vint, op=ibinop))
        setattr(cls, test_ibinop_name('value_pos_int'), partialmethod(_TestNumericField._test_ibinop_value_pos_int, op=ibinop))
        setattr(cls, test_ibinop_name('value_pos_vint'), partialmethod(_TestNumericField._test_ibinop_value_pos_vint, op=ibinop))
        setattr(cls, test_ibinop_name('type_neg_int'), partialmethod(_TestNumericField._test_ibinop_type_neg_int, op=ibinop))
        setattr(cls, test_ibinop_name('type_neg_vint'), partialmethod(_TestNumericField._test_ibinop_type_neg_vint, op=ibinop))
        setattr(cls, test_ibinop_name('value_neg_int'), partialmethod(_TestNumericField._test_ibinop_value_neg_int, op=ibinop))
        setattr(cls, test_ibinop_name('value_neg_vint'), partialmethod(_TestNumericField._test_ibinop_value_neg_vint, op=ibinop))
        setattr(cls, test_ibinop_name('type_false'), partialmethod(_TestNumericField._test_ibinop_type_false, op=ibinop))
        setattr(cls, test_ibinop_name('value_false'), partialmethod(_TestNumericField._test_ibinop_value_false, op=ibinop))
        setattr(cls, test_ibinop_name('type_zero_int'), partialmethod(_TestNumericField._test_ibinop_type_zero_int, op=ibinop))
        setattr(cls, test_ibinop_name('type_zero_vint'), partialmethod(_TestNumericField._test_ibinop_type_zero_vint, op=ibinop))
        setattr(cls, test_ibinop_name('value_zero_int'), partialmethod(_TestNumericField._test_ibinop_value_zero_int, op=ibinop))
        setattr(cls, test_ibinop_name('value_zero_vint'), partialmethod(_TestNumericField._test_ibinop_value_zero_vint, op=ibinop))
        setattr(cls, test_ibinop_name('type_pos_float'), partialmethod(_TestNumericField._test_ibinop_type_pos_float, op=ibinop))
        setattr(cls, test_ibinop_name('type_neg_float'), partialmethod(_TestNumericField._test_ibinop_type_neg_float, op=ibinop))
        setattr(cls, test_ibinop_name('type_pos_vfloat'), partialmethod(_TestNumericField._test_ibinop_type_pos_vfloat, op=ibinop))
        setattr(cls, test_ibinop_name('type_neg_vfloat'), partialmethod(_TestNumericField._test_ibinop_type_neg_vfloat, op=ibinop))
        setattr(cls, test_ibinop_name('value_pos_float'), partialmethod(_TestNumericField._test_ibinop_value_pos_float, op=ibinop))
        setattr(cls, test_ibinop_name('value_neg_float'), partialmethod(_TestNumericField._test_ibinop_value_neg_float, op=ibinop))
        setattr(cls, test_ibinop_name('value_pos_vfloat'), partialmethod(_TestNumericField._test_ibinop_value_pos_vfloat, op=ibinop))
        setattr(cls, test_ibinop_name('value_neg_vfloat'), partialmethod(_TestNumericField._test_ibinop_value_neg_vfloat, op=ibinop))
        setattr(cls, test_ibinop_name('type_zero_float'), partialmethod(_TestNumericField._test_ibinop_type_zero_float, op=ibinop))
        setattr(cls, test_ibinop_name('type_zero_vfloat'), partialmethod(_TestNumericField._test_ibinop_type_zero_vfloat, op=ibinop))
        setattr(cls, test_ibinop_name('value_zero_float'), partialmethod(_TestNumericField._test_ibinop_value_zero_float, op=ibinop))
        setattr(cls, test_ibinop_name('value_zero_vfloat'), partialmethod(_TestNumericField._test_ibinop_value_zero_vfloat, op=ibinop))


class _TestIntegerFieldCommon(_TestNumericField):
    def test_assign_true(self):
        raw = True
        self._def.value = raw
        self.assertEqual(self._def, raw)

    def test_assign_false(self):
        raw = False
        self._def.value = raw
        self.assertEqual(self._def, raw)

    def test_assign_pos_int(self):
        raw = 477
        self._def.value = raw
        self.assertEqual(self._def, raw)

    def test_assign_neg_int(self):
        raw = -13
        self._def.value = raw
        self.assertEqual(self._def, raw)

    def test_assign_int_field(self):
        raw = 999
        field = _create_field(self._create_ft())
        field.value = raw
        self._def.value = field
        self.assertEqual(self._def, raw)

    def test_assign_float(self):
        raw = 123.456
        self._def.value = raw
        self.assertEqual(self._def, int(raw))

    def test_assign_invalid_type(self):
        with self.assertRaises(TypeError):
            self._def.value = 'yes'

    def test_assign_uint(self):
        uint_ft = bt2.UnsignedIntegerFieldType(32)
        field = _create_field(uint_ft)
        raw = 1777
        field.value = 1777
        self.assertEqual(field, raw)

    def test_assign_uint_invalid_neg(self):
        uint_ft = bt2.UnsignedIntegerFieldType(32)
        field = _create_field(uint_ft)

        with self.assertRaises(ValueError):
            field.value = -23

    def test_str_op(self):
        self.assertEqual(str(self._def), str(self._def_value))


_inject_numeric_testing_methods(_TestIntegerFieldCommon)


class SignedIntegerFieldTestCase(_TestIntegerFieldCommon, unittest.TestCase):
    def _create_ft(self):
        return bt2.SignedIntegerFieldType(25)

    def setUp(self):
        self._field = _create_field(self._create_ft())
        self._field.value = 17
        self._def = _create_field(self._create_ft())
        self._def.value = 17
        self._def_value = 17
        self._def_new_value = -101

    def tearDown(self):
        del self._field
        del self._def


class EnumerationFieldTestCase(_TestIntegerFieldCommon, unittest.TestCase):
    def _create_ft(self):
        ft = bt2.SignedEnumerationFieldType(32)
        ft.map_range('something', 17)
        ft.map_range('speaker', 12, 16)
        ft.map_range('can', 18, 2540)
        ft.map_range('whole range', -(2 ** 31), (2 ** 31) - 1)
        ft.map_range('zip', -45, 1001)
        return ft

    def setUp(self):
        self._field = _create_field(self._create_ft())
        self._def = _create_field(self._create_ft())
        self._def.value = 17
        self._def_value = 17
        self._def_new_value = -101

    def tearDown(self):
        del self._field
        del self._def

    def test_str_op(self):
        expected_string_found = False
        s = str(self._def)

        # Establish all permutations of the three expected matches since
        # the order in which mappings are enumerated is not explicitly part of
        # the API.
        for p in itertools.permutations(['whole range', 'something',
                                         'zip']):
            candidate = '{} ({})'.format(self._def_value, ', '.join(p))
            if candidate == s:
                expected_string_found = True
                break

        self.assertTrue(expected_string_found)


class RealFieldTestCase(_TestNumericField, unittest.TestCase):
    def _create_ft(self):
        return bt2.RealFieldType()
    def setUp(self):
        self._field = _create_field(self._create_ft())
        self._def = _create_field(self._create_ft())
        self._def.value = 52.7
        self._def_value = 52.7
        self._def_new_value = -17.164857

    def tearDown(self):
        del self._field
        del self._def

    def _test_invalid_op(self, cb):
        with self.assertRaises(TypeError):
            cb()

    def test_assign_true(self):
        self._def.value = True
        self.assertTrue(self._def)

    def test_assign_false(self):
        self._def.value = False
        self.assertFalse(self._def)

    def test_assign_pos_int(self):
        raw = 477
        self._def.value = raw
        self.assertEqual(self._def, float(raw))

    def test_assign_neg_int(self):
        raw = -13
        self._def.value = raw
        self.assertEqual(self._def, float(raw))

    def test_assign_int_field(self):
        int_ft = bt2.SignedIntegerFieldType(32)
        int_field = _create_field(int_ft)
        raw = 999
        int_field.value = raw
        self._def.value = int_field
        self.assertEqual(self._def, float(raw))

    def test_assign_float(self):
        raw = -19.23
        self._def.value = raw
        self.assertEqual(self._def, raw)

    def test_assign_float_field(self):
        field = _create_field(self._create_ft())
        raw = 101.32
        field.value = raw
        self._def.value = field
        self.assertEqual(self._def, raw)

    def test_assign_invalid_type(self):
        with self.assertRaises(TypeError):
            self._def.value = 'yes'

    def test_invalid_lshift(self):
        self._test_invalid_op(lambda: self._def << 23)

    def test_invalid_rshift(self):
        self._test_invalid_op(lambda: self._def >> 23)

    def test_invalid_and(self):
        self._test_invalid_op(lambda: self._def & 23)

    def test_invalid_or(self):
        self._test_invalid_op(lambda: self._def | 23)

    def test_invalid_xor(self):
        self._test_invalid_op(lambda: self._def ^ 23)

    def test_invalid_invert(self):
        self._test_invalid_op(lambda: ~self._def)

    def test_str_op(self):
        self.assertEqual(str(self._def), str(self._def_value))

_inject_numeric_testing_methods(RealFieldTestCase)


class StringFieldTestCase(unittest.TestCase):
    def setUp(self):
        self._def_value = 'Hello, World!'
        self._def = _create_string_field()
        self._def.value = self._def_value
        self._def_new_value = 'Yes!'

    def tearDown(self):
        del self._def

    def test_assign_int(self):
        with self.assertRaises(TypeError):
            self._def.value = 283

    def test_assign_string_field(self):
        field = _create_string_field()
        raw = 'zorg'
        field.value = raw
        self.assertEqual(field, raw)

    def test_eq(self):
        self.assertEqual(self._def, self._def_value)

    def test_eq(self):
        self.assertNotEqual(self._def, 23)

    def test_lt_vstring(self):
        s1 = _create_string_field()
        s1.value = 'allo'
        s2 = _create_string_field()
        s2.value = 'bateau'
        self.assertLess(s1, s2)

    def test_lt_string(self):
        s1 = _create_string_field()
        s1.value = 'allo'
        self.assertLess(s1, 'bateau')

    def test_le_vstring(self):
        s1 = _create_string_field()
        s1.value = 'allo'
        s2 = _create_string_field()
        s2.value = 'bateau'
        self.assertLessEqual(s1, s2)

    def test_le_string(self):
        s1 = _create_string_field()
        s1.value = 'allo'
        self.assertLessEqual(s1, 'bateau')

    def test_gt_vstring(self):
        s1 = _create_string_field()
        s1.value = 'allo'
        s2 = _create_string_field()
        s2.value = 'bateau'
        self.assertGreater(s2, s1)

    def test_gt_string(self):
        s1 = _create_string_field()
        s1.value = 'allo'
        self.assertGreater('bateau', s1)

    def test_ge_vstring(self):
        s1 = _create_string_field()
        s1.value = 'allo'
        s2 = _create_string_field()
        s2.value = 'bateau'
        self.assertGreaterEqual(s2, s1)

    def test_ge_string(self):
        s1 = _create_string_field()
        s1.value = 'allo'
        self.assertGreaterEqual('bateau', s1)

    def test_bool_op(self):
        self.assertEqual(bool(self._def), bool(self._def_value))

    def test_str_op(self):
        self.assertEqual(str(self._def), str(self._def_value))

    def test_len(self):
        self.assertEqual(len(self._def), len(self._def_value))

    def test_getitem(self):
        self.assertEqual(self._def[5], self._def_value[5])

    def test_append_str(self):
        to_append = 'meow meow meow'
        self._def += to_append
        self._def_value += to_append
        self.assertEqual(self._def, self._def_value)

    def test_append_string_field(self):
        field = _create_string_field()
        to_append = 'meow meow meow'
        field.value = to_append
        self._def += field
        self._def_value += to_append
        self.assertEqual(self._def, self._def_value)


class _TestArraySequenceFieldCommon:
    def _modify_def(self):
        self._def[2] = 23

    def test_bool_op_true(self):
        self.assertTrue(self._def)

    def test_len(self):
        self.assertEqual(len(self._def), 3)

    def test_getitem(self):
        field = self._def[1]
        self.assertIs(type(field), bt2.fields._SignedIntegerField)
        self.assertEqual(field, 1847)

    def test_eq(self):
        field = _create_int_array_field(3)
        field[0] = 45
        field[1] = 1847
        field[2] = 1948754
        self.assertEqual(self._def, field)

    def test_eq_invalid_type(self):
        self.assertNotEqual(self._def, 23)

    def test_eq_diff_len(self):
        field = _create_int_array_field(2)
        field[0] = 45
        field[1] = 1847
        self.assertNotEqual(self._def, field)

    def test_eq_diff_content_same_len(self):
        field = _create_int_array_field(3)
        field[0] = 45
        field[1] = 1846
        field[2] = 1948754
        self.assertNotEqual(self._def, field)

    def test_setitem(self):
        self._def[2] = 24
        self.assertEqual(self._def[2], 24)

    def test_setitem_int_field(self):
        int_ft = bt2.SignedIntegerFieldType(32)
        int_field = _create_field(int_ft)
        int_field.value = 19487
        self._def[1] = int_field
        self.assertEqual(self._def[1], 19487)

    def test_setitem_non_basic_field(self):
        array_field = _create_struct_array_field(2)
        with self.assertRaises(TypeError):
            array_field[1] = 23

    def test_setitem_none(self):
        with self.assertRaises(TypeError):
            self._def[1] = None

    def test_setitem_index_wrong_type(self):
        with self.assertRaises(TypeError):
            self._def['yes'] = 23

    def test_setitem_index_neg(self):
        with self.assertRaises(IndexError):
            self._def[-2] = 23

    def test_setitem_index_out_of_range(self):
        with self.assertRaises(IndexError):
            self._def[len(self._def)] = 134679

    def test_iter(self):
        for field, value in zip(self._def, (45, 1847, 1948754)):
            self.assertEqual(field, value)

    def test_value_int_field(self):
        values = [45646, 145, 12145]
        self._def.value = values
        self.assertEqual(values, self._def)

    def test_value_check_sequence(self):
        values = 42
        with self.assertRaises(TypeError):
            self._def.value = values

    def test_value_wrong_type_in_sequence(self):
        values = [32, 'hello', 11]
        with self.assertRaises(TypeError):
            self._def.value = values

    def test_value_complex_type(self):
        struct_ft = bt2.StructureFieldType()
        int_ft = bt2.SignedIntegerFieldType(32)
        another_int_ft = bt2.SignedIntegerFieldType(32)
        str_ft = bt2.StringFieldType()
        struct_ft.append_field(field_type=int_ft, name='an_int')
        struct_ft.append_field(field_type=str_ft, name='a_string')
        struct_ft.append_field(field_type=another_int_ft, name='another_int')
        array_ft = bt2.StaticArrayFieldType(struct_ft, 3)
        stream = _create_stream([('array_field', array_ft)])
        values = [
            {
                'an_int': 42,
                'a_string': 'hello',
                'another_int': 66
            },
            {
                'an_int': 1,
                'a_string': 'goodbye',
                'another_int': 488
            },
            {
                'an_int': 156,
                'a_string': 'or not',
                'another_int': 4648
            },
        ]

        array = stream.create_packet().context_field['array_field']
        array.value = values
        self.assertEqual(values, array)
        values[0]['an_int'] = 'a string'
        with self.assertRaises(TypeError):
            array.value = values

    def test_str_op(self):
        s = str(self._def)
        expected_string = '[{}]'.format(', '.join(
            [repr(v) for v in self._def_value]))
        self.assertEqual(expected_string, s)


class StaticArrayFieldTestCase(_TestArraySequenceFieldCommon, unittest.TestCase):
    def setUp(self):
        self._def = _create_int_array_field(3)
        self._def[0] = 45
        self._def[1] = 1847
        self._def[2] = 1948754
        self._def_value = [45, 1847, 1948754]

    def tearDown(self):
        del self._def

    def test_value_wrong_len(self):
        values = [45, 1847]
        with self.assertRaises(ValueError):
            self._def.value = values


class DynamicArrayFieldTestCase(_TestArraySequenceFieldCommon, unittest.TestCase):
    def setUp(self):
        self._def = _create_dynamic_array()
        self._def[0] = 45
        self._def[1] = 1847
        self._def[2] = 1948754
        self._def_value = [45, 1847, 1948754]

    def tearDown(self):
        del self._def

    def test_value_resize(self):
        new_values = [1, 2, 3, 4]
        self._def.value = new_values
        self.assertCountEqual(self._def, new_values)


class StructureFieldTestCase(unittest.TestCase):
    def _create_ft(self):
        ft = bt2.StructureFieldType()
        ft.append_field('A', self._ft0_fn())
        ft.append_field('B', self._ft1_fn())
        ft.append_field('C', self._ft2_fn())
        ft.append_field('D', self._ft3_fn())
        ft.append_field('E', self._ft4_fn())
        return ft

    def setUp(self):
        self._ft0_fn = bt2.SignedIntegerFieldType
        self._ft1_fn = bt2.StringFieldType
        self._ft2_fn = bt2.RealFieldType
        self._ft3_fn = bt2.SignedIntegerFieldType
        self._ft4_fn = bt2.StructureFieldType

        self._ft = self._create_ft()
        self._def = _create_field(self._ft)
        self._def['A'] = -1872
        self._def['B'] = 'salut'
        self._def['C'] = 17.5
        self._def['D'] = 16497
        self._def['E'] = {}
        self._def_value = {
            'A': -1872,
            'B': 'salut',
            'C': 17.5,
            'D': 16497,
            'E': {}
        }

    def tearDown(self):
        del self._def

    def _modify_def(self):
        self._def['B'] = 'hola'

    def test_bool_op_true(self):
        self.assertTrue(self._def)

    def test_bool_op_false(self):
        field = self._def['E']
        self.assertFalse(field)

    def test_len(self):
        self.assertEqual(len(self._def), 5)

    def test_getitem(self):
        field = self._def['A']
        self.assertIs(type(field), bt2.fields._SignedIntegerField)
        self.assertEqual(field, -1872)

    def test_at_index_out_of_bounds_after(self):
        with self.assertRaises(IndexError):
            self._def.at_index(len(self._def_value))

    def test_eq(self):
        field = _create_field(self._create_ft())
        field['A'] = -1872
        field['B'] = 'salut'
        field['C'] = 17.5
        field['D'] = 16497
        self.assertEqual(self._def, field)

    def test_eq_invalid_type(self):
        self.assertNotEqual(self._def, 23)

    def test_eq_diff_len(self):
        ft = bt2.StructureFieldType()
        ft.append_field('A', self._ft0_fn())
        ft.append_field('B', self._ft1_fn())
        ft.append_field('C', self._ft2_fn())

        field = _create_field(ft)
        field['A'] = -1872
        field['B'] = 'salut'
        field['C'] = 17.5
        self.assertNotEqual(self._def, field)

    def test_eq_diff_content_same_len(self):
        field = _create_field(self._create_ft())
        field['A'] = -1872
        field['B'] = 'salut'
        field['C'] = 17.4
        field['D'] = 16497
        self.assertNotEqual(self._def, field)

    def test_eq_same_content_diff_keys(self):
        ft = bt2.StructureFieldType()
        ft.append_field('A', self._ft0_fn())
        ft.append_field('B', self._ft1_fn())
        ft.append_field('E', self._ft2_fn())
        ft.append_field('D', self._ft3_fn())
        ft.append_field('C', self._ft4_fn())
        field = _create_field(ft)
        field['A'] = -1872
        field['B'] = 'salut'
        field['E'] = 17.5
        field['D'] = 16497
        field['C'] = {}
        self.assertNotEqual(self._def, field)

    def test_setitem(self):
        self._def['C'] = -18.47
        self.assertEqual(self._def['C'], -18.47)

    def test_setitem_int_field(self):
        int_ft = bt2.SignedIntegerFieldType(32)
        int_field = _create_field(int_ft)
        int_field.value = 19487
        self._def['D'] = int_field
        self.assertEqual(self._def['D'], 19487)

    def test_setitem_non_basic_field(self):
        elem_ft = bt2.StructureFieldType()
        struct_ft = bt2.StructureFieldType()
        struct_ft.append_field('A', elem_ft)
        struct_field = _create_field(struct_ft)

        # Will fail on access to .items() of the value
        with self.assertRaises(AttributeError):
            struct_field['A'] = 23

    def test_setitem_none(self):
        with self.assertRaises(TypeError):
            self._def['C'] = None

    def test_setitem_key_wrong_type(self):
        with self.assertRaises(TypeError):
            self._def[3] = 23

    def test_setitem_wrong_key(self):
        with self.assertRaises(KeyError):
            self._def['hi'] = 134679

    def test_at_index(self):
        self.assertEqual(self._def.at_index(1), 'salut')

    def test_iter(self):
        orig_values = {
            'A': -1872,
            'B': 'salut',
            'C': 17.5,
            'D': 16497,
            'E': {},
        }

        for vkey, vval in self._def.items():
            val = orig_values[vkey]
            self.assertEqual(vval, val)

    def test_value(self):
        orig_values = {
            'A': -1872,
            'B': 'salut',
            'C': 17.5,
            'D': 16497,
            'E': {},
        }
        self.assertEqual(self._def, orig_values)

    def test_set_value(self):
        int_ft = bt2.SignedIntegerFieldType(32)
        another_int_ft = bt2.SignedIntegerFieldType(32)
        str_ft = bt2.StringFieldType()
        struct_ft = bt2.StructureFieldType()
        struct_ft.append_field(field_type=int_ft, name='an_int')
        struct_ft.append_field(field_type=str_ft, name='a_string')
        struct_ft.append_field(field_type=another_int_ft, name='another_int')
        values = {
            'an_int': 42,
            'a_string': 'hello',
            'another_int': 66
        }

        struct = _create_field(struct_ft)
        struct.value = values
        self.assertEqual(values, struct)

        bad_type_values = copy.deepcopy(values)
        bad_type_values['an_int'] = 'a string'
        with self.assertRaises(TypeError):
            struct.value = bad_type_values

        unknown_key_values = copy.deepcopy(values)
        unknown_key_values['unknown_key'] = 16546
        with self.assertRaises(KeyError):
            struct.value = unknown_key_values

    def test_str_op(self):
        expected_string_found = False
        s = str(self._def)
        # Establish all permutations of the three expected matches since
        # the order in which mappings are enumerated is not explicitly part of
        # the API.
        for p in itertools.permutations([(k, v) for k, v in self._def.items()]):
            items = ['{}: {}'.format(repr(k), repr(v)) for k, v in p]
            candidate = '{{{}}}'.format(', '.join(items))
            if candidate == s:
                expected_string_found = True
                break

        self.assertTrue(expected_string_found)


class VariantFieldTestCase(unittest.TestCase):
    def _create_ft(self):
        selector_ft = bt2.SignedEnumerationFieldType(range=32)
        selector_ft.map_range('corner', 23)
        selector_ft.map_range('zoom', 17, 20)
        selector_ft.map_range('mellotron', 1001)
        selector_ft.map_range('giorgio', 2000, 3000)

        ft0 = bt2.SignedIntegerFieldType(32)
        ft1 = bt2.StringFieldType()
        ft2 = bt2.RealFieldType()
        ft3 = bt2.SignedIntegerFieldType(17)

        ft = bt2.VariantFieldType()
        ft.append_field('corner', ft0)
        ft.append_field('zoom', ft1)
        ft.append_field('mellotron', ft2)
        ft.append_field('giorgio', ft3)
        ft.selector_field_type = selector_ft

        top_ft = bt2.StructureFieldType()
        top_ft.append_field('selector_field', selector_ft)
        top_ft.append_field('variant_field', ft)
        return top_ft

    def setUp(self):
       self._def = _create_field(self._create_ft())['variant_field']

    def tearDown(self):
        del self._def

    def test_selected_field(self):
        self._def.selected_index = 2
        self._def.value = -17.34
        self.assertEqual(self._def.field(), -17.34)
        self.assertEqual(self._def.selected_field, -17.34)

        self._def.selected_index = 3
        self._def.value = 1921
        self.assertEqual(self._def.field(), 1921)
        self.assertEqual(self._def.selected_field, 1921)

    def test_eq(self):
        field = _create_field(self._create_ft())['variant_field']
        field.selected_index = 0
        field.value = 1774
        self._def.selected_index = 0
        self._def.value = 1774
        self.assertEqual(self._def, field)

    def test_eq_invalid_type(self):
        self._def.selected_index = 1
        self._def.value = 'gerry'
        self.assertNotEqual(self._def, 23)

    def test_str_op_int(self):
        field = _create_field(self._create_ft())['variant_field']
        field.selected_index = 0
        field.value = 1774
        other_field = _create_field(self._create_ft())['variant_field']
        other_field.selected_index = 0
        other_field.value = 1774
        self.assertEqual(str(field), str(other_field))

    def test_str_op_str(self):
        field = _create_field(self._create_ft())['variant_field']
        field.selected_index = 1
        field.value = 'un beau grand bateau'
        other_field = _create_field(self._create_ft())['variant_field']
        other_field.selected_index = 1
        other_field.value = 'un beau grand bateau'
        self.assertEqual(str(field), str(other_field))

    def test_str_op_flt(self):
        field = _create_field(self._create_ft())['variant_field']
        field.selected_index = 2
        field.value = 14.4245
        other_field = _create_field(self._create_ft())['variant_field']
        other_field.selected_index = 2
        other_field.value = 14.4245
        self.assertEqual(str(field), str(other_field))
