# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2019 EfficiOS Inc.
#

# pyright: strict, reportPrivateUsage=false

import uuid
import typing
import unittest

import bt2
from bt2 import value as bt2_value
from bt2 import clock_class as bt2_clock_class
from utils import (
    TestOutputPortMessageIterator,
    run_in_component_init,
    get_const_event_message,
)
from test_all_mip_versions import test_all_mip_versions


class ClockOffsetTestCase(unittest.TestCase):
    def test_create_default(self):
        cco = bt2.ClockOffset()
        self.assertEqual(cco.seconds, 0)
        self.assertEqual(cco.cycles, 0)

    def test_create(self):
        cco = bt2.ClockOffset(23, 4871232)
        self.assertEqual(cco.seconds, 23)
        self.assertEqual(cco.cycles, 4871232)

    def test_create_kwargs(self):
        cco = bt2.ClockOffset(seconds=23, cycles=4871232)
        self.assertEqual(cco.seconds, 23)
        self.assertEqual(cco.cycles, 4871232)

    def test_create_invalid_seconds(self):
        with self.assertRaises(TypeError):
            bt2.ClockOffset("hello", 4871232)  # type: ignore

    def test_create_invalid_cycles(self):
        with self.assertRaises(TypeError):
            bt2.ClockOffset(23, "hello")  # type: ignore

    def test_eq(self):
        cco1 = bt2.ClockOffset(23, 42)
        cco2 = bt2.ClockOffset(23, 42)
        self.assertEqual(cco1, cco2)

    def test_ne_seconds(self):
        cco1 = bt2.ClockOffset(23, 42)
        cco2 = bt2.ClockOffset(24, 42)
        self.assertNotEqual(cco1, cco2)

    def test_ne_cycles(self):
        cco1 = bt2.ClockOffset(23, 42)
        cco2 = bt2.ClockOffset(23, 43)
        self.assertNotEqual(cco1, cco2)

    def test_eq_invalid(self):
        self.assertFalse(bt2.ClockOffset() == 23)


RetT = typing.TypeVar("RetT")


@test_all_mip_versions
class ClockClassTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Big hack to make `_mip_version` known to static type checkers in a
        # Python 3.5 compatible way.
        cls._mip_version = -1
        del cls._mip_version

    def run_in_component_init(self, f: typing.Callable[[bt2._UserSinkComponent], RetT]):
        return run_in_component_init(self._mip_version, f)

    def assertRaisesInComponentInit(
        self,
        expected_exc_type: typing.Type[Exception],
        user_code: typing.Callable[[bt2._UserSinkComponent], RetT],
        expected_str: typing.Optional[str] = None,
    ):
        def f(comp_self: bt2._UserSinkComponent):
            try:
                user_code(comp_self)
            except Exception as exc:
                return exc

        exc = self.run_in_component_init(f)
        self.assertIsNotNone(exc)
        self.assertEqual(type(exc), expected_exc_type)

        if expected_str is not None:
            self.assertIn(expected_str, str(exc))

    def test_create_default(self):
        cc = run_in_component_init(
            self._mip_version, lambda comp_self: comp_self._create_clock_class()
        )

        self.assertIsNone(cc.name)
        self.assertEqual(cc.frequency, 1000000000)
        self.assertIsNone(cc.description)

        if self._mip_version == 0:
            self.assertEqual(cc.precision, 0)
        else:
            self.assertIsNone(cc.precision)
            self.assertIsNone(cc.accuracy)

        self.assertEqual(cc.offset, bt2.ClockOffset())
        self.assertIs(cc.origin, bt2.unix_epoch_clock_origin)

        if self._mip_version == 0:
            self.assertIsNone(cc.uuid)
        else:
            self.assertIsNone(cc.namespace)
            self.assertIsNone(cc.name)
            self.assertIsNone(cc.uid)

        self.assertEqual(len(cc.user_attributes), 0)

    def test_create_namespace(self):
        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(namespace="the_clock")

        if self._mip_version == 0:
            self.assertRaisesInComponentInit(
                ValueError,
                f,
                "Clock class namespace is only available with MIP version ≥ 1 (currently 0)",
            )
        else:
            self.assertEqual(self.run_in_component_init(f).namespace, "the_clock")

    def test_create_invalid_namespace(self):
        if self._mip_version < 1:
            self.skipTest("requires MIP >= 1")

        def f(comp_self: bt2._UserSinkComponent):
            comp_self._create_clock_class(namespace=23)  # type: ignore

        self.assertRaisesInComponentInit(TypeError, f, "'int' is not a 'str' object")

    def test_create_name(self):
        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(name="the_clock")

        cc = self.run_in_component_init(f)
        self.assertEqual(cc.name, "the_clock")

    def test_create_invalid_name(self):
        def f(comp_self: bt2._UserSinkComponent):
            comp_self._create_clock_class(name=23)  # type: ignore

        self.assertRaisesInComponentInit(TypeError, f)

    def test_create_uid(self):
        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(uid="the_clock")

        if self._mip_version == 0:
            self.assertRaisesInComponentInit(
                ValueError,
                f,
                "Clock class UID is only available with MIP version ≥ 1 (currently 0)",
            )
        else:
            self.assertEqual(self.run_in_component_init(f).uid, "the_clock")

    def test_create_invalid_uid(self):
        if self._mip_version < 1:
            self.skipTest("requires MIP >= 1")

        def f(comp_self: bt2._UserSinkComponent):
            comp_self._create_clock_class(uid=23)  # type: ignore

        self.assertRaisesInComponentInit(TypeError, f, "'int' is not a 'str' object")

    def test_create_description(self):
        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(description="hi people")

        cc = self.run_in_component_init(f)
        self.assertEqual(cc.description, "hi people")

    def test_create_invalid_description(self):
        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(description=23)  # type: ignore

        self.assertRaisesInComponentInit(TypeError, f)

    def test_create_frequency(self):
        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(frequency=987654321)

        cc = self.run_in_component_init(f)
        self.assertEqual(cc.frequency, 987654321)

    def test_create_invalid_frequency(self):
        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(frequency="lel")  # type: ignore

        self.assertRaisesInComponentInit(TypeError, f)

    def test_create_precision(self):
        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(precision=12)

        self.assertEqual(self.run_in_component_init(f).precision, 12)

    def test_create_accuracy(self):
        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(accuracy=12)

        if self._mip_version == 0:
            self.assertRaisesInComponentInit(
                ValueError,
                f,
                "Clock class accuracy is only available with MIP version ≥ 1 (currently 0)",
            )
        else:
            self.assertEqual(self.run_in_component_init(f).accuracy, 12)

    def test_create_invalid_precision(self):
        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(precision="lel")  # type: ignore

        self.assertRaisesInComponentInit(TypeError, f)

    def test_create_offset(self):
        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(offset=bt2.ClockOffset(12, 56))

        cc = self.run_in_component_init(f)
        self.assertEqual(cc.offset, bt2.ClockOffset(12, 56))

    def test_create_invalid_offset(self):
        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(offset=object())  # type: ignore

        self.assertRaisesInComponentInit(TypeError, f)

    def test_create_origin_is_unix_epoch_true(self):
        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(origin_is_unix_epoch=True)

        cc = self.run_in_component_init(f)
        self.assertIs(cc.origin, bt2.unix_epoch_clock_origin)

    def test_create_origin_is_unix_epoch_false(self):
        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(origin_is_unix_epoch=False)

        cc = self.run_in_component_init(f)
        self.assertIs(cc.origin, bt2.unknown_clock_origin)

    def test_create_invalid_origin_is_unix_epoch(self):
        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(origin_is_unix_epoch=23)  # type: ignore

        self.assertRaisesInComponentInit(TypeError, f)

    def test_create_unix_epoch_origin(self):
        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(origin=bt2.unix_epoch_clock_origin)

        cc = self.run_in_component_init(f)

        self.assertIs(cc.origin, bt2.unix_epoch_clock_origin)

    def test_create_custom_origin(self):
        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(
                origin=bt2.ClockOrigin("ns", "name", "uid")
            )

        if self._mip_version == 0:
            self.assertRaisesInComponentInit(
                ValueError,
                f,
                "Custom clock class origin is only available with MIP version ≥ 1 (currently 0)",
            )
        else:
            origin = self.run_in_component_init(f).origin

            assert type(origin) is bt2.ClockOrigin
            self.assertEqual(origin.namespace, "ns")
            self.assertEqual(origin.name, "name")
            self.assertEqual(origin.uid, "uid")

    def test_create_unknown_origin(self):
        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(origin=bt2.unknown_clock_origin)

        cc = self.run_in_component_init(f)

        self.assertIs(cc.origin, bt2.unknown_clock_origin)

    def test_create_invalid_origin(self):
        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(origin=23)  # type: ignore

        self.assertRaisesInComponentInit(
            TypeError,
            f,
            "'int' is not a '<class 'bt2.clock_class.ClockOrigin'>' object",
        )

    def test_create_multiple_origin(self):
        cases = (
            (True, bt2.ClockOrigin("ns", "name", "uid")),
            (False, bt2.ClockOrigin("ns", "name", "uid")),
        )

        for case in cases:
            origin_is_unix_epoch, origin = case

            class Foo:
                def __init__(
                    self,
                    origin_is_unix_epoch: typing.Optional[bool],
                    origin: typing.Optional[bt2.ClockOrigin],
                ):
                    self.origin_is_unix_epoch = origin_is_unix_epoch
                    self.origin = origin

                def __call__(self, comp_self: bt2._UserSinkComponent):
                    return comp_self._create_clock_class(
                        origin_is_unix_epoch=self.origin_is_unix_epoch,
                        origin=self.origin,
                    )

            self.assertRaisesInComponentInit(
                ValueError,
                Foo(origin_is_unix_epoch, origin),
                "only one of `origin_is_unix_epoch` and `origin` can be set",
            )

    def test_cycles_to_ns_from_origin(self):
        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(
                frequency=10**8, origin_is_unix_epoch=True
            )

        cc = self.run_in_component_init(f)
        self.assertEqual(cc.cycles_to_ns_from_origin(112), 1120)

    def test_cycles_to_ns_from_origin_overflow(self):
        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(frequency=1000)

        cc = self.run_in_component_init(f)
        with self.assertRaises(bt2._OverflowError):
            cc.cycles_to_ns_from_origin(2**63)

    def test_create_uuid(self):
        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(
                uuid=uuid.UUID("b43372c32ef0be28444dfc1c5cdafd33")
            )

        if self._mip_version == 0:
            self.assertEqual(
                self.run_in_component_init(f).uuid,
                uuid.UUID("b43372c32ef0be28444dfc1c5cdafd33"),
            )
        else:
            self.assertRaisesInComponentInit(
                ValueError,
                f,
                "Clock class UUID is only available with MIP version 0 (currently 1)",
            )

    def test_create_invalid_uuid(self):
        if self._mip_version != 0:
            self.skipTest("requires MIP == 0")

        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(uuid=23)  # type: ignore

        self.assertRaisesInComponentInit(TypeError, f)

    def test_create_user_attributes(self):
        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(user_attributes={"salut": 23})

        cc = self.run_in_component_init(f)
        self.assertEqual(cc.user_attributes, {"salut": 23})
        self.assertIs(type(cc.user_attributes), bt2_value.MapValue)

    def test_const_user_attributes(self):
        cc = get_const_event_message().default_clock_snapshot.clock_class
        self.assertEqual(cc.user_attributes, {"a-clock-class-attribute": 1})
        self.assertIs(type(cc.user_attributes), bt2._MapValueConst)

    def test_create_invalid_user_attributes(self):
        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(user_attributes=object())  # type: ignore

        self.assertRaisesInComponentInit(TypeError, f)

    def test_create_invalid_user_attributes_value_type(self):
        def f(comp_self: bt2._UserSinkComponent):
            return comp_self._create_clock_class(user_attributes=23)  # type: ignore

        self.assertRaisesInComponentInit(TypeError, f)


class ClockSnapshotTestCase(unittest.TestCase):
    def run_in_component_init(self, f: typing.Callable[[bt2._UserSinkComponent], RetT]):
        return run_in_component_init(0, f)

    def setUp(self):
        def f(comp_self: bt2._UserSinkComponent):
            cc = comp_self._create_clock_class(
                1000, "my_cc", offset=bt2.ClockOffset(45, 354)
            )
            tc = comp_self._create_trace_class()

            return (cc, tc)

        _cc, _tc = self.run_in_component_init(f)
        _trace = _tc()
        _sc = _tc.create_stream_class(default_clock_class=_cc)
        _ec = _sc.create_event_class(name="salut")
        _stream = _trace.create_stream(_sc)
        self._stream = _stream
        self._ec = _ec
        self._cc = _cc

        class MyIter(bt2._UserMessageIterator):
            def __init__(
                self,
                config: bt2._MessageIteratorConfiguration,
                self_port_output: bt2._UserComponentOutputPort,
            ):
                self._at = 0

            def __next__(self):
                if self._at == 0:
                    notif = self._create_stream_beginning_message(_stream)
                elif self._at == 1:
                    notif = self._create_event_message(_ec, _stream, 123)
                elif self._at == 2:
                    notif = self._create_event_message(_ec, _stream, 2**63)
                elif self._at == 3:
                    notif = self._create_stream_end_message(_stream)
                else:
                    raise bt2.Stop

                self._at += 1
                return notif

        class MySrc(bt2._UserSourceComponent, message_iterator_class=MyIter):
            def __init__(
                self,
                config: bt2._UserSourceComponentConfiguration,
                params: bt2._MapValueConst,
                obj: object,
            ):
                self._add_output_port("out")

        self._graph = bt2.Graph()
        self._src_comp = self._graph.add_component(MySrc, "my_source")
        self._msg_iter = TestOutputPortMessageIterator(
            self._graph, self._src_comp.output_ports["out"]
        )

        for i, msg in enumerate(self._msg_iter):
            if i == 1:
                assert type(msg) is bt2._EventMessageConst
                self._msg = msg
            elif i == 2:
                assert type(msg) is bt2._EventMessageConst
                self._msg_clock_overflow = msg
                break

    def tearDown(self):
        del self._cc
        del self._msg

    def test_create_default(self):
        self.assertEqual(
            self._msg.default_clock_snapshot.clock_class.addr, self._cc.addr
        )
        self.assertEqual(self._msg.default_clock_snapshot.value, 123)

    def test_clock_class(self):
        cc = self._msg.default_clock_snapshot.clock_class
        self.assertEqual(cc.addr, self._cc.addr)
        self.assertIs(type(cc), bt2_clock_class._ClockClassConst)

    def test_ns_from_origin(self):
        s_from_origin = 45 + ((354 + 123) / 1000)
        ns_from_origin = int(s_from_origin * 1e9)
        self.assertEqual(
            self._msg.default_clock_snapshot.ns_from_origin, ns_from_origin
        )

    def test_ns_from_origin_overflow(self):
        with self.assertRaises(bt2._OverflowError):
            self._msg_clock_overflow.default_clock_snapshot.ns_from_origin

    def test_eq_int(self):
        self.assertEqual(self._msg.default_clock_snapshot, 123)

    def test_eq_invalid(self):
        self.assertFalse(self._msg.default_clock_snapshot == 23)

    def test_comparison(self):
        self.assertTrue(self._msg.default_clock_snapshot > 100)
        self.assertFalse(self._msg.default_clock_snapshot > 200)

        self.assertTrue(self._msg.default_clock_snapshot >= 123)
        self.assertFalse(self._msg.default_clock_snapshot >= 200)

        self.assertTrue(self._msg.default_clock_snapshot < 200)
        self.assertFalse(self._msg.default_clock_snapshot < 100)

        self.assertTrue(self._msg.default_clock_snapshot <= 123)
        self.assertFalse(self._msg.default_clock_snapshot <= 100)


if __name__ == "__main__":
    unittest.main()
