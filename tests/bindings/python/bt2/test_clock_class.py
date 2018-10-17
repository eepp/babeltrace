import unittest
import uuid
import copy
import bt2
from collections import OrderedDict

#Raise "create a graph to generate event notification so we can change and test the clock value using the 
#Bt_event_set_clock_value"

class ClockClassOffsetTestCase(unittest.TestCase):
    def test_create_default(self):
        cco = bt2.ClockClassOffset()
        self.assertEqual(cco.seconds, 0)
        self.assertEqual(cco.cycles, 0)

    def test_create(self):
        cco = bt2.ClockClassOffset(23, 4871232)
        self.assertEqual(cco.seconds, 23)
        self.assertEqual(cco.cycles, 4871232)

    def test_create_kwargs(self):
        cco = bt2.ClockClassOffset(seconds=23, cycles=4871232)
        self.assertEqual(cco.seconds, 23)
        self.assertEqual(cco.cycles, 4871232)

    def test_create_invalid_seconds(self):
        with self.assertRaises(TypeError):
            bt2.ClockClassOffset('hello', 4871232)

    def test_create_invalid_cycles(self):
        with self.assertRaises(TypeError):
            bt2.ClockClassOffset(23, 'hello')

    def test_eq(self):
        cco1 = bt2.ClockClassOffset(23, 42)
        cco2 = bt2.ClockClassOffset(23, 42)
        self.assertEqual(cco1, cco2)

    def test_ne_seconds(self):
        cco1 = bt2.ClockClassOffset(23, 42)
        cco2 = bt2.ClockClassOffset(24, 42)
        self.assertNotEqual(cco1, cco2)

    def test_ne_cycles(self):
        cco1 = bt2.ClockClassOffset(23, 42)
        cco2 = bt2.ClockClassOffset(23, 43)
        self.assertNotEqual(cco1, cco2)

    def test_eq_invalid(self):
        self.assertFalse(bt2.ClockClassOffset() == 23)


class ClockClassTestCase(unittest.TestCase):
    def setUp(self):
        self._cc = bt2.ClockClass('salut', 1000000)

    def tearDown(self):
        del self._cc

    def test_create_default(self):
        self.assertEqual(self._cc.name, 'salut')

    def test_create_full(self):
        my_uuid = uuid.uuid1()
        cc = bt2.ClockClass(name='name', description='some description',
                            frequency=1001, precision=176,
                            offset=bt2.ClockClassOffset(45, 3),
                            is_absolute=True, uuid=my_uuid)
        self.assertEqual(cc.name, 'name')
        self.assertEqual(cc.description, 'some description')
        self.assertEqual(cc.frequency, 1001)
        self.assertEqual(cc.precision, 176)
        self.assertEqual(cc.offset, bt2.ClockClassOffset(45, 3))
        self.assertEqual(cc.is_absolute, True)
        self.assertEqual(cc.uuid, copy.deepcopy(my_uuid))

    def test_create_no_uuid(self):
        cc = bt2.ClockClass()
        self.assertIsNone(cc.uuid)

    def test_assign_name(self):
        self._cc.name = 'the_clock'
        self.assertEqual(self._cc.name, 'the_clock')

    def test_assign_invalid_name(self):
        with self.assertRaises(TypeError):
            self._cc.name = 23

    def test_assign_description(self):
        self._cc.description = 'hi people'
        self.assertEqual(self._cc.description, 'hi people')

    def test_assign_invalid_description(self):
        with self.assertRaises(TypeError):
            self._cc.description = 23

    def test_assign_frequency(self):
        self._cc.frequency = 987654321
        self.assertEqual(self._cc.frequency, 987654321)

    def test_assign_invalid_frequency(self):
        with self.assertRaises(TypeError):
            self._cc.frequency = 'lel'

    def test_assign_precision(self):
        self._cc.precision = 12
        self.assertEqual(self._cc.precision, 12)

    def test_assign_invalid_precision(self):
        with self.assertRaises(TypeError):
            self._cc.precision = 'lel'

    def test_assign_offset(self):
        self._cc.offset = bt2.ClockClassOffset(12, 56)
        self.assertEqual(self._cc.offset, bt2.ClockClassOffset(12, 56))

    def test_assign_invalid_offset(self):
        with self.assertRaises(TypeError):
            self._cc.offset = object()

    def test_assign_absolute(self):
        self._cc.is_absolute = True
        self.assertTrue(self._cc.is_absolute)

    def test_assign_not_absolute(self):
        self._cc.is_absolute = False
        self.assertFalse(self._cc.is_absolute)

    def test_assign_invalid_absolute(self):
        with self.assertRaises(TypeError):
            self._cc.is_absolute = 23

    def test_assign_uuid(self):
        the_uuid = uuid.uuid1()
        self._cc.uuid = the_uuid
        self.assertEqual(self._cc.uuid, the_uuid)

    def test_assign_invalid_uuid(self):
        with self.assertRaises(TypeError):
            self._cc.uuid = object()


class ClockValueTestCase(unittest.TestCase):
    def setUp(self):
        _cc = bt2.ClockClass('my_cc', 1000, offset=bt2.ClockClassOffset(45, 354))
        _trace = bt2.Trace()
        _sc = _trace.create_stream_class()
        _sc.default_clock_class = _cc
        _ec = _sc.create_event_class()
        _ec.name = 'salut'
        _stream = _sc()
        _packet = _stream.create_packet()
        self._packet = _packet
        self._stream = _stream
        self._ec = _ec
        self._cc = _cc

        class MyIter(bt2._UserNotificationIterator):
            def __init__(self):
                self._at = 0

            def __next__(self):
                if self._at == 0:
                    notif = self._create_stream_beginning_notification(_stream)
                elif self._at == 1:
                    notif = self._create_packet_beginning_notification(_packet)
                elif self._at == 2:
                    notif = self._create_event_notification(_ec, _packet)
                    notif.event.default_clock_value = 123
                elif self._at == 3:
                    notif = self._create_packet_end_notification(_packet)
                elif self._at == 4:
                    notif = self._create_stream_end_notification(_stream)
                else:
                    raise bt2.Stop

                self._at += 1
                return notif


        class MySrc(bt2._UserSourceComponent, notification_iterator_class=MyIter):
            def __init__(self, params):
                self._add_output_port('out')

        self._graph = bt2.Graph()
        self._src_comp = self._graph.add_component(MySrc, 'my_source')
        self._notif_iter = self._src_comp.output_ports['out'].create_notification_iterator()

        for i, notif in enumerate(self._notif_iter):
            if i == 2:
                self._cv = notif.event.default_clock_value
                break

    def tearDown(self):
        del self._cc
        del self._cv

    def test_create_default(self):
        self.assertEqual(self._cv.clock_class.addr, self._cc.addr)
        self.assertEqual(self._cv.cycles, 123)

    def test_clock_class(self):
        self.assertEqual(self._cv.clock_class.addr, self._cc.addr)

    def test_create_invalid_cycles_type(self):
        with self.assertRaises(TypeError):
            self._cc('yes')

    def test_ns_from_origin(self):
        s_from_origin = 45 + ((354 + 123) / 1000)
        ns_from_origin = int(s_from_origin * 1e9)
        self.assertEqual(self._cv.ns_from_origin, ns_from_origin)

    def test_eq_int(self):
        self.assertEqual(self._cv, 123)

    def test_eq_invalid(self):
        self.assertFalse(self._cv == 23)
