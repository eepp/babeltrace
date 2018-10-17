from bt2 import values
import unittest
import uuid
import bt2


class TraceTestCase(unittest.TestCase):
    def setUp(self):
        self._trace = bt2.Trace()

    def tearDown(self):
        del self._trace

    def test_create_default(self):
        self.assertEqual(len(self._trace), 0)

    def test_create_full(self):
        header_ft = bt2.StructureFieldType()
        header_ft.append_field('magic', bt2.SignedIntegerFieldType(32))

        trace_uuid = uuid.UUID('da7d6b6f-3108-4706-89bd-ab554732611b')
        tc = bt2.Trace(name='my name', uuid=trace_uuid,
                       env={'the_string': 'value', 'the_int': 23},
                       packet_header_field_type=header_ft,
                       automatic_stream_class_id=True)

        sc = tc.create_stream_class()

        self.assertEqual(tc.name, 'my name')
        self.assertEqual(tc.uuid, trace_uuid)
        self.assertEqual(tc.env['the_string'], 'value')
        self.assertEqual(tc.env['the_int'], 23)
        self.assertEqual(tc[sc.id]._ptr, sc._ptr)

    def test_create_no_uuid(self):
        tc = bt2.Trace()
        self.assertIsNone(tc.uuid)

    def test_assign_invalid_name(self):
        with self.assertRaises(TypeError):
            self._trace.name = 17

    def test_assign_static(self):
        self._trace.make_static()
        self.assertTrue(self._trace.is_static)

    def test_assign_packet_header_field_type(self):
        header_ft = bt2.StructureFieldType()
        header_ft.append_field('magic', bt2.SignedIntegerFieldType(32))
        self._trace.packet_header_field_type = header_ft
        self.assertEqual(self._trace.packet_header_field_type.addr, header_ft.addr)

    def test_assign_no_packet_header_field_type(self):
        self.assertIsNone(self._trace.packet_header_field_type)

    def test_getitem(self):
        trace = bt2.Trace(automatic_stream_class_id=False)
        trace.create_stream_class(id=12)
        trace.create_stream_class(id=54)
        sc = trace.create_stream_class(id=2018)
        self.assertEqual(trace[2018].addr, sc.addr)

    def test_getitem_wrong_key_type(self):
        self._trace.create_stream_class()
        with self.assertRaises(TypeError):
            self._trace['hello']

    def test_getitem_wrong_key(self):
        self._trace.create_stream_class()
        with self.assertRaises(KeyError):
            self._trace[4]

    def test_len(self):
        self.assertEqual(len(self._trace), 0)
        self._trace.create_stream_class()
        self.assertEqual(len(self._trace), 1)

    def test_create_auto_event_class_id(self):
        trace = bt2.Trace()
        sc1 = trace.create_stream_class(automatic_event_class_id=False)
        self.assertFalse(sc1.assigns_automatic_event_class_id)

    def test_create_auto_stream_id(self):
        trace = bt2.Trace()
        sc1 = trace.create_stream_class(automatic_stream_id=False)
        self.assertFalse(sc1.assigns_automatic_stream_id)

    def test_iter(self):
        trace = bt2.Trace(automatic_stream_class_id=False)
        sc1 = trace.create_stream_class(id=12)
        sc2 = trace.create_stream_class(id=54)
        sc3 = trace.create_stream_class(id=2018)

        for sid, stream_class in trace.items():
            self.assertIsInstance(stream_class, bt2.stream_class._StreamClass)

            if sid == 12:
                self.assertEqual(stream_class.addr, sc1.addr)
            elif sid == 54:
                self.assertEqual(stream_class.addr, sc2.addr)
            elif sid == 2018:
                self.assertEqual(stream_class.addr, sc3.addr)

    def test_env_getitem_wrong_key(self):
        trace = bt2.Trace(env={'the_string': 'value', 'the_int': 23})
        with self.assertRaises(KeyError):
            trace.env['lel']


    def test_streams_none(self):
        self.assertEqual(len(self._trace.streams), 0)

    def test_streams_len(self):
        trace = bt2.Trace(automatic_stream_class_id=False)
        sc = trace.create_stream_class(id=12)

        stream0 = sc()
        stream1 = sc()
        stream2 = sc()
        self.assertEqual(len(trace.streams), 3)

    def test_streams_iter(self):
        sc = self._trace.create_stream_class()
        sc.assigns_automatic_stream_id = False
        stream0 = sc(id=12)
        stream1 = sc(id=15)
        stream2 = sc(id=17)

        sids = set()

        for stream in self._trace.streams:
            sids.add(stream.id)

        self.assertEqual(len(sids), 3)
        self.assertTrue(12 in sids and 15 in sids and 17 in sids)

    def test_create_stream_class_full(self):
        event_header_ft = bt2.StructureFieldType()
        event_header_ft.append_field('magic', bt2.SignedIntegerFieldType(32))

        packet_context_ft = bt2.StructureFieldType()
        packet_context_ft.append_field('magic', bt2.SignedIntegerFieldType(32))

        event_common_context_ft = bt2.StructureFieldType()
        event_common_context_ft.append_field('magic', bt2.SignedIntegerFieldType(32))
        cc = bt2.ClockClass()
        trace = bt2.Trace(automatic_stream_class_id=False)
        sc = trace.create_stream_class(id=12,
                event_header_ft=event_header_ft,
                packet_context_ft=packet_context_ft,
                event_common_context_ft=event_common_context_ft,
                default_clock_class=cc,
                default_clock_always_known=True,
                packets_have_discarded_event_counter_snapshot=False,
                packets_have_packet_counter_snapshot=False,
                packets_have_default_beginning_clock_value=False,
                packets_have_default_end_clock_value=False,
                automatic_event_class_id=False,
                automatic_stream_id=False)

        self.assertEqual(sc.event_header_field_type.addr, event_header_ft.addr)
        self.assertEqual(sc.packet_context_field_type.addr, packet_context_ft.addr)
        self.assertEqual(sc.event_common_context_field_type.addr, event_common_context_ft.addr)
        self.assertEqual(sc.default_clock_class.addr, cc.addr)
        self.assertTrue(sc.default_clock_always_known)
        self.assertFalse(sc.packets_have_discarded_event_counter_snapshot)
        self.assertFalse(sc.packets_have_packet_counter_snapshot)
        self.assertFalse(sc.packets_have_default_beginning_clock_value)
        self.assertFalse(sc.packets_have_default_end_clock_value)
        self.assertFalse(sc.assigns_automatic_event_class_id)
        self.assertFalse(sc.assigns_automatic_stream_id)

