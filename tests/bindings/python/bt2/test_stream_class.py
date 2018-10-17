from bt2 import values
import unittest
import bt2


class StreamClassTestCase(unittest.TestCase):
    def setUp(self):
        self._packet_context_ft = bt2.StructureFieldType()
        self._packet_context_ft.append_field('menu', bt2.RealFieldType())
        self._packet_context_ft.append_field('sticker', bt2.StringFieldType())
        self._event_header_ft = bt2.StructureFieldType()
        self._event_header_ft.append_field('id', bt2.UnsignedIntegerFieldType(19))
        self._event_common_context_ft = bt2.StructureFieldType()
        self._event_common_context_ft.append_field('msg', bt2.StringFieldType())

        self._trace = bt2.Trace(automatic_stream_class_id=False)

        self._sc = self._trace.create_stream_class(id=12)
        self._sc.name='my_stream_class'
        self._sc.packet_context_field_type=self._packet_context_ft
        self._sc.event_header_field_type=self._event_header_ft
        self._sc.event_common_context_field_type=self._event_common_context_ft
        self._sc.assigns_automatic_event_class_id = False


        context_ft = bt2.StructureFieldType()
        context_ft.append_field('allo', bt2.StringFieldType())
        context_ft.append_field('zola', bt2.UnsignedIntegerFieldType(18))
        payload_ft = bt2.StructureFieldType()
        payload_ft.append_field('zoom', bt2.StringFieldType())

        self._ec1 = self._sc.create_event_class(id=23)
        self._ec1.context_field_type = context_ft
        self._ec1.payload_field_type = payload_ft

        self._ec2 = self._sc.create_event_class(id=17)
        self._ec2.context_field_type = payload_ft
        self._ec2.payload_field_type = context_ft

    def tearDown(self):
        del self._packet_context_ft
        del self._event_header_ft
        del self._event_common_context_ft
        del self._ec1
        del self._ec2
        del self._sc

    def test_create(self):
        self.assertEqual(self._sc.name, 'my_stream_class')
        self.assertEqual(self._sc.id, 12)
        self.assertEqual(self._sc.packet_context_field_type.addr, self._packet_context_ft.addr)
        self.assertEqual(self._sc.event_header_field_type.addr, self._event_header_ft.addr)
        self.assertEqual(self._sc.event_common_context_field_type.addr, self._event_common_context_ft.addr)
        self.assertEqual(self._sc[23]._ptr, self._ec1._ptr)
        self.assertEqual(self._sc[17]._ptr, self._ec2._ptr)
        self.assertEqual(len(self._sc), 2)

    def test_assign_name(self):
        sc = self._trace.create_stream_class(id=14)
        sc.name = 'lel'
        self.assertEqual(sc.name, 'lel')

    def test_automatic_ids(self):
        sc = self._trace.create_stream_class(id=14, automatic_stream_id=True, automatic_event_class_id=True)
        ec = sc.create_event_class()
        stream = sc()
        self.assertIsNotNone(ec.id)
        self.assertIsNotNone(stream.id)

    def test_no_automatic_ids(self):
        sc = self._trace.create_stream_class(id=14, automatic_stream_id=False, automatic_event_class_id=False)
        ec = sc.create_event_class(id=121)
        stream = sc(id=0x1112)
        self.assertIsNotNone(ec.id)
        self.assertIsNotNone(stream.id)

    def test_assign_invalid_name(self):
        sc = self._trace.create_stream_class(id=14)
        with self.assertRaises(TypeError):
            sc.name = 17

    def test_assign_id(self):
        sc = self._trace.create_stream_class(id=1717)
        self.assertEqual(sc.id, 1717)

    def test_assign_invalid_id(self):
        with self.assertRaises(TypeError):
            sc = self._trace.create_stream_class(id='lel')

    def test_default_clock_class(self):
        cc = bt2.ClockClass()
        sc = self._trace.create_stream_class(id=1717)
        sc.default_clock_class = cc
        self.assertEqual(sc.default_clock_class.addr, cc.addr)

    def test_no_default_clock_class(self):
        sc = self._trace.create_stream_class(id=1717)
        self.assertIsNone(sc.default_clock_class)

    def test_clock_always_known(self):
        cc = bt2.ClockClass()
        sc = self._trace.create_stream_class(id=1717)
        sc.default_clock_class = cc
        self.assertTrue(sc.default_clock_always_known)

    def test_assign_packet_context_field_type(self):
        ft = bt2.StructureFieldType()
        ft.append_field('champ', bt2.UnsignedIntegerFieldType(19))
        sc = self._trace.create_stream_class(id=1717)
        sc.packet_context_field_type = ft
        self.assertEqual(sc.packet_context_field_type.addr, ft.addr)

    def test_assign_no_packet_context_field_type(self):
        sc = self._trace.create_stream_class(id=1717)
        self.assertIsNone(sc.packet_context_field_type)

    def test_assign_event_header_field_type(self):
        ft = bt2.StructureFieldType()
        ft.append_field('champ', bt2.UnsignedIntegerFieldType(19))
        sc = self._trace.create_stream_class(id=1717)
        sc.event_header_field_type = ft
        self.assertEqual(sc.event_header_field_type.addr, ft.addr)

    def test_assign_no_event_header_field_type(self):
        sc = self._trace.create_stream_class(id=1717)
        self.assertIsNone(sc.event_header_field_type)

    def test_assign_event_common_context_field_type(self):
        ft = bt2.StructureFieldType()
        ft.append_field('champ', bt2.UnsignedIntegerFieldType(19))
        sc = self._trace.create_stream_class(id=1717)
        sc.event_common_context_field_type = ft
        self.assertEqual(sc.event_common_context_field_type.addr, ft.addr)

    def test_assign_no_event_common_context_field_type(self):
        sc = self._trace.create_stream_class(id=1717)
        self.assertIsNone(sc.event_common_context_field_type)

    def test_trace_prop(self):
        tc = bt2.Trace()
        sc = tc.create_stream_class()
        self.assertEqual(sc.trace.addr, tc.addr)

    def test_getitem(self):
        self.assertEqual(self._sc[23]._ptr, self._ec1._ptr)
        self.assertEqual(self._sc[17]._ptr, self._ec2._ptr)

    def test_getitem_wrong_key_type(self):
        with self.assertRaises(TypeError):
            self._sc['event23']

    def test_getitem_wrong_key(self):
        with self.assertRaises(KeyError):
            self._sc[19]

    def test_len(self):
        self.assertEqual(len(self._sc), 2)

    def test_iter(self):
        for ec_id, event_class in self._sc.items():
            self.assertIsInstance(event_class, bt2.event_class._EventClass)

            if ec_id == 23:
                self.assertEqual(event_class._ptr, self._ec1._ptr)
            elif ec_id == 17:
                self.assertEqual(event_class._ptr, self._ec2._ptr)

    def test_counter_snapshots(self):
        sc = self._trace.create_stream_class(id=1717,
                packets_have_packet_counter_snapshot=True,
                packets_have_discarded_event_counter_snapshot=True)
        
        self.assertTrue(sc.packets_have_packet_counter_snapshot)
        self.assertTrue(sc.packets_have_discarded_event_counter_snapshot)

    def test_default_clock_values(self):
        cc = bt2.ClockClass()
        sc = self._trace.create_stream_class(id=1717,
                default_clock_class=cc,
                packets_have_default_beginning_clock_value=True,
                packets_have_default_end_clock_value=True)

        self.assertTrue(sc.packets_have_default_beginning_clock_value)
        self.assertTrue(sc.packets_have_default_end_clock_value)
