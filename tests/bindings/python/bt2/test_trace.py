from bt2 import values
import unittest
import uuid
import bt2


class TraceTestCase(unittest.TestCase):
    def setUp(self):
        self._sc = self._create_stream_class('sc1', 3)
        self._tc = bt2.Trace()

    def tearDown(self):
        del self._sc
        del self._tc

    def _create_stream_class(self, name, id):
        ec1, ec2 = self._create_event_classes()
        packet_context_ft = bt2.StructureFieldType()
        packet_context_ft.append_field('menu', bt2.FloatingPointNumberFieldType())
        packet_context_ft.append_field('sticker', bt2.StringFieldType())
        event_header_ft = bt2.StructureFieldType()
        event_header_ft.append_field('id', bt2.IntegerFieldType(19))
        event_context_ft = bt2.StructureFieldType()
        event_context_ft.append_field('msg', bt2.StringFieldType())
        return bt2.StreamClass(name=name, id=id,
                               packet_context_field_type=packet_context_ft,
                               event_header_field_type=event_header_ft,
                               event_context_field_type=event_context_ft,
                               event_classes=(ec1, ec2))

    def _create_event_classes(self):
        context_ft = bt2.StructureFieldType()
        context_ft.append_field('allo', bt2.StringFieldType())
        context_ft.append_field('zola', bt2.IntegerFieldType(18))
        payload_ft = bt2.StructureFieldType()
        payload_ft.append_field('zoom', bt2.StringFieldType())
        ec1 = bt2.EventClass('event23', id=23, context_field_type=context_ft,
                             payload_field_type=payload_ft)
        ec2 = bt2.EventClass('event17', id=17, context_field_type=payload_ft,
                             payload_field_type=context_ft)
        return ec1, ec2

    def test_create_default(self):
        self.assertEqual(len(self._tc), 0)

    def _get_std_header(self):
        header_ft = bt2.StructureFieldType()
        header_ft.append_field('magic', bt2.IntegerFieldType(32))
        header_ft.append_field('stream_id', bt2.IntegerFieldType(32))
        return header_ft

    def test_create_full(self):
        clock_classes = bt2.ClockClass('cc1', 1000), bt2.ClockClass('cc2', 30)
        sc = self._create_stream_class('sc1', 3)
        tc = bt2.Trace(name='my name',
                       native_byte_order=bt2.ByteOrder.LITTLE_ENDIAN,
                       env={'the_string': 'value', 'the_int': 23},
                       packet_header_field_type=self._get_std_header(),
                       clock_classes=clock_classes,
                       stream_classes=(sc,))
        self.assertEqual(tc.name, 'my name')
        self.assertEqual(tc.native_byte_order, bt2.ByteOrder.LITTLE_ENDIAN)
        self.assertEqual(tc.env['the_string'], 'value')
        self.assertEqual(tc.env['the_int'], 23)
        self.assertEqual(tc.packet_header_field_type, self._get_std_header())
        self.assertEqual(tc.clock_classes['cc1']._ptr, clock_classes[0]._ptr)
        self.assertEqual(tc.clock_classes['cc2']._ptr, clock_classes[1]._ptr)
        self.assertEqual(tc[3]._ptr, sc._ptr)

    def test_assign_name(self):
        self._tc.name = 'lel'
        self.assertEqual(self._tc.name, 'lel')

    def test_assign_invalid_name(self):
        with self.assertRaises(TypeError):
            self._tc.name = 17

    def test_assign_static(self):
        self._tc.set_is_static()
        self.assertTrue(self._tc.is_static)

    def test_assign_native_byte_order(self):
        self._tc.native_byte_order = bt2.ByteOrder.BIG_ENDIAN
        self.assertEqual(self._tc.native_byte_order, bt2.ByteOrder.BIG_ENDIAN)

    def test_assign_invalid_native_byte_order(self):
        with self.assertRaises(TypeError):
            self._tc.native_byte_order = 'lel'

    def test_assign_packet_header_field_type(self):
        header_ft = bt2.StructureFieldType()
        header_ft.append_field('magic', bt2.IntegerFieldType(32))
        self._tc.packet_header_field_type = header_ft
        self.assertEqual(self._tc.packet_header_field_type, header_ft)

    def test_assign_no_packet_header_field_type(self):
        self._tc.packet_header_field_type = None
        self.assertIsNone(self._tc.packet_header_field_type)

    def test_getitem(self):
        self._tc.add_stream_class(self._sc)
        self.assertEqual(self._tc[3].addr, self._sc.addr)

    def test_getitem_wrong_key_type(self):
        self._tc.add_stream_class(self._sc)
        with self.assertRaises(TypeError):
            self._tc['hello']

    def test_getitem_wrong_key(self):
        self._tc.add_stream_class(self._sc)
        with self.assertRaises(KeyError):
            self._tc[4]

    def test_len(self):
        self.assertEqual(len(self._tc), 0)
        self._tc.add_stream_class(self._sc)
        self.assertEqual(len(self._tc), 1)

    def test_iter(self):
        self._tc.packet_header_field_type = self._get_std_header()
        sc1 = self._create_stream_class('sc1', 3)
        sc2 = self._create_stream_class('sc2', 9)
        sc3 = self._create_stream_class('sc3', 17)
        self._tc.add_stream_class(sc1)
        self._tc.add_stream_class(sc2)
        self._tc.add_stream_class(sc3)

        for sid, stream_class in self._tc.items():
            self.assertIsInstance(stream_class, bt2.StreamClass)

            if sid == 3:
                self.assertEqual(stream_class.addr, sc1.addr)
            elif sid == 9:
                self.assertEqual(stream_class.addr, sc2.addr)
            elif sid == 17:
                self.assertEqual(stream_class.addr, sc3.addr)

    def test_env_getitem_wrong_key(self):
        with self.assertRaises(KeyError):
            self._tc.env['lel']

    def test_clock_classes_getitem_wrong_key(self):
        with self.assertRaises(KeyError):
            self._tc.clock_classes['lel']

    def test_streams_none(self):
        self.assertEqual(len(self._tc.streams), 0)

    def test_streams_len(self):
        self._tc.add_stream_class(self._create_stream_class('sc1', 3))
        stream0 = self._tc[3](name='stream_0', id=0)
        stream1 = self._tc[3](name='stream_1', id=1)
        stream2 = self._tc[3](name='stream_2', id=2)
        self.assertEqual(len(self._tc.streams), 3)

    def test_streams_iter(self):
        self._tc.add_stream_class(self._create_stream_class('sc1', 3))
        stream0 = self._tc[3](name='stream_0', id=12)
        stream1 = self._tc[3](name='stream_1', id=15)
        stream2 = self._tc[3](name='stream_2', id=17)
        sids = set()

        for stream in self._tc.streams:
            sids.add(stream.id)

        self.assertEqual(len(sids), 3)
        self.assertTrue(12 in sids and 15 in sids and 17 in sids)
