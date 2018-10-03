from bt2 import values
import unittest
import copy
import bt2


class EventClassTestCase(unittest.TestCase):
    def setUp(self):
        self._context_ft = bt2.StructureFieldType()
        self._context_ft.append_field('allo', bt2.StringFieldType())
        self._context_ft.append_field('zola', bt2.SignedIntegerFieldType(18))
        self._payload_ft = bt2.StructureFieldType()
        self._payload_ft.append_field('zoom', bt2.StringFieldType())
        if self._payload_ft == None:
            print('allo')
        trace = bt2.Trace()
        self._stream_class = trace.create_stream_class()
        self._stream_class.assigns_automatic_event_class_id = False
        self._ec = self._stream_class.create_event_class(id=18)
        self._ec.name = 'my_event'

    def tearDown(self):
        del self._context_ft
        del self._payload_ft
        del self._ec

    def test_create(self):
        self._ec.emf_uri = 'yes'
        self._ec.log_level = bt2.EventClassLogLevel.INFO
        self._ec.specific_context_field_type = self._context_ft
        self._ec.payload_field_type = self._payload_ft

        self.assertEqual(self._ec.name, 'my_event')
        self.assertEqual(self._ec.id, 18)
        self.assertEqual(self._ec.specific_context_field_type.addr, self._context_ft.addr)
        self.assertEqual(self._ec.payload_field_type.addr, self._payload_ft.addr)
        self.assertEqual(self._ec.emf_uri, 'yes')
        self.assertEqual(self._ec.log_level, bt2.EventClassLogLevel.INFO)


    def test_assign_context_field_type(self):
        ft = bt2.StructureFieldType()
        ft.append_field('garou', bt2.StringFieldType())
        self._ec.specific_context_field_type = ft
        self.assertEqual(self._ec.specific_context_field_type.addr, ft.addr)

    def test_assign_no_context_field_type(self):
        self.assertIsNone(self._ec.specific_context_field_type)

    def test_assign_invalid_context_field_type(self):
        with self.assertRaises(TypeError):
            self._ec.specific_context_field_type = 'lel'

    def test_assign_payload_field_type(self):
        self._ec.payload_field_type = self._payload_ft
        self.assertEqual(self._ec.payload_field_type.addr, self._payload_ft.addr)

    def test_assign_no_payload_field_type(self):
        self.assertIsNone(self._ec.payload_field_type)

    def test_assign_invalid_payload_field_type(self):
        with self.assertRaises(TypeError):
            self._ec.payload_field_type = 'lel'

    def test_stream_class_prop(self):
        self.assertEqual(self._ec.stream_class.addr, self._stream_class.addr)

    def test_assign_emf_uri(self):
        self._ec.emf_uri = 'salut'
        self.assertEqual(self._ec.emf_uri, 'salut')

    def test_assign_invalid_emf_uri(self):
        with self.assertRaises(TypeError):
            self._ec.emf_uri = 23

    def test_assign_log_level(self):
        self._ec.log_level = bt2.EventClassLogLevel.EMERGENCY
        self.assertEqual(self._ec.log_level, bt2.EventClassLogLevel.EMERGENCY)

    def test_assign_invalid_log_level(self):
        with self.assertRaises(ValueError):
            self._ec.log_level = 'zoom'
