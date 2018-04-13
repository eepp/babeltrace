from collections import OrderedDict
from bt2 import values
import unittest
import bt2


class StreamTestCase(unittest.TestCase):
    def setUp(self):
        self._stream = self._create_stream(stream_id=23)

    def tearDown(self):
        del self._stream

    def _create_stream(self, stream_name='my_stream', stream_id=None):
        # event header
        eh = bt2.StructureFieldType()
        eh += OrderedDict((
            ('id', bt2.IntegerFieldType(8)),
            ('ts', bt2.IntegerFieldType(32)),
        ))

        # stream event context
        sec = bt2.StructureFieldType()
        sec += OrderedDict((
            ('cpu_id', bt2.IntegerFieldType(8)),
            ('stuff', bt2.FloatingPointNumberFieldType()),
        ))

        # packet context
        pc = bt2.StructureFieldType()
        pc += OrderedDict((
            ('something', bt2.IntegerFieldType(8)),
            ('something_else', bt2.FloatingPointNumberFieldType()),
        ))

        # stream class
        sc = bt2.StreamClass()
        sc.packet_context_field_type = pc
        sc.event_header_field_type = eh
        sc.event_context_field_type = sec

        # event context
        ec = bt2.StructureFieldType()
        ec += OrderedDict((
            ('ant', bt2.IntegerFieldType(16, is_signed=True)),
            ('msg', bt2.StringFieldType()),
        ))

        # event payload
        ep = bt2.StructureFieldType()
        ep += OrderedDict((
            ('giraffe', bt2.IntegerFieldType(32)),
            ('gnu', bt2.IntegerFieldType(8)),
            ('mosquito', bt2.IntegerFieldType(8)),
        ))

        # event class
        event_class = bt2.EventClass('ec')
        event_class.context_field_type = ec
        event_class.payload_field_type = ep
        sc.add_event_class(event_class)

        # packet header
        ph = bt2.StructureFieldType()
        ph += OrderedDict((
            ('magic', bt2.IntegerFieldType(32)),
            ('stream_id', bt2.IntegerFieldType(16)),
        ))

        # trace c;ass
        tc = bt2.Trace()
        tc.packet_header_field_type = ph
        tc.add_stream_class(sc)

        # stream
        return sc(name=stream_name, id=stream_id)

    def test_attr_stream_class(self):
        self.assertIsNotNone(self._stream.stream_class)

    def test_attr_name(self):
        self.assertEqual(self._stream.name, 'my_stream')
