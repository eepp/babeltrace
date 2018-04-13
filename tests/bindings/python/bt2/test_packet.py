from collections import OrderedDict
from bt2 import values
import unittest
import copy
import bt2


class PacketTestCase(unittest.TestCase):
    def setUp(self):
        self._packet = self._create_packet()

    def tearDown(self):
        del self._packet

    def _create_packet(self, first=True, with_ph=True, with_pc=True):
        clock_class = bt2.ClockClass('my_cc', 1000)
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
        if with_pc:
            pc = bt2.StructureFieldType()
            pc += OrderedDict((
                ('something', bt2.IntegerFieldType(8)),
                ('something_else', bt2.FloatingPointNumberFieldType()),
                ('events_discarded', bt2.IntegerFieldType(64, is_signed=False)),
                ('packet_seq_num', bt2.IntegerFieldType(64, is_signed=False)),
                ('timestamp_begin', bt2.IntegerFieldType(64, is_signed=False, mapped_clock_class=clock_class)),
                ('timestamp_end', bt2.IntegerFieldType(64, is_signed=False, mapped_clock_class=clock_class)),
            ))
        else:
            pc = None

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
        if with_ph:
            ph = bt2.StructureFieldType()
            ph += OrderedDict((
                ('magic', bt2.IntegerFieldType(32)),
                ('stream_id', bt2.IntegerFieldType(16)),
            ))
        else:
            ph = None

        # trace class
        tc = bt2.Trace()
        tc.packet_header_field_type = ph
        tc.add_stream_class(sc)
        tc.add_clock_class(clock_class)

        # stream
        stream = sc()


        # packet
        # We create 3 packets because we need 2 frozen packets. A packet is
        # frozen when the next packet is created.
        packet1 = stream.create_packet(bt2.PreviousPacketAvailability.NONE, None)
        if with_pc:
            packet1.context_field['events_discarded'] = 5
            packet1.context_field['packet_seq_num'] = 0
            packet1.context_field['timestamp_begin'] = 1
            packet1.context_field['timestamp_end'] = 500

        packet2 = stream.create_packet(bt2.PreviousPacketAvailability.AVAILABLE, packet1)
        if with_pc:
            packet2.context_field['events_discarded'] = 20
            packet2.context_field['packet_seq_num'] = 4
            packet2.context_field['timestamp_begin'] = 1000
            packet2.context_field['timestamp_end'] = 2000

        packet3 = stream.create_packet(bt2.PreviousPacketAvailability.AVAILABLE, packet2)

        if first:
            return packet1
        else:
            return packet2

    def test_attr_stream(self):
        self.assertIsNotNone(self._packet.stream)

    def test_get_header_field(self):
        self.assertIsNotNone(self._packet.header_field)

    def test_no_header_field(self):
        packet = self._create_packet(with_ph=False)
        self.assertIsNone(packet.header_field)

    def test_get_context_field(self):
        self.assertIsNotNone(self._packet.context_field)

    def test_no_context_field(self):
        packet = self._create_packet(with_pc=False)
        self.assertIsNone(packet.context_field)

    def test_default_beginning_clock_value(self):
        self.assertEqual(self._packet.default_beginning_clock_value, 1)

    def test_default_end_clock_value(self):
        self.assertEqual(self._packet.default_end_clock_value, 500)

    def test_previous_packet_default_end_clock_value(self):
        packet = self._create_packet(first=False)
        self.assertEqual(packet.previous_packet_default_end_clock_value, 500)

    def test_discarded_event_counter(self):
        packet = self._create_packet(first=True)
        self.assertEqual(packet.discarded_event_counter, 5)
        packet = self._create_packet(first=False)
        self.assertEqual(packet.discarded_event_counter, 20)

    def test_sequence_number(self):
        packet = self._create_packet(first=False)
        self.assertEqual(packet.sequence_number, 4)

    def test_discarded_event_count(self):
        packet = self._create_packet(first=False)
        self.assertEqual(packet.discarded_event_count, 15)

    def test_discarded_packet_count(self):
        packet = self._create_packet(first=False)
        self.assertEqual(packet.discarded_packet_count, 3)

    def test_props_no_previous_packet(self):
        self.assertIsNone(self._packet.previous_packet_default_end_clock_value)
        self.assertIsNone(self._packet.discarded_event_count)
        self.assertIsNone(self._packet.discarded_packet_count)
