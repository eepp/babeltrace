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

        # trace class
        tc = bt2.Trace()
        # packet header
        if with_ph:
            ph = bt2.StructureFieldType()
            ph += OrderedDict((
                ('magic', bt2.SignedIntegerFieldType(32)),
                ('stream_id', bt2.SignedIntegerFieldType(16)),
            ))
            tc.packet_header_field_type = ph

        # event header
        eh = bt2.StructureFieldType()
        eh += OrderedDict((
            ('id', bt2.SignedIntegerFieldType(8)),
            ('ts', bt2.SignedIntegerFieldType(32)),
        ))

        # stream event context
        sec = bt2.StructureFieldType()
        sec += OrderedDict((
            ('cpu_id', bt2.SignedIntegerFieldType(8)),
            ('stuff', bt2.RealFieldType()),
        ))

        # stream class
        sc = tc.create_stream_class()
        sc.default_clock_class = clock_class
        sc.packets_have_default_beginning_clock_value = True
        sc.packets_have_default_end_clock_value = True
        sc.packets_have_discarded_event_counter_snapshot = True
        sc.packets_have_packet_counter_snapshot = True
    

        # packet context
        if with_pc:
            pc = bt2.StructureFieldType()
            pc += OrderedDict((
                ('something', bt2.SignedIntegerFieldType(8)),
                ('something_else', bt2.RealFieldType()),
                ('events_discarded', bt2.UnsignedIntegerFieldType(64)),
                ('packet_seq_num', bt2.UnsignedIntegerFieldType(64)),
            ))
            sc.packet_context_field_type = pc

        sc.event_header_field_type = eh
        sc.event_common_context_field_type = sec

        # event context
        ec = bt2.StructureFieldType()
        ec += OrderedDict((
            ('ant', bt2.SignedIntegerFieldType(16)),
            ('msg', bt2.StringFieldType()),
        ))

        # event payload
        ep = bt2.StructureFieldType()
        ep += OrderedDict((
            ('giraffe', bt2.SignedIntegerFieldType(32)),
            ('gnu', bt2.SignedIntegerFieldType(8)),
            ('mosquito', bt2.SignedIntegerFieldType(8)),
        ))

        # event class
        event_class = sc.create_event_class()
        event_class.name = 'ec'
        event_class.common_context_field_type = ec
        event_class.payload_field_type = ep

        # stream
        stream = sc()

        # packet
        # We create 3 packets because we need 2 frozen packets. A packet is
        # frozen when the next packet is created.
        packet1 = stream.create_packet()
        packet1.discarded_event_counter_snapshot = 5
        packet1.packet_counter_snapshot = 1
        packet1.default_beginning_clock_value = 1
        packet1.default_end_clock_value = 500

        packet2 = stream.create_packet()
        packet2.discarded_event_counter_snapshot = 20
        packet2.packet_counter_snapshot = 4
        packet2.default_beginning_clock_value = 1000
        packet2.default_end_clock_value = 2000

        packet3 = stream.create_packet()

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

    def test_discarded_event_counter_snapshot(self):
        packet = self._create_packet(first=True)
        self.assertEqual(packet.discarded_event_counter_snapshot, 5)
        packet = self._create_packet(first=False)
        self.assertEqual(packet.discarded_event_counter_snapshot, 20)

    def test_packet_counter_snapshot(self):
        packet = self._create_packet(first=True)
        self.assertEqual(packet.packet_counter_snapshot, 1)
        packet = self._create_packet(first=False)
        self.assertEqual(packet.packet_counter_snapshot, 4)
