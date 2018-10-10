from collections import OrderedDict
from bt2 import values
import unittest
import copy
import bt2


class EventTestCase(unittest.TestCase):
    def _create_event(self, packet_fields_config=None, event_fields_config=None,
            with_clockclass=False, with_eh=False, with_cc=False, with_sc=False, with_ep=False):
        # packet header
        ph = bt2.StructureFieldType()
        ph += OrderedDict((
            ('magic', bt2.SignedIntegerFieldType(64)),
            ('stream_id', bt2.SignedIntegerFieldType(16))
        ))

        trace = bt2.Trace(packet_header_field_type=ph)
        stream_class = trace.create_stream_class()

        # common context
        if with_cc:
            cc = bt2.StructureFieldType()
            cc += OrderedDict((
                ('cpu_id', bt2.SignedIntegerFieldType(8)),
                ('stuff', bt2.RealFieldType()),
            ))
            stream_class.event_common_context_field_type = cc

        # packet context
        pc = bt2.StructureFieldType()
        pc += OrderedDict((
            ('something', bt2.UnsignedIntegerFieldType(8)),
            ('something_else', bt2.RealFieldType()),
        ))
        stream_class.packet_context_field_type = pc

        if with_clockclass:
            clock_class = bt2.ClockClass('my_cc', 1000)
            stream_class.default_clock_class = clock_class

        # event header
        if with_eh:
            eh = bt2.StructureFieldType()
            eh += OrderedDict((
                ('id', bt2.SignedIntegerFieldType(8)),
                ('ts', bt2.UnsignedIntegerFieldType(64)),
            ))
            stream_class.event_header_field_type = eh


        event_class = stream_class.create_event_class()
        event_class.name = 'garou'
        # specific context
        if with_sc:
            sc = bt2.StructureFieldType()
            sc += OrderedDict((
                ('ant', bt2.SignedIntegerFieldType(16)),
                ('msg', bt2.StringFieldType()),
            ))
            event_class.specific_context_field_type = sc

        # event payload
        if with_ep:
            ep = bt2.StructureFieldType()
            ep += OrderedDict((
                ('giraffe', bt2.SignedIntegerFieldType(32)),
                ('gnu', bt2.SignedIntegerFieldType(8)),
                ('mosquito', bt2.SignedIntegerFieldType(8)),
            ))
            event_class.payload_field_type = ep


        stream = stream_class()
        packet = stream.create_packet()

        if packet_fields_config is not None:
            packet_fields_config(packet)

        self.packet = packet
        self.stream = stream
        self.event_class = event_class

        class MyIter(bt2._UserNotificationIterator):
            def __init__(self):
                self._at = 0

            def __next__(self):
                if self._at == 0:
                    notif = self._create_stream_beginning_notification(stream)
                elif self._at == 1:
                    notif = self._create_packet_beginning_notification(packet)
                elif self._at == 2:
                    notif = self._create_event_notification(event_class, packet)
                    if event_fields_config is not None:
                        event_fields_config(notif.event)
                elif self._at == 3:
                    notif = self._create_packet_end_notification(packet)
                elif self._at == 4:
                    notif = self._create_stream_end_notification(stream)
                elif self._at >= 5:
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
                return notif.event

    def test_attr_event_class(self):
        ev = self._create_event()
        self.assertEqual(ev.event_class.addr, self.event_class.addr)

    def test_attr_name(self):
        ev = self._create_event()
        self.assertEqual(ev.name, self.event_class.name)

    def test_attr_id(self):
        ev = self._create_event()
        self.assertEqual(ev.id, self.event_class.id)

    def test_get_event_header_field(self):
        class EventFieldsConfiguration:
            def __call__(self, event):
                event.header_field['id'] = 23
                event.header_field['ts'] = 1234


        ev = self._create_event(event_fields_config=EventFieldsConfiguration(), with_eh=True)

        self.assertEqual(ev.header_field['id'], 23)
        self.assertEqual(ev.header_field['ts'], 1234)

    def test_no_event_header_field(self):
        ev = self._create_event(with_eh=False)
        self.assertIsNone(ev.header_field)

    def test_get_common_context_field(self):
        class EventFieldsConfiguration:
            def __call__(self, event):
                event.common_context_field['cpu_id'] = 1
                event.common_context_field['stuff'] = 13.194


        ev = self._create_event(event_fields_config=EventFieldsConfiguration(), with_cc=True)

        self.assertEqual(ev.common_context_field['cpu_id'], 1)
        self.assertEqual(ev.common_context_field['stuff'], 13.194)

    def test_no_common_context_field(self):
        ev = self._create_event(with_cc=False)
        self.assertIsNone(ev.common_context_field)

    def test_get_specific_context_field(self):
        class EventFieldsConfiguration:
            def __call__(self, event):
                event.specific_context_field['ant'] = -1
                event.specific_context_field['msg'] = 'hellooo'


        ev = self._create_event(event_fields_config=EventFieldsConfiguration(), with_sc=True)

        self.assertEqual(ev.specific_context_field['ant'], -1)
        self.assertEqual(ev.specific_context_field['msg'], 'hellooo')

    def test_no_specific_context_field(self):
        ev = self._create_event(with_sc=False)
        self.assertIsNone(ev.specific_context_field)

    def test_get_event_payload_field(self):
        class EventFieldsConfiguration:
            def __call__(self, event):
                event.payload_field['giraffe'] = 1
                event.payload_field['gnu'] = 23
                event.payload_field['mosquito'] = 42


        ev = self._create_event(event_fields_config=EventFieldsConfiguration(), with_ep=True)

        self.assertEqual(ev.payload_field['giraffe'], 1)
        self.assertEqual(ev.payload_field['gnu'], 23)
        self.assertEqual(ev.payload_field['mosquito'], 42)

    def test_no_payload_field(self):
        ev = self._create_event(with_ep=False)
        self.assertIsNone(ev.payload_field)

    def test_clock_value(self):
        ev = self._create_event(with_clockclass=True)
        ev.default_clock_value = 177
        self.assertEqual(ev.default_clock_value.cycles, 177)

    def test_no_clock_value(self):
        ev = self._create_event(with_clockclass=False)
        self.assertIsNone(ev.default_clock_value)

    def test_stream(self):
        ev = self._create_event()
        self.assertEqual(ev.stream.addr, self.stream.addr)
    
    def test_getitem(self):
        class EventFieldsConfiguration:
            def __call__(self, event):
                event.payload_field['giraffe'] = 1
                event.payload_field['gnu'] = 23
                event.payload_field['mosquito'] = 42
                event.specific_context_field['ant'] = -1
                event.specific_context_field['msg'] = 'hellooo'
                event.common_context_field['cpu_id'] = 1
                event.common_context_field['stuff'] = 13.194
                event.header_field['id'] = 23
                event.header_field['ts'] = 1234

        class PacketFieldsConfiguration:
            def __call__(self, packet):
                packet.header_field['magic'] = 0xc1fc1fc1
                packet.header_field['stream_id'] = 0
                packet.context_field['something'] = 154
                packet.context_field['something_else'] = 17.2

        ev = self._create_event(packet_fields_config=PacketFieldsConfiguration(),
                event_fields_config=EventFieldsConfiguration(),
                with_eh=True, with_cc=True, with_sc=True, with_ep=True)

        #Test event fields
        self.assertEqual(ev['giraffe'], 1)
        self.assertEqual(ev['gnu'], 23)
        self.assertEqual(ev['mosquito'], 42)
        self.assertEqual(ev['ant'], -1)
        self.assertEqual(ev['msg'], 'hellooo')
        self.assertEqual(ev['cpu_id'], 1)
        self.assertEqual(ev['stuff'], 13.194)
        self.assertEqual(ev['id'], 23)
        self.assertEqual(ev['ts'], 1234)

        #Test packet fields
        self.assertEqual(ev['magic'], 0xc1fc1fc1)
        self.assertEqual(ev['stream_id'], 0)
        self.assertEqual(ev['something'], 154)
        self.assertEqual(ev['something_else'], 17.2)

        with self.assertRaises(KeyError):
            ev['yes']
