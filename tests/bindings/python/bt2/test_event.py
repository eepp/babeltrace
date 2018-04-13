from collections import OrderedDict
from bt2 import values
import unittest
import copy
import bt2



class EventTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        del self.event_class
        del self.stream
        del self.packet

    def _create_event(self, with_eh=True, with_sec=True, with_ec=True, with_ep=True):
        # packet header
        ph = bt2.StructureFieldType()
        ph += OrderedDict((
            ('magic', bt2.IntegerFieldType(32)),
            ('stream_id', bt2.IntegerFieldType(16))
        ))

        trace = bt2.Trace(packet_header_field_type=ph)

        # stream event context
        if with_sec:
            sec = bt2.StructureFieldType()
            sec += OrderedDict((
                ('cpu_id', bt2.IntegerFieldType(8)),
                ('stuff', bt2.FloatingPointNumberFieldType()),
            ))
        else:
            sec = None

        # packet context
        pc = bt2.StructureFieldType()
        pc += OrderedDict((
            ('something', bt2.IntegerFieldType(8)),
            ('something_else', bt2.FloatingPointNumberFieldType()),
        ))

        clock_class = bt2.ClockClass('my_cc', 1000)

        # event header
        if with_eh:
            eh = bt2.StructureFieldType()
            eh += OrderedDict((
                ('id', bt2.IntegerFieldType(8)),
                ('ts', bt2.IntegerFieldType(64, is_signed=False, mapped_clock_class=clock_class)),
            ))
        else:
            eh = None

        sc = bt2.StreamClass()
        sc.event_context_field_type = sec
        sc.packet_context_field_type = pc
        sc.event_header_field_type = eh

        # event context
        if with_ec:
            ec = bt2.StructureFieldType()
            ec += OrderedDict((
                ('ant', bt2.IntegerFieldType(16, is_signed=True)),
                ('msg', bt2.StringFieldType()),
            ))
        else:
            ec = None

        # event payload
        if with_ep:
            ep = bt2.StructureFieldType()
            ep += OrderedDict((
                ('giraffe', bt2.IntegerFieldType(32)),
                ('gnu', bt2.IntegerFieldType(8)),
                ('mosquito', bt2.IntegerFieldType(8)),
            ))
        else:
            ep = None

        event_class = bt2.EventClass('garou')
        event_class.context_field_type = ec
        event_class.payload_field_type = ep

        sc.add_event_class(event_class)
        trace.add_stream_class(sc)
        trace.add_clock_class(clock_class)
        stream = sc()
        packet = stream.create_packet()

        self.packet = packet
        self.stream = stream
        self.event_class = event_class
        self.clock_class = clock_class

        class MyIter(bt2._UserNotificationIterator):
            def __init__(self):
                self._at = 0

            def __next__(self):
                if self._at == 0:
                    notif = self._create_stream_beginning_notification(stream)
                elif self._at == 1:
                    notif = self._create_packet_beginning_notification(packet)
                elif self._at == 3:
                    notif = self._create_packet_end_notification(packet)
                elif self._at == 4:
                    notif = self._create_stream_end_notification(stream)
                elif self._at == 5:
                    raise bt2.Stop
                else:
                    notif = self._create_event_notification(event_class, packet)

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
        ev = self._create_event()
        ev.header_field['id'] = 23
        ev.header_field['ts'] = 1234
        self.assertEqual(ev.header_field['id'], 23)
        self.assertEqual(ev.header_field['ts'], 1234)

    def test_set_event_header_field(self):
        ev = self._create_event()
        eh = ev.header_field
        eh['id'] = 17
        eh['ts'] = 188
        self.assertEqual(ev.header_field['id'], 17)
        self.assertEqual(ev.header_field['ts'], 188)

    def test_get_stream_event_context_field(self):
        ev = self._create_event()
        ev.stream_event_context_field['cpu_id'] = 1
        ev.stream_event_context_field['stuff'] = 13.194
        self.assertEqual(ev.stream_event_context_field['cpu_id'], 1)
        self.assertEqual(ev.stream_event_context_field['stuff'], 13.194)

    def test_set_stream_event_context_field(self):
        ev = self._create_event()
        sec = ev.stream_event_context_field
        sec['cpu_id'] = 2
        sec['stuff'] = 19.19
        self.assertEqual(ev.stream_event_context_field['cpu_id'], 2)
        self.assertEqual(ev.stream_event_context_field['stuff'], 19.19)

    def test_no_stream_event_context(self):
        ev = self._create_event(with_sec=False)
        self.assertIsNone(ev.stream_event_context_field)

    def test_get_event_context_field(self):
        ev = self._create_event()
        ev.context_field['ant'] = -1
        ev.context_field['msg'] = 'hellooo'
        self.assertEqual(ev.context_field['ant'], -1)
        self.assertEqual(ev.context_field['msg'], 'hellooo')

    def test_set_event_context_field(self):
        ev = self._create_event()
        ec = ev.context_field
        ec['ant'] = 2
        ec['msg'] = 'hi there'
        self.assertEqual(ev.context_field['ant'], 2)
        self.assertEqual(ev.context_field['msg'], 'hi there')

    def test_no_event_context(self):
        ev = self._create_event(with_ec=False)
        self.assertIsNone(ev.context_field)

    def test_get_event_payload_field(self):
        ev = self._create_event()
        ev.payload_field['giraffe'] = 1
        ev.payload_field['gnu'] = 23
        ev.payload_field['mosquito'] = 42
        self.assertEqual(ev.payload_field['giraffe'], 1)
        self.assertEqual(ev.payload_field['gnu'], 23)
        self.assertEqual(ev.payload_field['mosquito'], 42)

    def test_set_event_payload_field(self):
        ev = self._create_event()
        ep = ev.payload_field
        ep['giraffe'] = 2
        ep['gnu'] = 124
        ep['mosquito'] = 17
        self.assertEqual(ev.payload_field['giraffe'], 2)
        self.assertEqual(ev.payload_field['gnu'], 124)
        self.assertEqual(ev.payload_field['mosquito'], 17)

    def test_clock_value(self):
        ev = self._create_event()
        ev.set_clock_value(self.clock_class, 177)
        self.assertEqual(ev.default_clock_value.cycles, 177)

    def test_no_clock_value(self):
        ev = self._create_event()
        self.assertIsNone(ev.default_clock_value)

    def test_stream(self):
        ev = self._create_event()
        self.assertEqual(ev.stream.addr, self.stream.addr)
    
    def test_getitem(self):
        ev = self._create_event()

        # Fill event fields
        ev.header_field['id'] = 23
        ev.header_field['ts'] = 1234
        ev.stream_event_context_field['cpu_id'] = 1
        ev.stream_event_context_field['stuff'] = 13.194
        ev.context_field['ant'] = -1
        ev.context_field['msg'] = 'hellooo'
        ev.payload_field['giraffe'] = 1
        ev.payload_field['gnu'] = 23
        ev.payload_field['mosquito'] = 42

        # Fill packet fields
        packet = ev.packet
        packet.header_field['magic'] = 0xc1fc1fc1
        packet.header_field['stream_id'] = 0
        packet.context_field['something'] = 154
        packet.context_field['something_else'] = 17.2

        #Test event fields
        self.assertEqual(ev['mosquito'], 42)
        self.assertEqual(ev['gnu'], 23)
        self.assertEqual(ev['giraffe'], 1)
        self.assertEqual(ev['msg'], 'hellooo')
        self.assertEqual(ev['ant'], -1)
        self.assertEqual(ev['stuff'], 13.194)
        self.assertEqual(ev['cpu_id'], 1)
        self.assertEqual(ev['ts'], 1234)
        self.assertEqual(ev['id'], 23)

        #Test packet fields
        self.assertEqual(ev['magic'], 0xc1fc1fc1)
        self.assertEqual(ev['stream_id'], 0)
        self.assertEqual(ev['something'], 154)
        self.assertEqual(ev['something_else'], 17.2)

        with self.assertRaises(KeyError):
            ev['yes']
