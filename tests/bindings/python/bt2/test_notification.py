from bt2 import values
import collections
import unittest
import copy
import bt2


class AllNotificationTestCase(unittest.TestCase):
    def setUp(self):
        _trace = bt2.Trace()
        _cc = bt2.ClockClass()
        _sc = _trace.create_stream_class(default_clock_class=_cc)
        self._event_class = _sc.create_event_class()
        self._event_class.name = 'salut'
        _my_int_ft = bt2.SignedIntegerFieldType(32)
        payload_ft = bt2.StructureFieldType()
        payload_ft += collections.OrderedDict([
            ('my_int', _my_int_ft),
        ])
        self._event_class.payload_field_type = payload_ft
        self._stream = _sc()
        self._packet = self._stream.create_packet()

        # Create variable proxies to access those from the inner classes.
        stream = self._stream
        packet = self._packet
        event_class = self._event_class

        class MyIter(bt2._UserNotificationIterator):
            def __init__(self):
                self._at = 0

            def __next__(self):
                if self._at == 0:
                    notif = self._create_stream_beginning_notification(stream)
                    notif.default_clock_value = self._at
                elif self._at == 1:
                    notif = self._create_packet_beginning_notification(packet)
                elif self._at == 2:
                    notif = self._create_event_notification(event_class, packet)
                elif self._at == 3:
                    notif = self._create_inactivity_notification(_cc)
                    notif.default_clock_value = self._at
                elif self._at == 4:
                    notif = self._create_packet_end_notification(packet)
                elif self._at == 5:
                    notif = self._create_stream_end_notification(stream)
                    notif.default_clock_value = self._at
                elif self._at >= 6:
                    raise bt2.Stop

                self._at += 1
                return notif


        class MySrc(bt2._UserSourceComponent, notification_iterator_class=MyIter):
            def __init__(self, params):
                self._add_output_port('out')

        self._graph = bt2.Graph()
        self._src_comp = self._graph.add_component(MySrc, 'my_source')
        self._notif_iter = self._src_comp.output_ports['out'].create_notification_iterator()

    def tearDown(self):
        del self._graph
        del self._src_comp
        del self._notif_iter
        del self._event_class
        del self._packet
        del self._stream

    def test_all_notif(self):
        for i, notif in enumerate(self._notif_iter):
            if i == 0:
                self.assertEqual(notif.stream.addr, self._stream.addr)
                self.assertEqual(notif.default_clock_value, i)
            elif i == 1:
                self.assertEqual(notif.packet.addr, self._packet.addr)
            elif i == 2:
                self.assertEqual(notif.event.event_class.addr, self._event_class.addr)
            elif i == 3:
                self.assertEqual(notif.default_clock_value, i)
            elif i == 4:
                self.assertEqual(notif.packet.addr, self._packet.addr)
            elif i == 5:
                self.assertEqual(notif.stream.addr, self._stream.addr)
                self.assertEqual(notif.default_clock_value, i)
            else:
                raise Exception()
